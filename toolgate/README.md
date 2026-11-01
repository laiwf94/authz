# toolgate

A security gateway that sits between AI agents and the tools they call over
the [Model Context Protocol](https://modelcontextprotocol.io/specification/2026-07-28)
(MCP). Every tool call is authenticated, checked against a declarative policy,
rate limited, optionally approved by a human, and written to a tamper-evident
audit log before it reaches the real MCP server.

Written in Go with the standard library only (no third-party dependencies).

```json
{
  "id": "read-workspace",
  "effect": "allow",
  "scopes": ["files:read"],
  "upstreams": ["fake"],
  "tools": ["read_file"],
  "arguments": {
    "type": "object", "required": ["path"], "additionalProperties": false,
    "properties": {"path": {"type": "string", "maxLength": 256, "x-path-prefix": ["reports", "notes"]}}
  },
  "output": {"redact": ["aws_access_key_id", "private_key"], "max_bytes": 8192}
}
```

```console
$ ./examples/demo.sh
3. Argument constraints: path traversal, a .env file, and an SSRF attempt
   HTTP 200  error -31001: denied by policy: arguments rejected by rule read-workspace: $.path: path must not contain ".." segments  rule_id=default-deny
   HTTP 200  error -31001: denied by policy: rule no-dotenv forbids this call  rule_id=no-dotenv
   HTTP 200  error -31001: denied by policy: arguments rejected by rule web-allowlist: $.url: URL host is not in the allowed list  rule_id=default-deny
...
7. Rug pull: the upstream swaps the translate tool's description for one with injected instructions
   alice-bot's tool list no longer offers it:
   fake.echo, fake.http_get, fake.read_file
   HTTP 200  error -31006: tool fake.translate changed its definition and is quarantined until an administrator reviews it
...
8. The audit log is a hash chain
   OK audit.jsonl: 23 records, head bcb6d990…
   someone rewrites line 3 to turn a denial into an allow...
   FAIL audit.jsonl: line 3: record does not match the hash stored in line 4: it was modified, removed or reordered
```

## Why

An agent that can call tools acts with whatever authority those tools have,
and anything it reads (a web page, a file, a tool description) can try to
steer it. OWASP lists this as
[LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and
[LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/),
and the [Top 10 for Agentic Applications](https://genai.owasp.org/) as tool
misuse (ASI02). The model cannot be relied on to refuse, so the controls have
to sit outside it, on the path every call takes: least privilege per agent,
complete mediation, a human for the risky calls, and a record of everything.

## How a call is handled

Each of the steps below can refuse a call, and a refusal ends it there. The
exact order is in the [design notes](docs/DESIGN.md#the-path-of-one-call).

Every agent has an identity: a static key (only its SHA-256 is stored, and it
is compared in constant time) or a short-lived signed token (HS256 JWS with
`iss`, `aud`, `exp`, `nbf`, `iat`, a lifetime cap and key rotation by `kid`).
An identity carries an agent id, an owner and scopes.

The policy is an ordered JSON rule list. Nothing is allowed unless a rule says
so, and an explicit deny beats any allow. Rules match agents or scopes,
upstreams and tools (exact or `prefix_*`), and constrain arguments with a
closed JSON Schema subset: `type`, `enum`, `pattern` (RE2),
`minimum`/`maximum`, `minLength`/`maxLength`, `required`,
`additionalProperties: false` and `items`, plus `x-path-prefix` for canonical
file paths and `x-allowed-hosts` for URLs. Those two are accepted in allow
rules only, so odd input fails closed. Unknown keywords are errors, every
decision names the rule that made it, and the file is hot-reloaded
atomically; an invalid file is rejected and the old policy keeps running.

A policy can be tested like code. A case file lists calls and tool lists with
the decision each should get, and `toolgate policy test POLICY CASES` checks
them all and prints, for each case that fails, what it expected next to what
the policy decided:

```console
$ toolgate policy test narrowed.json examples/policy_cases.json
FAIL alice reads a note
     decision: want allow
                got deny
     rule:     want read-workspace
                got default-deny
     decided: deny by default-deny (arguments rejected by read-workspace): arguments rejected by rule read-workspace: $.path: path is outside the allowed directories
FAIL 17 cases: 16 passed, 1 failed
```

Rules marked `requires_approval` park the call until an administrator approves
or denies it on a separate admin API. A grant is bound to the agent, the tool
and the SHA-256 of the exact arguments, works once and expires. The agent's
request either waits for a configured time or gets a "pending" error and
retries the same call.

Calls are rate limited with token buckets (GCRA) per agent and per agent and
tool, a daily quota per agent, and a concurrency limit per upstream. Refusals
are HTTP 429 with `Retry-After` (200 with `Retry-After` for clients in a 2025
session).

Agents only see the tools they may call, named `upstream.tool`. The gateway
forwards calls with a timeout and a response size limit and adds the
upstream's own credential; agent credentials are never forwarded, upstream
URLs come only from configuration, and redirects are not followed. Each tool
definition (name, title, description, schemas, annotations) is pinned by hash
the first time it is seen. If an upstream later changes it, the tool is
quarantined, hidden and refused until an administrator approves the new hash.

Results can be redacted per rule for credential shapes (AWS keys, GitHub and
Slack tokens, private keys, bearer tokens, JWTs, or custom RE2) and truncated
to a byte budget, and the audit log records when that happened.

The audit log is append-only JSONL. Each record carries the SHA-256 of the
previous line and is fsynced before the call goes ahead (concurrent calls
share an fsync). `toolgate audit verify` finds any edit, deletion or
reordering and names the line. Arguments are stored as an HMAC plus a redacted
preview, never raw, and if the log can't be written the call is refused.

toolgate speaks the current MCP revision (2026-07-28: stateless, `_meta` and
header checks, `server/discover`) and the handshake revisions (2025-11-25,
2025-06-18, 2025-03-26: `initialize`, `Mcp-Session-Id` bound to the agent,
`DELETE`) on one endpoint, as both server and client. It takes one JSON-RPC
message per request (batches are refused, as the protocol has required since
2025-06-18), validates `Origin` against DNS rebinding, limits bodies, rejects
duplicate keys, and mirrors and checks `x-mcp-header`.

## Trying it

The demo script builds both binaries, starts them and runs every scenario
shown above:

```console
$ ./examples/demo.sh
```

At the end it turns the audit log into recorded decisions (timestamps,
latencies, request and approval ids and argument HMACs normalised) and
compares them with `examples/demo_decisions.jsonl`, failing on any difference,
so a change that alters what the gateway decides in these scenarios cannot
pass CI unnoticed. When a change is meant to alter them, rewrite the recording
with `DEMO_RECORD=1 ./examples/demo.sh` and review the diff.

To run the pieces yourself:

```console
$ (cd .. && go build -o toolgate/authz ./cmd/authz)    # the one binary: authz mcp is the gateway
$ ./authz mcp token new                                 # a key for an agent, and the hash for the config
$ MCPFAKE_SANDBOX=examples/sandbox MCPFAKE_TOKEN=upstream-secret-0123456789 \
    MCPFAKE_ADDR=127.0.0.1:19100 ./authz mcpfake &
$ export FAKE_UPSTREAM_TOKEN=upstream-secret-0123456789
$ TOOLGATE_CONFIG=examples/config.json TOOLGATE_POLICY=examples/policy.json \
    TOOLGATE_AUDIT_LOG=audit.jsonl TOOLGATE_AUDIT_KEY=$(openssl rand -hex 32) \
    TOOLGATE_ADMIN_TOKEN=$(openssl rand -hex 24) TOOLGATE_STATE_DIR=. ./authz mcp
```

Every `TOOLGATE_` variable can also be spelled `AUTHZ_MCP_` (and every
`MCPFAKE_` one `AUTHZ_MCPFAKE_`); setting both spellings to different values
stops the command at start.

Then point any MCP client at `http://127.0.0.1:8080/mcp` with
`Authorization: Bearer <agent key>`. Configuration is documented in
`authz mcp -h` and [cmd/authz/internal/mcp/mcp.go](../cmd/authz/internal/mcp/mcp.go); the config and policy formats in
[examples/config.json](examples/config.json) and
[examples/policy.json](examples/policy.json), with its test cases in
[examples/policy_cases.json](examples/policy_cases.json).

The Docker image holds the one `authz` binary (entry point `authz mcp`), runs as `nonroot` on distroless, and
keeps the audit log and tool pins in `/data`. In this example the fake
upstream runs as a second container, so the config must name it
(`http://mcpfake:19100/mcp`):

```console
$ (cd .. && docker build -t toolgate -f toolgate/Dockerfile .)
$ docker network create tgnet
$ docker run -d --network tgnet --network-alias mcpfake --entrypoint /authz \
    -v "$PWD/examples/sandbox:/sandbox:ro" -e MCPFAKE_ADDR=0.0.0.0:19100 \
    -e MCPFAKE_SANDBOX=/sandbox -e MCPFAKE_TOKEN=upstream-secret-0123456789 toolgate mcpfake
$ sed 's#127.0.0.1:19100#mcpfake:19100#' examples/config.json > /tmp/tg/config.json   # plus policy.json
$ docker run -d --network tgnet -p 127.0.0.1:8080:8080 -v /tmp/tg:/etc/toolgate:ro -v tgdata:/data \
    -e TOOLGATE_CONFIG=/etc/toolgate/config.json -e TOOLGATE_POLICY=/etc/toolgate/policy.json \
    -e TOOLGATE_AUDIT_LOG=/data/audit.jsonl -e TOOLGATE_STATE_DIR=/data \
    -e TOOLGATE_AUDIT_KEY=$(openssl rand -hex 32) -e TOOLGATE_ADMIN_TOKEN=$(openssl rand -hex 24) \
    -e FAKE_UPSTREAM_TOKEN=upstream-secret-0123456789 toolgate
```

## API

Agents (`TOOLGATE_ADDR`, default `127.0.0.1:8080`), `Authorization: Bearer <agent key or token>`:

| Endpoint | Purpose |
|---|---|
| `POST /mcp` | MCP over Streamable HTTP: `server/discover`, `tools/list`, `tools/call` (2026-07-28); `initialize`, `ping`, `tools/list`, `tools/call` in a session (2025-x). |
| `DELETE /mcp` | End a 2025-x session (`Mcp-Session-Id`). |
| `GET /healthz` | 200, or 503 when the audit log cannot be written. No auth. |

Administrators (`TOOLGATE_ADMIN_ADDR`, default `127.0.0.1:8081`), `Authorization: Bearer $TOOLGATE_ADMIN_TOKEN`:

| Endpoint | Purpose |
|---|---|
| `GET /admin/approvals`, `GET /admin/approvals/{id}` | Open approval requests with their exact arguments. |
| `POST /admin/approvals/{id}/approve` | `{"ttl_seconds":300,"note":"..."}` grants one use. |
| `POST /admin/approvals/{id}/deny` | `{"note":"..."}` refuses; retries of the same call are refused too. |
| `GET /admin/tools` | Pinned tool definitions; quarantined ones show the pending definition and hash. |
| `POST /admin/tools/{name}/approve` | `{"hash":"<pending_hash>"}` trusts the reviewed definition (compare-and-set). |
| `GET /admin/policy`, `POST /admin/policy/reload` | Policy hash; reload now (also on SIGHUP and when the file changes). |
| `GET /admin/audit/head` | Record count and head hash, to anchor the log elsewhere. |
| `GET /metrics` | Prometheus metrics. |

JSON-RPC errors from the gateway use codes outside the range JSON-RPC and MCP
reserve: `-31000` unauthenticated (401), `-31001` denied by policy, `-31002`
rate limited (429), `-31003` daily quota (429), `-31004` approval pending,
`-31005` approval denied, `-31006` tool quarantined, `-31007` upstream error
(502), `-31008` upstream timeout (504), `-31009` upstream busy (429), `-31010`
audit log unavailable (503). Protocol errors use the specification's codes:
`-32020` header mismatch, `-32022` unsupported version, `-32602` invalid params
or unknown tool. Clients in a 2025 session get every JSON-RPC error with
HTTP 200, as those revisions expect, and still get `Retry-After`.

Admin errors look like
`{"error":{"code":"not_found","message":"...","request_id":"..."}}`.

## Tests and benchmarks

| Area | Test |
|---|---|
| Policy decisions | Random policies (wildcards, scopes, deny rules with and without argument schemas, path prefixes) and random calls are checked against an independent, naive reference evaluator, for both `Evaluate` and the `tools/list` filter. Breaking the engine on purpose (ignoring scopes, dropping `*` upstream rules from the index, ignoring deny-rule schemas, hiding tools on conditional denies) makes it fail. |
| Policy cases | The case parser is strict (unknown fields, duplicate keys and names, expectations that cannot apply are errors); a case written from the engine's own answer passes and the same case with the decision flipped fails on that field; the example cases run against the example policy in CI. |
| Rate limiting | Random schedules against an exact integer token-bucket reference; the GCRA limiter must admit exactly the same calls. |
| Audit log | Every single-byte flip is detected (by `Verify` or by the head hash); the log cut at every byte offset recovers exactly the complete records and the chain continues; edits, deletions, swaps and duplicates are reported at the right line; failed writes and fsyncs are injected. |
| End to end | A real gateway in front of a real MCP server over HTTP: filtered lists, credential injection, every denial path, rate limits, quotas, approval (including concurrent waiters, single use, denial), rug-pull quarantine and re-approval, redaction, truncation, upstream timeouts, oversized and malformed upstream replies, a down upstream, policy hot reload, signed tokens, legacy sessions and session hijack attempts, audit failure refusing calls. The binary itself is restarted with its state to check that pins and the audit chain survive. |
| Protocol | Every transport rule of both protocol eras over HTTP (headers, `_meta`, versions, Origin, Accept, body limit, batches, sessions); the client against a modern server, a hand-written 2025-era server with SSE, pagination and expiring sessions, and a set of misbehaving servers. |
| Parsers | Go fuzzing of the JSON-RPC decoder, the policy parser, the policy case parser and runner, the schema compiler and validator, the token verifier and the audit log reader. |
| Concurrency | The whole suite runs under the race detector in CI. |

```console
$ go test -race ./internal/agents/... ./cmd/authz/internal/mcp/... ./cmd/authz/internal/mcpfake/...   # full suite, 96% statement coverage
$ go test -run=^$ -bench=. ./internal/agents/...
```

The benchmark figures below are from an Apple M4 Max. Durability dominates:
macOS `fsync` (`F_FULLFSYNC`) took 4 to 7 ms across runs, and an allowed call
writes two fsynced audit records before it returns. Ranges are over several
runs; the in-memory steps are stable.

| Operation | Time |
|---|---|
| Policy decision, 200 rules, path constraint | 0.26 to 0.32 µs |
| Argument schema validation (4 properties, path and URL checks) | 1.3 µs |
| Static key authentication | 0.08 µs |
| Signed token verification | 2.3 to 2.6 µs |
| Rate limiter take | 0.10 to 0.12 µs |
| Audit append, one writer (fsync each) | 4.3 to 7.2 ms |
| Audit append, 16 writers (group commit) | 64 to 122 µs per record |
| `tools/call` end to end over HTTP, one agent | 8.6 to 17 ms |
| `tools/call` end to end, 64 concurrent callers | 0.8 to 1.2 ms per call |
| Denied `tools/call` end to end (one audit record) | 4.2 to 8.7 ms |

## Repository map

The design notes in [docs/DESIGN.md](docs/DESIGN.md) cover the threat model,
the order of checks, the policy semantics, approvals, rug-pull detection, the
audit log format, how both MCP protocol eras are served, failure modes, limits
and what would change to run it as a fleet. toolgate is part of the authz
module: its packages live in the repository root under `internal/agents/`,
and its commands are `authz mcp` and `authz mcpfake` in the one `authz`
binary. Paths below are relative to the repository root:

```text
cmd/authz/internal/mcp         `authz mcp`: gateway entry point, `audit verify`, `policy test` and `token`
cmd/authz/internal/mcpfake     `authz mcpfake`: a small MCP server to put behind the gateway
internal/agents/gateway        the enforcement pipeline, upstream tool caching, admin API, configuration
internal/agents/mcp            MCP over Streamable HTTP: dual-era server, client, header rules
internal/agents/jsonrpc        strict JSON-RPC 2.0 decoding and encoding
internal/agents/policy         policy parsing, evaluation, hot reload, test cases
internal/agents/schema         the argument-constraint schema subset
internal/agents/identity       static keys and signed tokens
internal/agents/ratelimit      GCRA buckets, daily quotas, upstream concurrency
internal/agents/approval       human approval requests and single-use grants
internal/agents/pins           tool definition pinning and quarantine
internal/agents/guard          output redaction, truncation and audit previews
internal/agents/audit          hash-chained audit log and verification
internal/agents/fakeserver     the tools behind `authz mcpfake`
internal/agents/httpx          request IDs, logging, metrics, errors
internal/agents/metrics        Prometheus text exposition
```

## License

MIT
