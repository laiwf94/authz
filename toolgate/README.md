# toolgate

A security gateway that sits between AI agents and the tools they call over
the [Model Context Protocol](https://modelcontextprotocol.io/specification/2026-07-28)
(MCP). Every tool call is authenticated, checked against a declarative policy,
rate limited, optionally approved by a human, and written to a tamper-evident
audit log before it reaches the real MCP server.

Written in Go with the standard library only (no third-party dependencies).

toolgate is now part of authz: the gateway is `authz mcp` and its fake
upstream `authz mcpfake`, in the one `authz` binary. Configuration, policy
files, endpoints and the audit format are unchanged, and the old command
names keep working; see
[Moving from the toolgate binary](#moving-from-the-toolgate-binary).

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
is compared in constant time; keys are issued, rotated and revoked on the
admin API without a restart), a short-lived token the gateway's own key
signs (HS256 JWS with `iss`, `aud`, `exp`, `nbf`, `iat`, a lifetime cap and
key rotation by `kid`), or an access token from an authorization server
(EdDSA, ES256 or RS256, verified against the keys of the issuer's pinned
JWKS; see [Agent tokens from an authorization server](#agent-tokens-from-an-authorization-server)).
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

A rule can also ask the authorization engine. Under `authz run` with its
serve part, a rule's `check` names a resource, a permission and a subject
built from the call, and the in-process engine is asked whether the subject
holds the permission, with no network hop:

```json
{"id": "edit-own-projects", "effect": "allow", "agents": ["*"],
 "upstreams": ["files"], "tools": ["write_file"],
 "check": {"resource": "project:{args.project}", "permission": "edit"}}
```

IDs are templates of `{owner}` (the user behind the agent), `{agent}` and
`{args.name}` (a string or integer argument, `{args.a.b}` for a nested one).
The subject defaults to `user:{owner}` and may be a userset
(`team:{args.team}#member`). In an allow rule the check is one more
condition: if the engine does not answer allowed, the rule does not allow
and the next one is tried. In a deny rule it is the condition for the deny,
and it fails closed: a missing or invalid value, a conditional answer or an
engine that cannot answer all deny. Each distinct check is asked once per
call, at `minimize_latency`. When the engine cannot answer and no other rule
allows the call, it is refused with 503 `-31012`, an outage rather than a
denial. Audit records list each check as
`resource#permission@subject: outcome`, and
`toolgate_relationship_checks_total{result}` counts them. A case file can
answer checks itself, with `"checks": {"project:p1#edit@user:alice":
"allowed"}` and the subject's `"owner"`, so `authz mcp policy test` needs no
engine.

Rules can also say when they apply and how often they allow:

```json
{"id": "deploy-office-hours", "effect": "allow", "agents": ["ci-bot"],
 "upstreams": ["ops"], "tools": ["deploy"],
 "windows": [{"zone": "Europe/Berlin", "days": ["mon", "tue", "wed", "thu", "fri"],
              "from": "09:00", "to": "17:00"}],
 "when": "args.env != 'prod' || session.auth == 'signed'",
 "limits": {"rate": 0.1, "burst": 2, "daily": 20, "zone": "Europe/Berlin"}}
```

- `windows`: the rule applies only while the local time in the window's
  IANA zone is in `[from, to)` on one of its `days` (every day when absent);
  a `to` earlier than `from` runs overnight. Times are wall-clock, so on the
  days the clocks change a window over the skipped hour is shorter and one
  over the repeated hour longer.
- `when`: a CEL expression, checked when the policy loads, over `now`
  (a timestamp; `now.getHours("Asia/Tokyo")` takes a zone), `args`, `agent`,
  `owner`, `upstream`, `tool`, `scopes` and `session` (`auth`, `issuer`,
  `key_id` and `protocol`). Use `has(args.x)` for an optional argument.
- In an allow rule a window that is closed or a condition that is false,
  fails or cannot be decided means the rule does not allow, and a default
  deny names it as `constraint_rule_id`. In a deny rule they say when it
  forbids, and an error counts as true. Conditions are tested before the
  relationship check, so a false one spares the engine.
- `limits` (allow rules only): `rate` calls a second with a `burst` (1 when
  absent) and `daily` calls a day, the day of `zone` (UTC when absent),
  counted per agent and rule. A refused call gets 429 with `-31002` and
  `"scope": "rule"` or `-31003`, both with the `rule_id` and a
  `Retry-After` (until midnight in the zone for the daily quota). The
  counts carry across reloads while a rule keeps its id and its limits;
  changing the limits starts them afresh.

Decisions are made at the gateway's clock. A case file gives a call case
its time as `"now": "2026-12-05T10:00:00+01:00"` and the subject its
`"session"`; without `now`, windows and conditions that read it are
unknown.

A policy can be tested like code. A case file lists calls and tool lists with
the decision each should get, and `authz mcp policy test POLICY CASES` checks
them all and prints, for each case that fails, what it expected next to what
the policy decided:

```console
$ authz mcp policy test narrowed.json examples/policy_cases.json
FAIL alice reads a note
     decision: want allow
                got deny
     rule:     want read-workspace
                got default-deny
     decided: deny by default-deny (arguments rejected by read-workspace): arguments rejected by rule read-workspace: $.path: path is outside the allowed directories
FAIL 17 cases: 16 passed, 1 failed
```

A single decision can be explained. `authz mcp policy explain POLICY CALL`
decides the call a file describes (a case without its name and
expectations, plus an optional `"checks"` map answering relationship
checks) and lists every rule for the upstream in the order they are tried,
with what each found: `subject_not_matched`, `tool_not_matched`,
`arguments_not_matched`, `conditions_false`, `conditions_unknown`,
`check_denied` (or another check outcome), `matched` or `not_reached`. The
rule that decided is marked `*` and the allow rule a default deny names is
marked `!`; `-json` prints the same object as the admin API:

```console
$ cat call.json
{"subject": {"agent": "alice-bot", "scopes": ["files:read"]},
 "call": {"tool": "fake.read_file", "arguments": {"path": "../etc/passwd"}}}
$ authz mcp policy explain examples/policy.json call.json
fake.read_file: deny by default-deny
  reason: arguments rejected by rule read-workspace: $.path: path must not contain ".." segments
  constraint rule: read-workspace
  at: unknown time
  policy: d461acec378432fec4b2666a799fd6a0906bf805b91966c4353202d391152c0f
rules (5 for this upstream, 0 for others):
    deny  no-dotenv                arguments_not_matched: $.path: does not match the required pattern
  ! allow read-workspace           arguments_not_matched: $.path: path must not contain ".." segments
    allow echo                     tool_not_matched
    allow web-allowlist            tool_not_matched
    allow translate-needs-approval tool_not_matched
```

On a running gateway, `POST /admin/explain` takes the same body without
`checks` and explains the call against the live policy, at the gateway's
clock unless the body gives `now`, asking the gateway's engine for
relationship checks (with the engine's trace of each, at most
`trace_nodes`, default 1000, when it runs in process). It adds what the
gateway would answer before the upstream: `outcome` (`allowed`,
`unknown_tool`, `quarantined`, `denied` or `check_unavailable`), the
JSON-RPC `code` and HTTP `status`, and `tool_known` from the last tool
list. It counts no limit or quota, creates no approval, asks no upstream,
writes no audit record and moves no tool call metric.

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

A rule can also refuse a result outright. `deny` takes the same built-in
names and `deny_patterns` custom RE2, all compiled when the policy loads:

```json
{"id": "search", "effect": "allow", "agents": ["*"], "upstreams": ["web"], "tools": ["search"],
 "output": {"redact": ["jwt"], "deny": ["github_token", "private_key"],
            "deny_patterns": ["INTERNAL-ONLY-[0-9]+"]}}
```

Deny patterns are tried first, on the result as the upstream sent it, over
every string and object key of the text and `structuredContent` (base64
image, audio and blob data excepted, as for redaction). If one matches, the
whole result is withheld and the agent gets `-31011` with
`{"rule_id": "search", "pattern": "deny_patterns[0]"}`: the pattern is
named by its built-in name or position, never by the matched text. When
several match, the one listed first is named. Otherwise redaction and
truncation run as before. An upstream error message that matches is
withheld too (still `-31007`, with the same `rule_id` and `pattern`). The
upstream did run the call, so a refused result counts against quotas. The
completed audit record of a call under such a rule carries `result`
(`allow`, `redact` or `refuse`) and, for a refusal, `result_pattern`;
`toolgate_tool_calls_total{outcome="result_refused"}` counts refusals.

The audit log is append-only JSONL. Each record carries the SHA-256 of the
previous line and is fsynced before the call goes ahead (concurrent calls
share an fsync). `authz mcp audit verify` finds any edit, deletion or
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

The same settings can instead live in the `mcp` section of the platform
configuration file, `authz mcp serve -config authz.json` (or
`AUTHZ_CONFIG=authz.json`), with secrets given as `{"file": ...}` or
`{"env": ...}`:

```json
{"version": 1,
 "mcp": {"config": "examples/config.json", "policy": "examples/policy.json",
         "audit_log": "audit.jsonl", "audit_key": {"file": "/run/secrets/mcp-audit-key"},
         "admin_token": {"file": "/run/secrets/mcp-admin-token"}, "state_dir": "."}}
```

The file, its secret files, the agents config and the policy are watched:
agents, signing keys, the policy and the log level change within about a
second, and an invalid change is refused with the running configuration
kept. With a file the `TOOLGATE_` variables are ignored and the
`AUTHZ_MCP_` ones override its members. `authz check -config authz.json`
validates it without starting.

Then point any MCP client at `http://127.0.0.1:8080/mcp` with
`Authorization: Bearer <agent key>`. Configuration is documented in
`authz mcp -h` and [cmd/authz/internal/mcp/mcp.go](../cmd/authz/internal/mcp/mcp.go); the config and policy formats in
[examples/config.json](examples/config.json) and
[examples/policy.json](examples/policy.json), with its test cases in
[examples/policy_cases.json](examples/policy_cases.json).

The Docker image holds the one `authz` binary (entry point `authz mcp`), runs
as `nonroot` on distroless, and keeps the audit log and tool pins in `/data`.
`/toolgate` and `/mcpfake` in it are links to `/authz`, so the old image's
`--entrypoint /toolgate` and `--entrypoint /mcpfake` still work. In this
example the fake upstream runs as a second container, so the config must name
it (`http://mcpfake:19100/mcp`):

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

`examples/image.sh` builds the image and runs this example through the old
entry points `/mcpfake` and `/toolgate`, with `TOOLGATE_` variables only: an
allowed and a refused read of the sandbox, `toolgate audit verify` on the log
the container wrote, `toolgate policy test` on the example cases, and a clean
`docker stop`. CI runs it on every change (the "Image (agents)" step of ci.yml).

## Agent tokens from an authorization server

Agents can authenticate with access tokens from an OAuth authorization
server or identity provider instead of keys the gateway holds. The gateway
is then an OAuth protected resource, as the MCP authorization
specification asks: a client that knows only the gateway's URL finds the
authorization server from the first 401, gets a token for this gateway
and calls with it. Two sections of the agents config set it up:

```json
{"resource": {"url": "https://mcp.example.com", "scopes_supported": ["files:read"], "name": "Example tools"},
 "issuers": [{"issuer": "https://idp.example.com", "audience": "https://mcp.example.com",
              "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
              "algorithms": ["ES256"], "claims": {"subject": "azp", "scopes": "scp"},
              "max_ttl_seconds": 900}]}
```

- `resource.url` is the gateway's resource identifier (RFC 8707), in
  canonical form: https (http only on loopback), lower-case host, no default
  port, query or trailing slash. Every issuer's `audience`, and
  `tokens.audience` when the gateway also signs tokens, must be exactly
  this URL, so a token the authorization server minted for another
  resource is refused.
- `issuer` is the exact `iss`; `jwks_uri` is where its keys are fetched,
  over https, through the egress guard. Keys never come from a URL in a
  token (`jku`, `x5u`, `jwk` and `x5c` are ignored). `claims` names the
  claims holding the agent id, owner and scopes (`sub`, `owner` and `scope`
  by default). An issuer on a private network needs its addresses in
  `private_networks`, and one with a private CA its bundle in `ca_file`.
- The same issuers can be listed in `$.mcp.issuers` of the platform file,
  after the agents config's. Both reload without a restart; a reload keeps
  a JWKS client and the keys it holds while its URL is unchanged.

What a client sees:

```console
$ curl -si -X POST https://mcp.example.com/mcp -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="toolgate", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read"

$ curl -s https://mcp.example.com/.well-known/oauth-protected-resource
{"authorization_servers":["https://idp.example.com"],"bearer_methods_supported":["header"],"resource":"https://mcp.example.com","resource_name":"Example tools","scopes_supported":["files:read"]}
```

The client reads the authorization server's own metadata (RFC 8414, at
`https://idp.example.com/.well-known/oauth-authorization-server`), asks its
token endpoint for a token with `resource=https://mcp.example.com`, and
sends it as `Authorization: Bearer`. A bad, expired or misdirected token
gets the same 401 with `error="invalid_token"` and says nothing about why.

Key rotation needs nothing from the gateway. The issuer publishes its new
key in the JWKS next to the old one, then starts signing with it: the
first token under the new `kid` makes the gateway fetch the set again (at
most once a minute; calls that arrive during the fetch wait for it, others
keep verifying), so no call fails. Keys the issuer drops stop verifying at
the next scheduled refresh, which follows the set's `max-age` from 5
minutes to 24 hours, and all of an issuer's keys stop 24 hours after its
last successful fetch.

A static key is revoked at once: `POST /admin/keys/{id}/revoke` answers
only after the revocation is saved and in force, and every call that
starts after the answer is refused with 401 `invalid_token` (see [API](#api)).

`TestMCPIssuerEndToEnd` in [cmd/authz](../cmd/authz/issuer_e2e_test.go)
runs all of this through the built binary and a local authorization
server on loopback TLS: discovery from the 401 to a served call, a token
for another resource refused, four agents calling without one failure
while the issuer rotates its key (one JWKS fetch for the new kid however
many agents present it), and a static key issued and then revoked while
its agent keeps calling.

## Moving from the toolgate binary

Nothing in a deployment has to change on the day it moves to authz:

| toolgate | authz | Notes |
|---|---|---|
| `toolgate [serve]` | `authz mcp [serve]` | same flags, exit codes and signals (SIGHUP reloads the policy) |
| `toolgate audit verify [-head HASH] FILE` | `authz mcp audit verify ...` | same output; logs written by toolgate verify and are continued |
| `toolgate policy test [-v] POLICY CASES` | `authz mcp policy test ...` | case files run unchanged |
| (new) | `authz mcp policy explain [-json] POLICY CALL` | also under the old name |
| `toolgate token new\|hash\|mint` | `authz mcp token ...` | |
| `mcpfake` | `authz mcpfake` | |
| `TOOLGATE_<NAME>` | `AUTHZ_MCP_<NAME>` | either spelling; both set to different values stops the command at start |
| `MCPFAKE_<NAME>` | `AUTHZ_MCPFAKE_<NAME>` | the same |
| image entry point `/toolgate` | `/authz mcp` | `/toolgate` and `/mcpfake` remain as links to `/authz` |

A binary invoked as `toolgate` or `mcpfake`, through a link such as
`ln -s authz toolgate`, runs `authz mcp` or `authz mcpfake` and names itself
the old way in its usage and error messages, so scripts that match them keep
working. Two things are new under both names: `-h` prints the help and exits
0, and a flag before the subcommand is a usage error with exit status 2. The
config `credential_env` names are read exactly as written. The recorded
decisions in `examples/demo_decisions.jsonl` came from the toolgate binary
and `examples/demo.sh` compares every `authz mcp` run with them, so the
decisions and audit records are the same.

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
| `POST /admin/explain` | A call file (`subject`, `call`, optional `now` and `trace_nodes`) decided against the live policy without being made: every rule considered and what it found, the decision, and the `outcome`, `code` and `status` the agent would get. 400 for an invalid call, 415 without `application/json`. |
| `GET /admin/audit/head` | Record count and head hash, to anchor the log elsewhere. |
| `GET /admin/audit/checkpoint` | The newest signed checkpoint of the audit log (`text/plain`, a signed note), with `AUTHZ_AUDIT_SIGNING_KEY` set; 404 without it. Check a log against it with `authz audit verify -key`. |
| `POST /admin/audit/export` | The newest signed checkpoint, as `GET /admin/audit/checkpoint` serves it, recorded as exported beside the log: with `AUTHZ_AUDIT_RETAIN_BYTES` or `AUTHZ_AUDIT_RETAIN_AGE`, retention may then remove the rotated-out segments it covers. 404 without a signing key. |
| `GET /admin/audit/proof` | An RFC 6962 proof over the audit log as JSON, with `AUTHZ_AUDIT_SIGNING_KEY` set: `?record=N` that record N is in the log, `?from=M` that the log extends its first M records; against the newest checkpoint, which it carries, or the first `size=S` records. 400 for bad parameters, 404 without a key or out of range. Check it with `authz audit prove -check`. |
| `GET /admin/keys` | The static key set and its `version` (also the `ETag`): every configured agent key that still verifies and every key the API issued, by `id` (the first 16 hex characters of its SHA-256), with `agent`, `source` (`config` or `issued`), `created` and, inside a rotation overlap, `until`. |
| `POST /admin/keys` | `{"agent":"alice-bot","version":N}` issues another static key for a configured agent and answers 201 with its `secret`, shown only here. |
| `POST /admin/keys/{id}/rotate` | `{"version":N,"overlap_seconds":3600}` issues a replacement; the old key verifies for the overlap (0 to 604800 seconds; 0 ends it at once). |
| `POST /admin/keys/{id}/revoke` | `{"version":N}` stops a configured or issued key at once. A revoked configured key stays revoked across restarts and reloads until the config lists another digest. |
| `GET /metrics` | Prometheus metrics. |

JSON-RPC errors from the gateway use codes outside the range JSON-RPC and MCP
reserve: `-31000` unauthenticated (401), `-31001` denied by policy, `-31002`
rate limited (429), `-31003` daily quota (429), `-31004` approval pending,
`-31005` approval denied, `-31006` tool quarantined, `-31007` upstream error
(502), `-31008` upstream timeout (504), `-31009` upstream busy (429), `-31010`
audit log unavailable (503), `-31011` result refused by a rule's deny
patterns (200, as a policy denial), `-31012` relationship check unavailable
(503). Protocol errors use the specification's codes:
`-32020` header mismatch, `-32022` unsupported version, `-32602` invalid params
or unknown tool. Clients in a 2025 session get every JSON-RPC error with
HTTP 200, as those revisions expect, and still get `Retry-After`.

Admin errors look like
`{"error":{"code":"not_found","message":"...","request_id":"..."}}`. A key
change against a version that is no longer current answers 409
`version_conflict` with the current version in the `ETag`: read the key set
again and retry.

## Tests and benchmarks

| Area | Test |
|---|---|
| Policy decisions | Random policies (wildcards, scopes, deny rules with and without argument schemas, path prefixes) and random calls are checked against an independent, naive reference evaluator, for both `Evaluate` and the `tools/list` filter. Breaking the engine on purpose (ignoring scopes, dropping `*` upstream rules from the index, ignoring deny-rule schemas, hiding tools on conditional denies) makes it fail. |
| Policy cases | The case parser is strict (unknown fields, duplicate keys and names, expectations that cannot apply are errors); a case written from the engine's own answer passes and the same case with the decision flipped fails on that field; the example cases run against the example policy in CI. |
| Rate limiting | Random schedules against an exact integer token-bucket reference; the GCRA limiter must admit exactly the same calls. |
| Audit log | Every single-byte flip is detected (by `Verify` or by the head hash); the log cut at every byte offset recovers exactly the complete records and the chain continues; edits, deletions, swaps and duplicates are reported at the right line; failed writes and fsyncs are injected. |
| End to end | A real gateway in front of a real MCP server over HTTP: filtered lists, credential injection, every denial path, rate limits, quotas, approval (including concurrent waiters, single use, denial), rug-pull quarantine and re-approval, redaction, truncation, upstream timeouts, oversized and malformed upstream replies, a down upstream, policy hot reload, signed tokens, tokens from an authorization server discovered from the 401 and verified through a key rotation under load, static keys revoked while in use, legacy sessions and session hijack attempts, audit failure refusing calls. The binary itself is restarted with its state to check that pins and the audit chain survive. |
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
| Signed token verification (HS256) | 2.3 to 2.6 µs |
| Rate limiter take | 0.10 to 0.12 µs |
| Audit append, one writer (fsync each) | 4.3 to 7.2 ms |
| Audit append, 16 writers (group commit) | 64 to 122 µs per record |
| `tools/call` end to end over HTTP, one agent | 8.6 to 17 ms |
| `tools/call` end to end, 64 concurrent callers | 0.8 to 1.2 ms per call |
| Denied `tools/call` end to end (one audit record) | 4.2 to 8.7 ms |

### Token verification and JWKS refresh

```console
$ go test -run='^$' -bench='Verify|JWKS' -benchmem ./internal/agents/identity/
```

These figures are from a shared 4-vCPU Intel Xeon at 2.1 GHz (Go 1.27,
linux/amd64), three runs each; they are slower than the table above, which
was measured on a faster machine. Each verification is a whole
`Authenticate`: header and claim parsing, key lookup, signature, and the
issuer, audience, lifetime and scope checks. "4 CPUs" is the time per token
with all four verifying at once (`RunParallel`); nothing on the path takes a
lock.

| Algorithm and key | One CPU | 4 CPUs | Allocated |
|---|---|---|---|
| HS256 (shared secret, for comparison) | 3.9 to 4.0 µs | 2.4 to 2.6 µs | 2.5 KB, 28 allocs |
| EdDSA (Ed25519) | 51 to 56 µs | 13 to 14 µs | 2.9 KB, 64 allocs |
| ES256 (P-256) | 77 to 82 µs | 21 µs | 4.3 KB, 86 allocs |
| RS256, 2048-bit key | 36 to 38 µs | 11 µs | 4.6 KB, 75 allocs |
| RS256, 3072-bit key | 143 to 150 µs | 62 to 69 µs | 46 KB, 159 allocs |
| RS256, 4096-bit key | 223 to 245 µs | 97 to 99 µs | 65 KB, 167 allocs |

Through a JWKS client the numbers are the same (EdDSA 50 to 55 µs, ES256
79 to 80 µs, RS256 35 to 38 µs): a known kid is read from the current set
without a lock or a request. The refresh path, against an issuer on
loopback TLS over a kept-alive connection:

| JWKS operation | Time | Allocated |
|---|---|---|
| Token with an unknown kid, refused inside the minute without a request | 5.9 µs | 3.0 KB, 64 allocs |
| Refresh answered 304 (ETag unchanged) | 71 to 78 µs | 8.3 KB, 87 allocs |
| Refresh answered 200, 3 keys (one of each type) | 105 to 123 µs | 16 KB, 158 allocs |
| Refresh answered 200, 100 keys (the most a set may hold, 22 KB) | 0.72 to 0.79 ms | 277 KB, 1772 allocs |
| Parsing alone, 3 keys / 100 keys | 9.6 to 11 µs / 0.31 to 0.32 ms | 5.5 KB / 185 KB |
| First token under a rotated key: unknown kid, fetch, swap, verify (EdDSA) | 187 to 201 µs | 20 KB, 232 allocs |

A refresh runs once per `max-age` (5 minutes to 24 hours) and an
unknown kid fetches at most once a minute, so the refresh path costs well
under a millisecond a minute per issuer; it never runs on a request for a
known kid. RSA keys of 3072 bits and more are about four and six times the
cost of 2048-bit ones and allocate ten times as much; issuers that can
choose should sign with EdDSA, ES256 or RS256 at 2048 bits.

## Repository map

The design notes in [docs/DESIGN.md](docs/DESIGN.md) cover the threat model,
the order of checks, the policy semantics, approvals, rug-pull detection, the
audit log format, how both MCP protocol eras are served, failure modes, limits
and what would change to run it as a fleet. toolgate is part of the authz
module: its packages live in the repository root under `internal/agents/`,
and its commands are `authz mcp` and `authz mcpfake` in the one `authz`
binary. Paths below are relative to the repository root:

```text
cmd/authz/internal/mcp         `authz mcp`: gateway entry point, `audit verify`, `policy test`, `policy explain` and `token`
cmd/authz/internal/mcpfake     `authz mcpfake`: a small MCP server to put behind the gateway
internal/agents/gateway        the enforcement pipeline, upstream tool caching, admin API, configuration
internal/agents/mcp            MCP over Streamable HTTP: dual-era server, client, header rules
internal/agents/jsonrpc        strict JSON-RPC 2.0 decoding and encoding
internal/agents/policy         policy parsing, evaluation, hot reload, test cases
internal/agents/schema         the argument-constraint schema subset
internal/agents/identity       static keys and signed tokens
internal/agents/ratelimit      daily quotas, upstream concurrency, the platform buckets
internal/platform/ratelimit    the platform's GCRA limiter (shared)
internal/agents/approval       human approval requests and single-use grants
internal/agents/pins           tool definition pinning and quarantine
internal/agents/guard          output refusal, redaction, truncation and audit previews
internal/platform/audit        the platform's hash-chained audit log (shared)
internal/agents/fakeserver     the tools behind `authz mcpfake`
internal/agents/httpx          request IDs, logging, metrics, errors
internal/platform/metrics      the shared metrics registry and Prometheus text exposition
```

## License

MIT
