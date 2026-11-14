# authz

One identity and access platform in Go: it signs people and agents in, decides what they may do, and governs what AI agents do with their tools. It brings three projects together in one repository and, during November 2026, one module and one binary:

| Part | Started as | Today |
|---|---|---|
| Authorization | grantd | Zanzibar-style relationships, a schema language, consistent snapshots and a crash-safe write-ahead log (this directory) |
| Sign-on | wicket | OIDC and SAML single sign-on in front of any app through nginx, Traefik or Envoy forward-auth: `authz gateway` ([wicket/](wicket/), [docs/proxies.md](docs/proxies.md)) |
| Agent gateway | toolgate | A security gateway for AI agent tool calls over MCP: default-deny policy, approvals, rate limits and a tamper-evident audit log: `authz mcp` ([toolgate/](toolgate/)) |

All three keep their full history. The plan for the next year, three tracks in parallel, is in [ROADMAP.md](ROADMAP.md) and the issues labelled `roadmap`.

## Authorization (formerly grantd)

An authorization service in the style of Google's
[Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/):
you describe who can do what in a small schema, store relationships
("alice is a member of eng", "eng can edit this doc"), and ask
"can this user do this?". Answers are consistent with the writes you made,
fast, and explainable from the data.

Written in Go with the standard library only (no third-party dependencies).

```text
definition user {}

definition group {
  relation member: user | group#member         // groups can contain groups
}

definition folder {
  relation parent: folder
  relation viewer: user | user:* | group#member
  permission view = viewer + parent->view       // inherit from the parent folder
}

definition doc {
  relation parent: folder
  relation owner: user
  relation editor: user | group#member
  relation banned: user
  permission edit = owner + editor
  permission view = (edit + parent->view) - banned
}
```

```console
$ curl -s localhost:8080/v1/check -H "$AUTH" -H 'Content-Type: application/json' \
    -d '{"resource":"doc:design","permission":"view","subject":"user:alice"}'
{"allowed":true,"checked_at":"AQAAAAAAAAAD..."}
```

## Checking a permission

The schema above uses every operator the language has: relations, computed
permissions, union `+`, intersection `&`, exclusion `-`, arrows such as
`parent->view`, nested groups through `group#member`, and public access through
`user:*`. A schema is validated before it is accepted. Unknown names, unsafe
arrows and permissions that depend on themselves are rejected with a line and
column.

With a schema and some relationships in place, you can ask whether alice can
view `doc:plan`, send up to 100 such questions at once, or ask which docs alice
can view and page through the answer. A watch call long-polls for every
relationship change after a token, which is how a cache or search index stays
in sync.

Every write gets a revision and returns a signed consistency token. A read can
ask to be at least as fresh as a token, so a user who was just removed can't
see the next change. Zanzibar calls this the new enemy problem.

Writes go to a checksummed write-ahead log, fsynced per write and compacted
into a checkpoint on start. Recovery is tested by cutting the log at every
byte. Around that sit API keys checked in constant time, limits on request size
and work, deadlines, structured JSON logs with request IDs, Prometheus metrics
and graceful shutdown.

## Running authz

Everything is one binary, `authz`, with a subcommand per part
(`authz help` lists them). `authz serve` is the authorization API that used
to be the grantd command, with the same `GRANTD_*` environment variables.

```console
$ export GRANTD_API_KEYS=local-dev-key-0123456
$ go run ./cmd/authz check -serve -schema examples/docs.schema   # validate without starting
$ go run ./cmd/authz serve                     # in memory; add GRANTD_DATA_DIR and GRANTD_KEYS_FILE to persist
$ ./examples/demo.sh                           # writes a schema and data, then runs checks
```

`authz ctl` talks to a running server, with the key in `AUTHZ_API_KEY` and
the address in `AUTHZ_URL` (default `http://localhost:8080`):

```console
$ export AUTHZ_API_KEY=local-dev-key-0123456
$ authz ctl schema write examples/docs.schema
$ tok=$(authz ctl rel touch group:eng#member@user:alice doc:design#editor@group:eng#member)
$ authz ctl check -token "$tok" doc:design edit user:alice
allowed
$ authz ctl rel read doc:design            # pages through every match at one snapshot
$ authz ctl lookup doc view user:alice
```

`check` exits 0 when allowed and 3 when denied; every subcommand exits 2 for
a usage error. `authz check -relationships file -schema file` validates a
file of relationships against a schema before you load it, and
`authz check -config authz.json` validates the platform configuration file
(its `serve`, `gateway` and `mcp` sections, see
[docs/DESIGN.md](docs/DESIGN.md#one-configuration-file-internalplatformconfig)),
`authz serve -config authz.json` starts from its serve section, applying
API key and log level changes while it runs, and `authz gateway -config
authz.json` from its gateway section, applying cookie key, provider, app and
log level changes while it runs, and `authz mcp serve -config authz.json`
from its mcp section, applying agent, signing key, policy and log level
changes while it runs.

`authz run` starts `serve`, `gateway` and `mcp serve` in one process. Each
part reads the configuration its own subcommand reads (the `GRANTD_`,
`WICKET_` and `TOOLGATE_` variables, or the serve and gateway sections of
`-config authz.json`), and they share one listener group and one metrics
registry: every listener is bound together or not at all, `/metrics` on any
part shows the metrics of all three, SIGTERM flips every `/readyz` at once
and drains every listener within one bound, and each log line says which
part wrote it. TLS and draining are set once for every listener with
`AUTHZ_TLS_CERT`, `AUTHZ_TLS_KEY`, `AUTHZ_TLS_CLIENT_CA`, `AUTHZ_DRAIN_DELAY`
and `AUTHZ_DRAIN_TIMEOUT`; a part's own TLS or drain setting is refused.
`-parts serve,gateway` runs a subset. If a part cannot start, nothing is
bound and the command exits 1 naming that part.

Under `authz run` there is one grantd engine. The gateway and mcp parts ask
serve's engine in process (`part.Host.Engine` hands it to them): no network
hop, the same check cache, and the same consistency tokens as the HTTP API,
so a token from a `/v1/relationships/write` is good for an in-process check
and the other way round. In-process checks show in
`grantd_check_duration_seconds` on every `/metrics`. Gateway route rules
and MCP tool rules that make such checks come with the sign-on and agent
roadmap weeks ([#82](https://github.com/laiwf94/authz/issues/82),
[#87](https://github.com/laiwf94/authz/issues/87)).

```console
$ authz run -config authz.json
$ authz run -parts serve,mcp
```

Nothing changes for an existing grantd deployment: the same variables, data
directory (`grantd.wal`), tokens, endpoints, error codes, metric names and
logs. CI holds that to a recording made from the grantd binary before the
move: every request of the demo above plus every endpoint and error code,
then a restart on the same data directory, must produce the same status,
headers, body and startup log byte for byte through `authz serve`, and
`authz serve` must start on a data directory grantd wrote
([internal/authz/golden](internal/authz/golden)):

```console
$ go build -o /tmp/authz ./cmd/authz
$ go run scripts/serve-golden.go -- /tmp/authz serve
internal/authz/golden/testdata/serve.golden: matches (28701 bytes)
internal/authz/golden/testdata/demo.golden: matches (448 bytes)
```

Or with Docker:

```console
$ docker build -t authz .
$ docker run -p 8080:8080 -e GRANTD_API_KEYS=local-dev-key-0123456 authz
```

## Sign-on gateway (formerly wicket)

`authz gateway` puts OIDC and SAML single sign-on in front of any app as the
forward-auth backend of nginx, Traefik or Envoy. It is the wicket command
moved into the one binary, and nothing changes for an operator: the same
config file, the same `WICKET_*` variables, endpoints, cookies, session file,
logs, SIGHUP reload and exit codes. Both images keep `/wicket` as a link to
`/authz`, so `wicket check` and `wicket genkey` still work.

```console
$ go build -o authz ./cmd/authz
$ export WICKET_COOKIE_KEYS=$(./authz gateway genkey)
$ ./authz gateway check -online wicket.json    # your config: file checks, then each provider
$ WICKET_CONFIG=wicket.json ./authz gateway     # :4180, admin API on 127.0.0.1:4181
$ ./wicket/examples/demo.sh                     # nginx in Docker, OIDC and SAML logins, end to end
```

`WICKET_KEYS_FILE` (or `keys_file` in the gateway section) moves the cookie
keys and the upstream signing key onto rotating key rings in one file, which
the first start fills from `WICKET_COOKIE_KEYS` and `WICKET_SIGNING_KEYS` so
nobody is signed out; the published JWKS follows every rotation (see
[docs/DESIGN.md](docs/DESIGN.md#key-rings-in-the-gateway)).

`"revalidate": {"interval": "5m"}` on an OpenID provider confirms every
session with its refresh token at that interval and ends it when the
provider refuses (a disabled user), or by `on_failure` (`end` or `grace`)
when the provider can't be asked.

The end-to-end responses are pinned byte for byte in golden transcripts
recorded from wicket before the move, and CI replays them through
`authz gateway` started from a wicket config file. Proxy snippets and the
move from wicket are in [docs/proxies.md](docs/proxies.md); the gateway's
design and tests are in [wicket/README.md](wicket/README.md) and
[wicket/docs/DESIGN.md](wicket/docs/DESIGN.md).

## Agent gateway (formerly toolgate)

`authz mcp` sits between AI agents and the MCP servers whose tools they
call. Every call is authenticated, checked against a default-deny policy,
rate limited, optionally held for a human's approval and written to a
hash-chained audit log before it reaches the upstream. It is the toolgate
command moved into the one binary, and a deployment changes nothing: the same
config and policy files, the same `TOOLGATE_*` variables (each may also be
spelled `AUTHZ_MCP_*`), endpoints, audit format, tool pins, SIGHUP reload and
exit codes. Audit logs written by toolgate verify under `authz mcp` and are
continued. The toolgate image keeps `/toolgate` and `/mcpfake` as links to
`/authz`.

```console
$ go build -o authz ./cmd/authz
$ ./authz mcp policy test toolgate/examples/policy.json toolgate/examples/policy_cases.json
PASS 17 cases: 17 passed, 0 failed
$ ./authz mcp audit verify audit.jsonl          # names the first line that was changed, removed or reordered
$ ./toolgate/examples/demo.sh                   # authz mcpfake and authz mcp, every scenario end to end
```

The demo's decisions and audit records are pinned in
`toolgate/examples/demo_decisions.jsonl`, recorded from the toolgate binary
before the move, and every run through `authz mcp` must match them. The
policy language, approvals, pinning, both MCP eras and the move from the
toolgate binary are in [toolgate/README.md](toolgate/README.md) and
[toolgate/docs/DESIGN.md](toolgate/docs/DESIGN.md).

`TOOLGATE_KEYS_FILE` (or `keys_file` in the mcp section) moves the agent
token signing keys onto a rotating `agent` key ring in the process's key
ring file, which the first start fills from `TOOLGATE_SIGNING_KEYS` so no
token is refused; `authz mcp token mint` signs with its current key (see
[docs/DESIGN.md](docs/DESIGN.md#key-rings-in-the-agent-gateway)).

Running in production, rotating keys, retiring a compromised one and how
configuration changes reach a running process are covered in
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## One audit chain

Every part of the platform writes to one hash-chained audit log: `authz
serve` its writes, schema changes and (with `GRANTD_AUDIT_CHECKS=true`)
every check decision; `authz gateway` sign-ins, logouts, admin actions and
denials; `authz mcp` tool calls, approvals and quarantines. So a sign-in, a
permission change and an agent's tool call are links of the same chain, and
one signed checkpoint covers them all. Run as three processes on a host,
the three subcommands may share one file: each append locks it, reads what
the others wrote since and chains its record after them. Every record is
checked against its event's typed schema before it is written, and carries
the request's correlation ID, the trace ID of its `traceparent` or a new
one, which is also on the request's log lines and is passed on to
upstreams.

A log nobody but the operator can check proves little, so the log is built
for an auditor who trusts only a public key:

| Piece | What it gives | Files beside `audit.jsonl` |
|---|---|---|
| Hash chain | no record changed, removed or reordered, except at the end | |
| Segments | the file rotates by size or age; the chain runs on across segments, and a missing one is named | `audit.jsonl.<first record>` |
| Signed checkpoints | the record count, the RFC 6962 tree head and the last record's hash, signed with Ed25519 in the signed note format: records cut from the end are caught | `.checkpoint`, `.tree` |
| Proofs | one record is in the log, or today's log extends an earlier checkpoint, in about log2(N) hashes, checked without the log | |
| Query | records by track, tenant, actor, agent, tool, rule, decision, payload field and time, read with the chain checked; a sparse time index skips the rest | `.<first record>.idx` |
| Retention | old segments go once an exported checkpoint covers them; the tree head and the proofs of what is left are unchanged | `.exported`, `.base` |

### Setting it up

```console
$ ./authz audit keygen -out /etc/authz/audit.key audit.example.com     # the auditor gets the public key it prints
audit.example.com+1d9f0a3c+AaW...
$ export AUTHZ_AUDIT_SIGNING_KEY_FILE=/etc/authz/audit.key             # every subcommand signs checkpoints with it
$ export GRANTD_AUDIT_LOG=/var/lib/authz/audit.jsonl GRANTD_AUDIT_CHECKS=true
$ export WICKET_AUDIT_LOG=/var/lib/authz/audit.jsonl
$ export AUTHZ_MCP_AUDIT_LOG=/var/lib/authz/audit.jsonl
$ export GRANTD_AUDIT_ROTATE_BYTES=67108864 WICKET_AUDIT_ROTATE_BYTES=67108864 AUTHZ_MCP_AUDIT_ROTATE_BYTES=67108864
$ export AUTHZ_AUDIT_RETAIN_BYTES=1073741824                           # optional: keep about 1 GiB of old segments
```

`*_AUDIT_ROTATE_BYTES` and `*_AUDIT_ROTATE_AGE` (or `audit_rotate_bytes`
and `audit_rotate_age` in a section of the configuration file) cut the
file into segments; older ones sit beside it named for their first record,
each linked to the one before. Every process writing the file must set the
same limits, and one that does not is refused at start. With the signing
key, each subcommand writes a checkpoint to `audit.jsonl.checkpoint` on
start, every `AUTHZ_AUDIT_CHECKPOINT_INTERVAL` (default `1m`) when records
were added, after each rotation and on shutdown. The key, the interval and
the retention limits are platform-wide variables, read by all three
subcommands; `authz check` reports a malformed or missing one before
anything starts.

### Checking it

`authz audit verify` checks every segment as one chain and every record
against its schema; with `-key` it also checks the newest checkpoint, or
one the auditor saved, against the log. A segment that was removed,
renamed, reordered or replaced is named:

```console
$ ./authz audit verify -key audit.example.com+1d9f0a3c+AaW... /var/lib/authz/audit.jsonl
OK /var/lib/authz/audit.jsonl: 829 records in 27 segments, head ac8735bc...
OK /var/lib/authz/audit.jsonl: checkpoint signed by audit.example.com at 2026-11-20T10:05:00Z covers 807 of the 829 records
$ rm /var/lib/authz/audit.jsonl.00000000000000000372                     # someone removes a middle segment
$ ./authz audit verify /var/lib/authz/audit.jsonl
FAIL /var/lib/authz/audit.jsonl: /var/lib/authz/audit.jsonl.00000000000000000404: records 372 to 403 are missing between audit.jsonl.00000000000000000343 and this segment; a segment (audit.jsonl.00000000000000000372) was removed
```

`authz audit query FILE TERM...` prints the records every term matches, as
the JSON lines they are, checking the chain as it reads. Terms filter on
`track`, `event`, `tenant`, `actor`, `subject`, `action`, `decision` and
`correlation`, on an agent's `agent`, `tool` and `rule`, on any payload
field (`data.NAME`), and on time (`since`, `until`). A query bounded in
time skips the segments, and the parts of segments, that hold nothing in
its window, using the time index the first query writes beside each
rotated-out segment:

```console
$ ./authz audit query /var/lib/authz/audit.jsonl track=agents agent=report-bot decision=deny since=-24h
{"seq":977,"time":"2026-11-20T10:04:11.52Z",...,"event":"tool_call",...,"data":{"agent":"report-bot",...,"decision":"deny","rule_id":"default-deny",...}}
authz audit query: 1 of 1204 records matched; 310 read with the chain checked, 894 outside the times skipped by the time index (authz audit verify reads them)
$ ./authz audit query -count /var/lib/authz/audit.jsonl track=authn decision=deny subject=app:wiki,app:crm
```

### Proving it to an auditor

The auditor keeps the public key and the checkpoints they were given, and
never needs the log or the admin token. The mcp admin API serves the newest
checkpoint at `GET /admin/audit/checkpoint`, an RFC 6962 inclusion proof of
record N at `GET /admin/audit/proof?record=N`, and a proof that the log
extends an earlier checkpoint of M records at `?from=M` (both with
`&size=S` for a checkpoint of S records); `authz audit prove -record N|-from
M FILE` makes the same proofs from the files. `authz audit prove -check`
checks one with the public key alone, and with query terms also checks that
the record proved is what the auditor was told it is:

```console
$ curl -H "Authorization: Bearer $ADMIN" localhost:8081/admin/audit/checkpoint > evidence/checkpoint
$ curl -H "Authorization: Bearer $ADMIN" "localhost:8081/admin/audit/proof?record=977&size=1204" > evidence/record.proof
$ curl -H "Authorization: Bearer $ADMIN" "localhost:8081/admin/audit/proof?from=512&size=1204" > evidence/grew.proof
$ examples/audit/auditor.sh audit.example.com+1d9f0a3c+AaW... saved.checkpoint evidence \
    track=agents agent=report-bot tool=http_get decision=deny
OK evidence/grew.proof: the 1204 records signed by audit.example.com at 2026-11-20T10:05:00Z extend the 512 signed at 2026-11-19T17:00:00Z
OK evidence/record.proof: record 977 (tool_call at 2026-11-20T10:04:11.52Z) is in the 1204 records signed by audit.example.com at 2026-11-20T10:05:00Z and matches track=agents agent=report-bot tool=http_get decision=deny
{"seq":977,...}
```

[examples/audit/auditor.sh](examples/audit/auditor.sh) is the auditor's
side in full: the consistency proof shows the log shown now extends the one
the auditor saw last time (nothing they were shown was dropped or
rewritten since, and there is no second log), the inclusion proof shows the
record is in it byte for byte, and the terms that it is a denial of that
call. A claim the record does not back, such as `decision=allow`, fails.
Then the newer checkpoint becomes the one they keep.
[examples/audit/demo.sh](examples/audit/demo.sh), which CI runs, does the
whole thing: three processes rotating one busy log, verify with the public
key, the auditor's proof of an agent's denied call, a false claim refused,
and a removed middle segment named by verify and query.

### Retention

With `AUTHZ_AUDIT_RETAIN_BYTES` or `AUTHZ_AUDIT_RETAIN_AGE` (and the
signing key), the oldest rotated-out segments are removed once they are
past the limit, but only those an exported checkpoint covers: one handed
out by `POST /admin/audit/export` or `authz audit export`, which records it
as `audit.jsonl.exported`. `audit.jsonl.base` keeps the removed records'
count, last hash and Merkle range, so the auditor's checkpoints still
verify and proofs of the records left are unchanged:

```console
$ ./authz audit export -key audit.example.com+1d9f0a3c+AaW... -out saved.checkpoint /var/lib/authz/audit.jsonl
OK /var/lib/authz/audit.jsonl: checkpoint of 977 records signed by audit.example.com at 2026-11-20T10:05:00Z recorded as exported in /var/lib/authz/audit.jsonl.exported
```

A sign-in, the check it leads to and the tool call that check allows
follow one another in one verified chain under one correlation ID; CI runs
exactly that across the three processes. The format, the locking, the
segment, checkpoint and index formats, and what each check does and does
not prove are in [docs/DESIGN.md](docs/DESIGN.md#one-audit-log-internalplatformaudit).

## HTTP API

The authorization API (`authz serve`). All `/v1` endpoints take `Authorization: Bearer <key>` and JSON bodies.

| Endpoint | Purpose |
|---|---|
| `PUT /v1/schema` | Replace the schema. Refused if existing data would break it. With `?dry_run=true` it writes nothing and lists the `changes`, the `affected_permissions` and the `breaking_relationships` (up to `limit`, at most 1,000, with `breaking_count` for all). |
| `GET /v1/schema` | Current schema in canonical form. |
| `POST /v1/relationships/write` | Atomic batch of `touch` / `create` / `delete`, with optional preconditions. Returns `written_at`. |
| `POST /v1/relationships/read` | Filtered, paged read at a snapshot. |
| `POST /v1/relationships/delete` | Delete everything matching a filter in one revision, up to `limit` (at most 1,000), with optional preconditions; `allow_partial` deletes the first `limit` in text order and answers `partial: true`. Returns `deleted` and `deleted_at`. |
| `POST /v1/check` | One permission check. |
| `POST /v1/check/bulk` | Up to 100 checks at one snapshot. |
| `POST /v1/lookup/resources` | Objects of a type the subject can access, paged. |
| `POST /v1/lookup/subjects` | Subjects of a type (or `group#member` usersets) that hold a permission on one object, paged; a wildcard comes back as `user:*` with the IDs it `excluded`. |
| `POST /v1/expand` | Who holds a permission on one object, as a userset tree; `recursive` follows usersets, `max_nodes` bounds it. |
| `POST /v1/watch` | Changes after a token; waits up to 30 s for new ones. |
| `GET /healthz`, `GET /metrics` | Health (no auth) and Prometheus metrics. |

Every read takes an optional `consistency`:

| Mode | Snapshot used |
|---|---|
| `minimize_latency` (default) | A recent snapshot shared for 100 ms, so repeated checks hit the cache. |
| `at_least_as_fresh` + `token` | No older than the token. Use the token from your own write. |
| `at_exact_snapshot` + `token` | Exactly the token's snapshot, e.g. to page consistently. |
| `fully_consistent` | The newest committed write. |

Errors look like `{"error":{"code":"invalid_argument","message":"...","request_id":"..."}}`
with stable codes: `invalid_argument` 400, `unauthenticated` 401, `already_exists` 409,
`snapshot_expired` 410, `failed_precondition` 412, `resource_exhausted` 422,
`no_schema` 424, `unavailable` 503, `deadline_exceeded` 504.

## Correctness

| What | How |
|---|---|
| Permission logic | Random graphs of nested groups, folder trees (with cycles), bans and intersections are checked against an independent reference that computes memberships by fixpoint iteration over whole sets. Deliberately broken versions of the engine fail this test. |
| Crash safety | The log is truncated at every byte offset; recovery must always produce exactly the state after some prefix of acknowledged writes. Corruption in the middle of the log stops startup instead of silently losing data. |
| Parsers | Go fuzzing of the schema and relationship parsers: anything that parses must round-trip through its canonical form. |
| API | Every endpoint and error code over real HTTP, including read-your-writes under concurrent writers, auth, body limits and the watch long-poll. |
| Concurrency | The whole suite runs under the race detector in CI. |
| Compatibility | `authz serve` replays grantd's recorded end-to-end transcript and restarts on grantd's data directory; every grantd test moved with only its imports and package clause changed (`scripts/testbody-diff.sh`). |

```console
$ go test -race ./...                 # full suite
$ go test -run=^$ -bench=. ./internal/authz/check/
```

## Check latency

Engine benchmarks on an Apple M4 Max, a document inheriting access through a
chain of folders, each folder holding 20 unrelated viewers:

| Case | Time per check |
|---|---|
| Folder chain depth 1 | 5.6 µs |
| Folder chain depth 10 | 42 µs |
| Folder chain depth 40 | 167 µs |
| Depth 40, cached at the snapshot | 0.23 µs |

Cached results never go stale: the cache key includes the snapshot revision, and a
snapshot never changes.

## Code map

The design notes in [docs/DESIGN.md](docs/DESIGN.md) cover the data model, the
log format and recovery, how consistency tokens work, how cycles are handled,
the trade-offs taken and what would change to run this across many machines.

```text
cmd/authz                   the one binary: subcommand dispatcher and version
cmd/authz/internal/serve    authz serve (formerly grantd): configuration and startup
cmd/authz/internal/ctl      authz ctl: HTTP client for schema, relationships, checks
cmd/authz/internal/checkcmd authz check: validate the config file, environment, schema and relationship files
cmd/authz/internal/runcmd   authz run: serve, gateway and mcp in one process, one listener group and one registry
cmd/authz/internal/part     what a serving subcommand takes from its process: listeners, registry, log name, the engine
internal/authz/schema       schema language: lexer, parser, validation, canonical printer
internal/authz/store        multi-version relationship store and write-ahead log
internal/authz/check        check engine, result cache, lookups
internal/authz/token        signed consistency tokens
internal/authz/api          HTTP API, auth, errors, logging, metrics wiring
internal/authz/golden       end-to-end transcript of the API, recorded from grantd
cmd/authz/internal/gateway  authz gateway (formerly wicket): environment, startup, check
cmd/authz/internal/fakeidp  authz fakeidp: test OIDC and SAML identity provider
internal/authn/...          sign-on: forward-auth server, OIDC, SAML, sessions, policy
internal/authn/golden/e2e   the gateway's end-to-end golden transcripts
cmd/authz/internal/mcp      authz mcp (formerly toolgate): config, serve, audit verify, policy test, tokens
cmd/authz/internal/auditcmd authz audit verify, prove, query, export and keygen: the platform's audit log across its segments, with schemas and signed checkpoints
cmd/authz/internal/mcpfake  authz mcpfake: a small MCP server with a file sandbox, to try the gateway
internal/agents/...         agent traffic: MCP and JSON-RPC, policy, approvals, pins, limits, audit chain
internal/platform/keys      key rings with rotation, JWKS and the old key files
internal/platform/jose      JWS/JWK/JWT: verification, ES256 signing, HS256 agent tokens
internal/platform/seal      AES-256-GCM cookie sealing with key rotation
internal/platform/metrics   one metrics registry: counters, gauges, histograms, series caps
internal/platform/httpserver one HTTP server setup: listeners, TLS, limits, readiness, drain, shared groups
internal/platform/storage/wal one append log: typed record streams, CRC32C, fsync policy, recovery
```

## License

MIT
