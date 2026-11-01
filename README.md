# authz

One identity and access platform in Go: it signs people and agents in, decides what they may do, and governs what AI agents do with their tools. It brings three projects together in one repository and, during November 2026, one module and one binary:

| Part | Started as | Today |
|---|---|---|
| Authorization | grantd | Zanzibar-style relationships, a schema language, consistent snapshots and a crash-safe write-ahead log (this directory) |
| Sign-on | wicket | OIDC and SAML single sign-on in front of any app through nginx, Traefik or Envoy forward-auth ([wicket/](wicket/)) |
| Agent gateway | toolgate | A security gateway for AI agent tool calls over MCP: default-deny policy, approvals, rate limits and a tamper-evident audit log ([toolgate/](toolgate/)) |

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
    -d '{"resource":"doc:plan","permission":"view","subject":"user:alice"}'
{"allowed":true,"checked_at":"AQAAAAAAAAAC..."}
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
$ go run ./cmd/authz serve                     # in memory; add GRANTD_DATA_DIR and GRANTD_TOKEN_KEY to persist
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
file of relationships against a schema before you load it.

Or with Docker:

```console
$ docker build -t authz .
$ docker run -p 8080:8080 -e GRANTD_API_KEYS=local-dev-key-0123456 authz
```

## HTTP API

All `/v1` endpoints take `Authorization: Bearer <key>` and JSON bodies.

| Endpoint | Purpose |
|---|---|
| `PUT /v1/schema` | Replace the schema. Refused if existing data would break it. |
| `GET /v1/schema` | Current schema in canonical form. |
| `POST /v1/relationships/write` | Atomic batch of `touch` / `create` / `delete`, with optional preconditions. Returns `written_at`. |
| `POST /v1/relationships/read` | Filtered, paged read at a snapshot. |
| `POST /v1/check` | One permission check. |
| `POST /v1/check/bulk` | Up to 100 checks at one snapshot. |
| `POST /v1/lookup/resources` | Objects of a type the subject can access, paged. |
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
cmd/authz/internal/checkcmd authz check: validate environment, schema and relationship files
internal/authz/schema       schema language: lexer, parser, validation, canonical printer
internal/authz/store        multi-version relationship store and write-ahead log
internal/authz/check        check engine, result cache, lookups
internal/authz/token        signed consistency tokens
internal/authz/api          HTTP API, auth, errors, logging, metrics wiring
internal/metrics            Prometheus text exposition
```

## License

MIT
