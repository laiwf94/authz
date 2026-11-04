# authz design

The authorization core described first was the grantd service; since week 1
it is `authz serve` in the one binary. The sections after it cover how it and
the sign-on gateway moved in.

A check has to return exactly what the schema and the stored relationships
say, at a well-defined snapshot. It also has to avoid the new enemy problem:
after a client removes someone's access and then changes the protected thing,
the removed user must not see the change, which needs reads that are at least
as fresh as a known write. No single request may consume unbounded memory or
CPU, and the service ships as one binary with no dependencies and safe
defaults.

Multi-node replication and storage larger than memory are out of scope for this
version. Both are discussed under [Beyond one node](#beyond-one-node).

## Data model

A relationship is `resource#relation@subject`:

```text
doc:plan#editor@group:eng#member     members of eng are editors of doc:plan
group:eng#member@user:alice          alice is a member of eng
folder:pub#viewer@user:*             everyone can view folder:pub
```

The schema says which relations exist, which subject types each one accepts,
and how permissions are computed from relations. Writes are checked against the
schema, and a schema change is refused if any stored relationship would no
longer be valid. Data and schema can't drift apart.

## Storage: multi-version, in memory, with a write-ahead log

Every write is atomic and gets the next **revision**. Each relationship keeps a
list of versions `(created, deleted)`. A read at revision `r` sees a version
when `created <= r` and it was not deleted at or before `r`. A snapshot never
changes once written, which is what makes caching and consistency tokens simple.

Indexes are nested maps: `type -> "id#relation" -> subject -> versions`. A
check needs "subjects of `doc:plan#editor` at `r`", a single map lookup.

### History and garbage collection

The store keeps `GRANTD_RETENTION` revisions of history (default 100,000).
Older versions are collected every 128 writes. Reading or watching from before
the window returns `snapshot_expired` (HTTP 410), the same contract Zanzibar
uses: clients retry with a fresh read.

### Write-ahead log

Each committed write is appended as one line, then fsynced before the write is
acknowledged:

```text
<crc32c, 8 hex digits> <JSON record>\n
```

On start the log is replayed:

- A torn last record (no newline, or a bad checksum on the final line) is a
  write that was never acknowledged. It is dropped and the file truncated.
- A bad record anywhere else means the disk or file is damaged. Startup stops
  with an error. Guessing would silently lose acknowledged writes.
- After replay, the state is written as a single checkpoint record into a
  temporary file, fsynced, and atomically renamed over the log, so recovery
  time stays proportional to live data, not to history.

If an append fails half way, the partial bytes are truncated away. If even that
fails, the log refuses all further writes (HTTP 503) rather than appending after
garbage.

The test suite writes a series of random batches, then for **every byte
offset** of the resulting log, truncates a copy there and recovers it. The
recovered state must equal the state after some prefix of the acknowledged
writes.

The cost is write throughput: fsync per write under the store lock caps it at
the disk's sync rate. Group commit (batching concurrent writes into one fsync)
is the next step if write volume needs it. Checks are unaffected, because reads
take a shared lock.

## Consistency tokens

Every write and read returns a token naming its revision. A token is
`version || revision || HMAC-SHA256(key, version || revision)[:16]`, base64url
encoded.

Clients store the token next to the content it protects (Zanzibar's "zookie").
When they later check access to that content, they pass the token with
`at_least_as_fresh`. The server picks a snapshot at least that new, so a
permission change made before the content change is always visible.

Tokens are MACed so clients can't invent revisions. A forged future revision
would otherwise make reads fail or wait. Tokens from another key, a tampered
revision or an unknown version are all rejected.

### Shared snapshots

`minimize_latency` reads use a snapshot that is refreshed at most every 100 ms.
Thousands of checks then share one revision and therefore share cache entries.
`at_least_as_fresh` uses that shared snapshot when it is new enough, and the
newest revision only when it isn't. Most reads stay cacheable without giving up
freshness.

## The check engine

A check walks the schema's rewrite rules depth first:

- A relation reads the stored subjects and matches the target directly or
  through `user:*`, or recurses into stored usersets such as `group:eng#member`.
- A permission evaluates its expression. `+` short-circuits on the first
  true, `&` on the first false, and `a - b` evaluates `b` only when `a` is true.
- An arrow such as `parent->view` checks `view` on each object stored in
  `parent`.

A userset always contains itself, so `group:eng#member` can be the subject of a
check ("can everyone in eng view this?").

### Cycles

Data can form cycles: group A contains B, B contains A. The engine tracks the
`object#relation` nodes on the current path. Reaching one of them again counts
as "not reached through this path". Membership is the least fixpoint, and any
real path to the subject visits each node at most once, so the root answer is
still exact.

A result computed while a node was cut short may be different when the same
node is entered from elsewhere. Such results are marked **tainted** and are not
memoized or cached. The taint also flows through exclusions, where a "false"
on the right turns into a "true".

The engine is checked against a separate reference implementation that
computes every membership by iterating whole sets to a fixpoint, on random
graphs that include group and folder cycles. Breaking the engine on purpose
(ignoring exclusion, dropping the taint, ignoring wildcards) makes that test
fail.

### Limits

| Limit | Value | Why |
|---|---|---|
| Depth | 50 hops | Stops pathological chains; returns `resource_exhausted`. |
| Work | 100,000 node evaluations per check | Bounds CPU per request regardless of graph shape. |
| Deadline | 5 s per request | The context is checked at every node. |
| Body | 1 MiB | Checked before decoding. |
| Bulk | 100 checks | One snapshot, one response. |
| Write | 1,000 updates, 100 preconditions | Keeps the write lock short. |
| Schema | 256 KiB, 256 types, expression depth 32 | Bounds parse cost and stack use. |

### Caching

Results are cached in a sharded LRU keyed by
`revision | object#relation | subject`. A snapshot is immutable, so an entry can
never be wrong. The only question is whether it is still useful, which LRU
handles. Shared snapshots (above) make repeated checks land on the same keys.

## Lookups

`lookup/resources` answers "which docs can alice view?" by checking each
object of the type that has at least one relationship. Objects with no
relationships can't hold a permission, so the candidate set is complete. It
is exactly as correct as `check`, and each call evaluates at most 10,000
candidates before returning a cursor.

This is linear in the number of objects of the type. For very large types the
production answer is a reverse index (subject to resources), maintained from
the watch stream, like Zanzibar's Leopard index for nested groups.

## API security

- API keys are compared as SHA-256 digests with `subtle.ConstantTimeCompare`
  against every configured key, so timing does not reveal which key or prefix
  matched. Keys must be at least 16 characters.
- `GRANTD_TOKEN_KEY` is required when data is persisted, so tokens stay valid
  across restarts and can't be minted by clients.
- Strict JSON: unknown fields and trailing data are rejected; the body size is
  capped before decoding.
- Internal errors return a generic message and request ID. The details go to
  the server log only.
- Request IDs from clients are accepted only if they match a safe pattern;
  otherwise a random one is generated.

## Beyond one node

Running this as a fleet would start with the write path. Putting it behind
Raft, or a managed log, means a revision is committed on a quorum before it is
acknowledged. Followers apply the same log and serve reads at any revision they
have applied. A read at a token can then go to any replica: one that has not
yet applied the token's revision either waits briefly or forwards, and the
token format already carries everything needed for that.

The check work would be partitioned rather than the data. Zanzibar hashes
`object#relation` to servers so the same sub-problem is always evaluated, and
cached, in one place, and the engine's recursive calls become RPCs to the owner
of each node. Precomputing flattened group memberships from the watch stream,
as Leopard does, would make deep nesting cost one lookup instead of a walk.

For storage beyond memory, the map store can be swapped for an LSM or a SQL
table keyed by `(type, id, relation, subject, created_revision)`. The `Reader`
interface the engine depends on is a single method.

## One binary (authz serve)

grantd's packages moved to `internal/authz/{api,check,schema,store,token}`
and its command to `cmd/authz/internal/serve`, which exports `Run`;
`cmd/authz/main.go` dispatches `authz serve` to it. Every old main package
became its own package under `cmd/authz/internal` because grantd, wicket,
fakeidp, toolgate and mcpfake each define `run`, `env` or `loadConfig`, and
their test bodies call those names unqualified. `internal/metrics` stays
where it was until the shared registry in week 2.

**The contract.** An operator changes nothing: the `GRANTD_*` variables, the
data directory and its `grantd.wal`, the token key and so every issued token,
the endpoints, headers, error codes and messages, the `grantd_*` metric names,
the JSON log lines, and exit status 1 when it cannot start. The image's
default command is `serve`, so `docker run` with the old arguments starts
the same server. The one difference is at the command line: grantd ignored
arguments, while `authz serve` answers `-h` with its environment reference
and exits 2 for anything else.

**How it is checked.**

- *Golden transcript* (`internal/authz/golden`). The scenario is the README
  walk-through (`examples/demo.sh`) followed by every endpoint and error code
  one node can produce, then a restart on the same data directory. It runs
  with a fixed API key and token key, a request ID per request and an explicit
  consistency mode on every read, so nothing in it is random and nothing is
  replaced by a placeholder. The transcript keeps the status, every header but
  Date and Content-Length, the body, the `# TYPE` lines of `/metrics` and the
  non-request log lines without their time and address.
  `scripts/serve-golden.go` recorded it, and the demo's own output, from the
  grantd binary built at 41d9bf0, the last commit before the move. CI replays
  both through a built `authz serve`, and the Test step replays the
  transcript in process through serve's startup path.
- *Grantd's data directory.* The recording kept the `grantd.wal` that grantd
  wrote in the fresh phase. A test restarts `authz serve` on a copy and wants
  grantd's restart phase back, and another wants the log that `authz serve`
  writes in the same phase to equal grantd's byte for byte.
- *Test bodies and counts* (`scripts/testbody-diff.sh`). grantd's test files
  moved with only their import blocks and package clauses changed, and every
  package kept its tests: api 12, check 27, schema 9, store 19, token 3,
  metrics 2 and the command's 4, now in `cmd/authz/internal/serve`.

The restart phase also records a behaviour worth knowing: the log is
compacted into a checkpoint at the head on start, so tokens for the head stay
valid across a restart while older snapshots answer `snapshot_expired`.

## Sign-on gateway (authn)

The sign-on side, `authz gateway`, is the wicket command moved into the one
binary in week 1. Its internals (request flows, the SAML verification order,
the session log, key rotation, the threat model) are in
[wicket/docs/DESIGN.md](../wicket/docs/DESIGN.md), and the proxy snippets and
the move from wicket in [proxies.md](proxies.md). This section records what
the move had to keep and how that is checked.

**Layout.** Go's internal rule stopped the root binary from importing
`wicket/internal`, so the packages moved to `internal/authn/*` with
`scripts/rewrite-imports.go`, which changes import specs and nothing else, and
`cmd/wicket` and `cmd/fakeidp` became `cmd/authz/internal/gateway` and
`cmd/authz/internal/fakeidp`. Each old main package exports `Run`, and
`cmd/authz/main.go` lists it as a subcommand. When the binary is run as
`wicket` (the `/wicket -> /authz` link in both images), it behaves as
`authz gateway`.

**The contract.** An operator changes nothing: the same config file, the same
`WICKET_*` variables, endpoints, `__Host-wicket` cookies (so users stay
signed in across the upgrade), session file, JSON logs, SIGHUP reload and exit
codes. The one change is in `authz fakeidp`, a test tool: an undefined flag
now exits 2, as every subcommand does.

**How it is checked.** Four gates in `ci.yml` hold the contract:

- *Golden transcripts* (`internal/authn/golden/e2e`). Five transcripts
  recorded from the wicket code before the move pin every byte the gateway
  sends on the end-to-end paths: OIDC and SAML logins (with and without signed
  requests), forward-auth in nginx, Traefik and Envoy modes, the forbidden
  page, logout and the admin API. Only values that are random by construction
  (ports, sealed cookies, state, nonce, CSRF tokens, signatures, session IDs)
  become numbered placeholders, and times are written relative to the clock.
  The same scenarios replay in process against `server.New` and through
  `authz gateway`'s startup path: settings from `WICKET_*` variables, a
  wicket config file, key files, a session file and the gateway's own plain
  HTTP listeners behind a TLS-terminating client. The clock is the only thing
  injected, because the transcripts write times relative to it. A single
  changed header fails both with a line diff.
- *Test bodies* (`scripts/testbody-diff.sh`). Every wicket test file moved
  with only its import block and package clause changed.
- *Suite counts* (`scripts/suite-counts.go`). The 338 tests, subtests and
  fuzz seeds wicket ran before the move (73 attack, 6 property, 25 fuzz, 234
  unit) must all still run and pass.
- *The demo and the images.* `wicket/examples/demo.sh` runs a real nginx in
  Docker in front of the whoami app through `authz gateway` and
  `authz fakeidp`. `scripts/image-check.sh` serves one config through
  `/wicket`, the gateway image's entrypoint and `authz gateway`, and compares
  the responses.

## Agent gateway (agents)

The agent side, `authz mcp`, is the toolgate command moved into the one
binary in week 1. Its internals (the path of one call, the policy language,
approvals, tool pinning, the audit chain, both MCP eras, failures and
limits) are in [toolgate/docs/DESIGN.md](../toolgate/docs/DESIGN.md), and
the move from the toolgate binary in
[toolgate/README.md](../toolgate/README.md#moving-from-the-toolgate-binary).
This section records what the move had to keep and how that is checked.

**Layout.** The packages moved from `toolgate/internal/*` to
`internal/agents/*` with `scripts/rewrite-imports.go`, and `cmd/toolgate`
and `cmd/mcpfake` became `cmd/authz/internal/mcp` and
`cmd/authz/internal/mcpfake`, each exporting `Run` for `cmd/authz/main.go`.
`authz mcpfake` is a hidden subcommand: it runs, but `authz help` leaves it
out. A binary run as `toolgate` or `mcpfake` (the links in the toolgate
image) is `authz mcp` or `authz mcpfake`, and names itself the old way in
its usage and error messages.

**The contract.** An operator changes nothing: the same config and policy
files, `TOOLGATE_*` and `MCPFAKE_*` variables, endpoints on both listeners,
audit record format, pin store, SIGHUP and file-change reload, and exit
codes. Each variable may also be spelled `AUTHZ_MCP_*` or `AUTHZ_MCPFAKE_*`;
setting both spellings to different values stops the command at start
rather than picking one. Two things are new: `-h` prints help and exits 0,
and a flag before the subcommand is a usage error with exit 2.

**How it is checked.** Six gates in `ci.yml` hold the contract:

- *Recorded decisions* (`scripts/recorded-decisions.go`,
  `gateway.RecordDecisions`). `toolgate/examples/demo_decisions.jsonl` holds
  the 23 decisions of every demo scenario (allow, argument and deny-rule
  refusals, redaction, rate limit, approval and its single use, rug-pull
  quarantine), recorded from the toolgate binary before the move. Times,
  latencies and per-run identifiers become placeholders, numbered so that
  records sharing a request, an approval or the same arguments still show
  it; every other field (decision, rule, reason, outcome, preview,
  redactions, policy and tool hashes) is compared exactly. `demo.sh` runs
  every scenario through `authz mcpfake` and `authz mcp` and fails on any
  difference.
- *Old audit chains* (`internal/agents/audit/testdata`). A log written by
  the toolgate binary verifies under the new code with the same head, is
  opened and extended the way `authz mcp serve` does at start, and fails at
  the right line when a record is changed. `authz mcp audit verify` prints,
  for the log and seven damaged copies of it, exactly what the toolgate
  binary printed, with the same exit status.
- *Test bodies* (`scripts/testbody-diff.sh`). Every toolgate test file moved
  with only its import block and package clause changed, apart from two
  relative fixture paths the deeper directories force (listed in
  `scripts/testbody-allow.txt`).
- *Suite counts* (`scripts/suite-counts.go`). The 133 tests, subtests and
  fuzz seeds toolgate ran before the move must all run and pass under the
  race detector (`internal/agents/testdata/toolgate-suite.txt`).
- *Crash harness* (`TestMCPSurvivesSIGKILL`). The real `authz mcp serve`
  runs as a child process under load from six agents and is killed with
  SIGKILL at random points, eight times on one audit log and state
  directory, with a torn half-record left once. Every call the upstream saw
  must have a durable `started` record, every answered call its records,
  each restart must cut the torn tail and verify, and the pins must survive.
  It runs three more times in the "Suite counts (agents)" step.
- *Policy cases, the demo and the image.* `authz mcp policy test` runs the
  17 example cases unchanged, and `toolgate/examples/image.sh` runs the
  two-container example in the README through the image's `/mcpfake` and
  `/toolgate` links with `TOOLGATE_*` variables only.
