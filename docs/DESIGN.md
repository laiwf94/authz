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
  across restarts and can't be minted by clients. It may list several keys,
  newest first: the keys form an HS256 ring (`internal/platform/keys`), the
  first MACs new tokens and every key verifies, so rotating means putting a
  new key in front and removing the old one once its tokens no longer
  matter. Tokens carry no key id; a token is checked against the current key
  first, then the others, so a forged token costs at most one MAC per key.
- Strict JSON: unknown fields and trailing data are rejected; the body size is
  capped before decoding.
- Internal errors return a generic message and request ID. The details go to
  the server log only.
- Request IDs from clients are accepted only if they match a safe pattern;
  otherwise a random one is generated.
- `GRANTD_KEY_RATE` (requests per second) and `GRANTD_KEY_BURST` limit each
  API key with the platform limiter (below). The limit is taken after the
  key is recognised, so failed authentications and `/healthz` cost nothing;
  a request over it gets 429 `resource_exhausted` with `Retry-After`, counted
  in `grantd_rate_limited_total`. It is off by default.

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
their test bodies call those names unqualified. `internal/metrics` stayed
where it was until the shared registry in week 2; it is now
`internal/platform/metrics`.

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
- *Old audit chains* (`internal/platform/audit/testdata`). A log written by
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

## One audit log (internal/platform/audit)

toolgate's hash-chained writer moved to `internal/platform/audit` in week 2
(#78) so that all three parts append to one chain. The line format is
toolgate's, with an optional envelope between `event` and `data`:

    {"seq":3,"time":"…","prev":"<sha256 of line 2>","event":"authz.check_decided",
     "tenant":"acme","actor":"gateway","subject":"document:readme","action":"view",
     "decision":"allow","correlation_id":"4bf92f35…","data":{"principal":"user:alice",…}}

Every envelope field is optional in the format, and `Append` writes none, so
a log written by the toolgate binary keeps its exact bytes and head and is
extended in place. Each event type has a typed payload (`payloads.go`): its
json fields are the schema, a field without `omitempty` is required, and the
definition says which envelope fields the type needs (a check decision needs
subject, action and decision). `OpenWith(..., Options{Schemas: Default()})`
refuses a record that does not match before anything is written, and
`VerifyWith` checks every record of a log against the schemas as well as the
chain. authz and authn event types are prefixed with their track
(`authz.relationships_written`, `authn.login_succeeded`); the agents track
keeps toolgate's names (`tool_call`, `approval_decided`, …), and the old
binary's log and every record the gateway writes match them.

`authz serve` and `authz gateway` write to it when `GRANTD_AUDIT_LOG` or
`WICKET_AUDIT_LOG` names a file; it is opened with the default schemas, so
every record is checked before it is written. serve records
`authz.schema_written` (the schema's SHA-256 and size, never its text) and
`authz.relationships_written` (counts of touches, creates, deletes and
preconditions) with the zed token of the write. The actor is the API key's
`api_key:` ID, the first 8 hex characters of a domain-separated SHA-256 of
the key, so keys can be told apart without being recorded. The gateway
records each event it already logged with `"audit":true` (logins, login
failures and rejections, logouts, admin revocations, forward-auth denials,
config loads) as its typed `authn.` event, and keeps the log line as wicket
wrote it. The user's subject is the actor and `app:<id>`, `session:<id>` or
`host:<host>` is the subject. Values from outside, such as an identity
provider's subject, go through `audit.Clean`, so a control character or an
oversized name can't cause a record to be refused. The correlation ID is the
request's (see "One log handler"): the trace ID of its `traceparent`, or a
generated one, and not the `X-Request-Id`, which stays in the log lines.
The records `authz mcp` writes for a request (tool calls, approvals asked
and decided, quarantines, tool approvals) carry it too, in an envelope with
only that field, so their data and the recorded decisions are toolgate's;
policy loads happen outside any request and carry none. Both servers have already committed what a record describes,
so a failed append is counted (`grantd_audit_failures_total`,
`wicket_audit_failures_total`) and logged instead of failing the request.
After that, `/healthz` answers 503 until the process restarts, the way
`authz mcp`'s does.

Check decisions are the exception. With `GRANTD_AUDIT_CHECKS=true` (or
`audit_checks` in the serve section), every answered check, single or bulk,
is an `authz.check_decided` record: the resource as the subject, the
permission as the action, allow or deny, the principal and the zed token it
was checked at, and the item count for a bulk check. Nothing is committed
by a check, so the order is the other way round: the record is durable
before the answer is sent, and a check whose record cannot be written is
answered 503 `unavailable` rather than given unrecorded. A check that fails
(a bad request, an unknown permission in a bulk item) records nothing. It is
off by default because each check waits for an fsync, shared with every
other append under group commit; a bulk check's records are written with
`WriteAll`, which waits for one fsync for all of them.

`authz mcp` opens its log with the default schemas too, so a record the
gateway writes that does not match its agents schema is refused before it
reaches the file, as serve's and the gateway's are.

### One file, three writers

The three subcommands usually run as separate processes on one host, and
one chain means one file. Each `Log` therefore takes an exclusive `flock` on
the file around each write. Under the lock it compares the file's size with
the end of its own last record; if another writer has appended since, it
reads just those records, checks that they continue the chain from its own
head (sequence and `prev`), and moves its head past them before writing its
own. A torn final line found that way belongs to a writer that died
mid-write (its lock died with it) and is cut off, as `Open` does; anything
else that does not continue the chain, or a file that shrank, stops the
writer for good like a failed write, since it can no longer know where its
record belongs. `Open` takes the lock as well, so it never cuts off a line a
live writer is still writing. The lock is released before the fsync, so
group commit still covers every append, from this process or another,
written before it; `BenchmarkAppend` and `BenchmarkAppendParallel` read the
same with and without the lock (about 140 µs and 28 µs per append on the
4-core test machine, both bound by the fsync). `Head` reads the other
writers' records the same way first, so `/admin/audit/head` reports the
file's head and `authz mcp audit verify -head` holds for a shared file. Windows has no `flock` in the standard library,
so there a log keeps one writer.

### Segments

A log that only grows is hard to ship, keep or prune, so `Options.Rotation`
cuts it into segments once the active one reaches `MaxBytes` (the record
that reaches the limit is its last) or its first record is `MaxAge` old
(checked on the next append). The configured path is always the active
segment, the only file written to. An older segment is named for its first
record, `audit.jsonl.00000000000000001205`, padded to 20 digits so names
sort in chain order and every `uint64` fits. Each segment after the first
opens with an `audit.segment_started` record (track `audit`, action
`audit.rotate`): an ordinary link of the chain, its `prev` the hash of the
previous segment's last record, whose payload names that segment, its first
record and why it ended (`size`, `age` or `manual` for `Log.Rotate`). It is
only valid as a file's first line.

A rotation happens under the active file's lock, after reading what other
writers appended: fsync the active file; write the segment start record to
`audit.jsonl.next`, lock it and fsync it; hard-link `audit.jsonl` to its
segment name; rename `.next` over `audit.jsonl`; fsync the directory. The
path never stops naming a complete log, so a writer opening it at any
moment finds either the old file or the new one, and `Open` retries when the
file it locked is no longer the one the path names. A crash leaves at worst
a `.next` file or a segment name that is a second link to the active file;
`Open` removes both under the lock. A rotation that fails before its rename
(the segment name is taken, the directory is not writable) fails that
append and leaves the active segment as it was, so the next append tries
again; a failed fsync stops the log as it does anywhere else.

Writers sharing the file keep the old one open. Under the lock each append
compares the file it holds with the one the path names (one `stat`); when
they differ it reads the rest of the old segment, then opens the segment
that starts at its next record (the path's file, or, if that was rotated
again meanwhile, the segment named for that record), locks it and reads on
from its segment start record, which must continue its head; it repeats
until it holds the path's file. `TestFollowSeveralRotations` idles a writer
through three rotations, and `TestRotateWriterProcesses` has four processes
with different limits rotate one file. The rotating writer fsynced the old segment, records of the others
included, so their pending appends need no fsync of their own; the old
file is closed by the next group commit, which may still be fsyncing it.
Offsets for the group commit run on across segments. `BenchmarkAppendRotating`
(64 KiB segments, a rotation every few hundred records) costs about 33 µs
per append against 31 µs without rotation on the 4-core test machine.

`VerifyChain` checks a rotated log: each file's own chain, then the links
between them. The oldest segment must start at record 1, each later one
must be named for its first record, follow the previous one without a gap,
name it, and link to its last record, so a segment that was removed,
renamed, swapped, copied over another or edited at its end is named in the
error. `authz mcp audit verify` uses it whenever segments are present, and
for a never-rotated log prints exactly what toolgate printed. Rotation
needs `flock`, so it is refused on Windows.

`TestMainOneChain` (cmd/authz) runs it end to end as a deployment would:
serve, gateway and mcp as three processes of the binary with one
`*_AUDIT_LOG` file, a fake identity provider, and a proxy configured like
the nginx example in docs/proxies.md in front of an app. A traced browser
signs in through the gateway; the proxy's forward-auth subrequest carries
the browser's `traceparent`, the gateway's allowed answer hands one back,
and the app passes it on to the check it asks serve and to the tool call it
then makes through mcp, which passes it to the tool's server. The file must
pass `VerifyWith` with records from all three writers, and under the
browser's trace ID it must hold, in order, `authn.login_succeeded` (alice,
`app:docs`), `authz.check_decided` (`doc:readme` `view` allow for
`user:alice`) and the call's two `tool_call` records (alice's agent,
`read_file`, allowed by `files-read`). A sign-in spans several browser
requests, so in production the sign-in shares a trace ID with what follows
only when the client keeps one trace across them; otherwise the session ID
in `authn.login_succeeded` and the user in the later records tie them.
`TestSharedWriterProcesses` has four processes append 600 records at once
and requires one chain with each record once.

## One configuration file (internal/platform/config)

Every subcommand reads its part of one versioned JSON document. A section
is a Go struct registered with `config.NewSection(name, defaults, check)`;
`config.NewSchema` refuses a section type it cannot decode, or two members
that would share an environment variable, when the program starts rather
than on some document.

- *Every problem at once.* The document is walked token by token against
  the section types, as wicket's config check did: unknown members (with a
  "did you mean"), duplicates, wrong types and bad durations are reported
  and dropped, and the section checks still run over the rest. Each problem
  carries its JSON path and line and column, or the environment variable
  its value came from.
- *Versioned.* `"version"` is required. A version newer than the build's is
  refused instead of being half understood.
- *Precedence.* Defaults, then the file, then the environment. Each member
  outside arrays and maps has a variable, `AUTHZ_<SECTION>_<PATH>`; lists of
  strings are comma-separated; empty variables are ignored. A section given
  only by variables is present. Unknown `AUTHZ_<SECTION>_` variables are
  warnings.
- *Secrets.* A `config.Secret` member cannot hold a literal in the file. It
  is `{"file": path}` (at most 64 KiB, white space trimmed) or
  `{"env": name}`, or set by `AUTHZ_<...>` or `AUTHZ_<...>_FILE`; setting both
  is an error. `String`, `%v` and `%#v` print where it came from, never
  the value.
- *Live reload.* A `config.Watcher` holds the current `*Config` behind an
  atomic pointer. Every second (`DefaultInterval`) it reads the
  configuration file and every secret file the last load read, and compares
  SHA-256 sums, so a same-size rewrite within one mtime tick, a Kubernetes
  symlink swap and a file that appears or disappears are all seen. A change
  is loaded and checked in full and swapped in only if it has no errors.
  Otherwise the old configuration stays and `OnError` is called once for
  that version of the files. Readers call `Current()` per request and see
  one whole configuration or the next, never a mix: under a test that
  rewrites the files in place, out of order and with garbage while eight
  clients hammer an HTTP handler, no request fails and no client sees a
  generation go backwards.

### The sections

Each subcommand defines its section next to the code that runs it
(`serve.Section`, `gateway.Section`, `mcp.Section`), and `checkcmd.Schema`
puts the three together for `authz check -config`.

- *serve* holds the `GRANTD_*` settings by their `AUTHZ_SERVE_*` names:
  `addr`, `data_dir`, `api_keys` and `token_key` (secrets), `cache_size`,
  `retention`, `log_level`, `audit_log`, `key_rate` (a number, so the
  platform reads `float64` members), `key_burst`, and the `GRANTD_TLS_*`
  and `GRANTD_DRAIN_*` settings as `tls_cert`, `tls_key`, `tls_client_ca`,
  `drain_delay` and `drain_timeout`. Its checks are the ones
  `authz check -serve` applies to the environment.
- *mcp* holds the `TOOLGATE_*` settings by their `AUTHZ_MCP_*` names, which
  are already the gateway's second spelling of each variable, so
  `AUTHZ_MCP_ADDR` means the same thing whether or not a file is used.
  `admin_token`, `audit_key` and `signing_keys` are secrets. The check reads
  the agents config and the policy the section names, as the gateway does
  when it starts, and builds the authenticator from the config and the
  signing keys.
- *gateway* holds the `WICKET_*` settings (`cookie_keys` and `admin_token`
  are secrets) and, inline, every member of a wicket file, so a wicket file
  moves into the section unchanged. The wicket members are written back out
  as a wicket document and checked by `check.Bytes`, the code behind
  `authz gateway check`, offline or with `-online`; its paths are moved
  under `$.gateway`, and the platform locates them in the file. A test keeps
  the section's members in step with `config.Config`.

### Starting from the file

`authz serve -config file` (or `AUTHZ_CONFIG=file`) starts from the serve
section; without either, the `GRANTD_*` variables work exactly as before,
and with a file they are ignored, with a warning naming them. The section
starts the server with exactly the configuration the same values as
`GRANTD_*` variables give (a test compares the two).

Each subcommand reads one section of a file that may hold all three.
`config.Skip(name)` lists the others: they are read past whatever they
hold, so a problem in the gateway's section does not stop `authz serve`, but
a misspelt section name is still an error. `WatchOptions.Validate` refuses a
version of the file with no serve section, as a problem in it would be.

While serving, a `config.Watcher` polls the file and the secret files it
names every second. `api_keys` applies at once: `api.Server.SetAPIKeys`
swaps the accepted keys behind an atomic pointer, so a request is checked
against one whole key list, and a key kept across the change keeps its rate
limit bucket. `log_level` applies at once through a `slog.LevelVar`; the
reload is logged at the more verbose of the two levels so a change to a
quieter one is still seen. The other members are logged as applying on
restart. An invalid version (a short key, broken JSON, no serve section) is
logged and refused, and the running configuration is kept. Under eight
clients using a key that every version holds, while the key file is
replaced, rewritten in place and the configuration broken and fixed, no
request fails (about 60,000 requests in the test), and a key file change
applies about a second after it is written.

`authz gateway -config file` (or `AUTHZ_CONFIG=file`) starts the sign-on
gateway from the gateway section the same way, with serve and mcp skipped;
without either, the `WICKET_*` variables and the wicket file `WICKET_CONFIG`
names work exactly as before, and with a file they are ignored, with a
warning naming them. The section gains `tls_cert`, `tls_key`,
`tls_client_ca`, `drain_delay` and `drain_timeout` for the `WICKET_TLS_*`
and `WICKET_DRAIN_*` variables, so every variable `authz gateway -h`
documents has a member (a test reads the help to keep it so), and a test
compares the settings the section starts with to those the same values as
variables give.

The gateway's reload has two halves:

- `cookie_keys` and `log_level` apply inside the watcher's poll.
  `seal.Keyring.Rotate` swaps the key list behind an atomic pointer, so a
  cookie is sealed or opened with one whole list; the ring the handlers
  hold stays the same object. A key listed twice is refused by the ring
  and so by the watcher.
- The wicket members (`public_url`, `session`, `providers`, `apps` and the
  rest) are rebuilt by `server.Reload`, the code SIGHUP and
  `POST /admin/reload` already ran: the poll wakes the serve loop, which
  calls it, and the server's `Load` returns the section the watcher holds,
  written out as a wicket document. SIGHUP and `POST /admin/reload` poll
  the files first, so they pick up a change at once and report a refused
  one; a change such a reload finds is built once, not again by the serve
  loop. Files the wicket members name (`client_secret_file`, `ca_file`, SAML
  metadata and keys) are read on every rebuild, as before.

The reload is logged with the members applied (`cookie_keys`,
`log_level` and each wicket member that changed) and those that wait for a
restart: the listeners, `admin_token`, `session_file`, `signing_keys`,
`trusted_proxies`, `login_rate`, `audit_log`, TLS and drain. Under eight
clients sending forward-auth requests with a cookie sealed by a key every
version lists, while the keys rotate, an app changes and the key file and
the document are broken and fixed, no request fails (about 74,000 requests
in the test), and a key or app change applies within about a second.

`authz mcp serve -config file` (or `AUTHZ_CONFIG=file`) starts the MCP
gateway from the mcp section the same way, with serve and gateway skipped.
Without either, the `TOOLGATE_*` variables and their `AUTHZ_MCP_*` names
work exactly as before. With a file the `TOOLGATE_*` names are ignored, with
a warning naming them, and are not merged with the `AUTHZ_MCP_*` names,
which override the section's members; so two spellings that disagree are
no longer a start-up error. A test compares the configuration a section
starts with to the one the same values as variables give.

The mcp section names two files that are not secrets but change as often:
the agents config and the policy. Its check reads them with
`Checker.ReadFile`, which makes each one a source of the configuration, so
the watcher loads and checks the whole section again when either changes,
as it does for a secret file. The check keeps what it built (the parsed
agents config and the authenticator for it and the signing keys) in
unexported members of the section, so the gateway starts and reloads from
exactly what was checked, not from a second read. A reload applies:

- the agents, the token settings and the limits of the agents config, and
  `signing_keys`, through `gateway.SetAgents`, which swaps the
  authenticator and the limits behind one atomic pointer. Each request
  reads it once; rate-limit buckets and daily quotas are kept per agent,
  so an agent that stays keeps what it has used. A token signed by a key
  that was removed stops verifying.
- the policy, through `policy.Store.Poll`, the unforced read one tick of
  the store's own watch makes: a version the store has already applied or
  rejected is not reported twice, so the store's `policy_poll` and the
  configuration watcher can both look at the file. A broken policy is
  refused by the watcher, and the store rejects it too, with its log line,
  metric and `policy_rejected` audit record.
- `log_level`, as serve does.

The upstreams and approval settings of the agents config, the listeners,
`admin_token`, the policy path, `audit_log`, `audit_key`, `state_dir`,
`allowed_origins`, `policy_poll`, TLS and drain are logged as applying on
restart. SIGHUP polls the files first, then reloads the policy as it always
has. Under eight clients calling a tool as an agent that every version
keeps, while agents are added and removed, signing keys rotate, the policy
changes, and the agents config, the policy and the file are rewritten in
place or broken, no call fails (about 5,000 audited calls in the test), and
an agent, key or policy change applies about a second after it is written.

## One log handler (internal/platform/logging)

Every subcommand logs JSON lines through log/slog. `internal/platform/logging`
(week 2, #78) is the one handler they move to. It wraps slog's JSON handler
and adds three attributes at the top level of every record, outside any
group the logger opened:

- `subcommand`: set once when the handler is built (`serve`, `gateway`, `mcp`).
- `correlation_id`: taken from the request context. `Middleware` sets it to
  the trace ID of the request's W3C `traceparent` when that header is valid,
  or to a new random trace ID when it isn't. The same value goes into the
  audit envelope's `correlation_id`, and `Traceparent(id)` carries it to an
  upstream with a fresh parent ID. So a log line, its audit record and the
  upstream call share one ID.
- `tenant`: taken from the context, or the handler's default. The default
  tenant adds nothing.

serve, gateway and mcp log through it (week 2, #78). Each request wrapper
calls `logging.Correlate` before anything else, so the request line, every
line logged with the request's context and the audit record share the ID.
`authz mcp` sends it to its upstreams with `logging.Propagate`, which sets a
`traceparent` with the same trace ID and a new parent ID on every MCP request
made under the call's context. The gateway returns one on an allowed
forward-auth answer when the proxy sent one, for the proxy to copy upstream
(docs/proxies.md, "Correlation IDs and `traceparent`"); without one its
answers stay as wicket's golden transcripts recorded them. None of the three
sets `subcommand` yet: serve's golden replay compares its start and stop
lines byte for byte. `TestMainCorrelationAcrossSubcommands` runs the three as
the binary does, with and without a `traceparent`, and requires the same ID
on the request line, in the audit record and, for mcp, on the upstream's
`traceparent`.

A key that the logger or the record already sets at the top level is not
added again. If the handler has none of these values, it writes exactly the
bytes slog's JSON handler writes. Moving a subcommand to it therefore changes
no log line until the subcommand asks for one of the attributes.

The level is an `slog.Leveler`, normally an `*slog.LevelVar`. It can be
changed while the process runs in three ways:

- `SetLevel` changes it directly.
- `ReloadLevel` re-reads it each time a channel fires, such as on SIGHUP or a
  config reload.
- `LevelHandler` serves GET and PUT `{"level":"debug"}` for an admin API.

Each change is logged at the higher of the old and new levels, so it shows
whichever way the level moved.

Secrets are redacted before encoding, at any depth:

- a value of type `logging.Secret`, which `fmt` and `encoding/json` also print
  as `[REDACTED]`;
- an attribute whose key names a secret. The key is matched after
  lowercasing it and turning `-` into `_`. It matches `password`, `token`,
  `authorization`, `cookie`, `client_secret`, the OAuth token names, and any
  key ending in `_token`, `_secret`, `_password` or `_api_key`. The list can
  be extended per handler, and empty values are kept;
- a struct field tagged `log:"secret"`. A struct holding one is written as a
  group named the way encoding/json names its fields, with that field
  redacted. A slice or map of such structs is redacted whole. Types that
  render themselves (`error`, `json.Marshaler`) are left to their author.

On the request line every subcommand writes (five attributes), slog's JSON
handler takes about 1.1 µs and no allocations on a 4-core 2.1 GHz Xeon. This
handler takes about 1.7 µs and no allocations with a subcommand and no
context values. With a correlation ID and tenant it takes about 2.5 µs and
2 allocations, because the record is rebuilt and never appended to. A
disabled level costs 22 ns.

### Secret scan

Redaction only covers the values someone thought to mark. The secret scan
(week 2, #78) checks the output instead: `logging.Scanner` looks for the
shapes credentials take, and every test suite runs under it.

The rules, each named in a finding:

- `jwt`: a compact JWS or JWE whose header decodes to JSON with `alg` or `enc`.
- `private_key`: a PEM private key block.
- `jwk_private`: a JWK's private members (`d`, `p`, `q`, ..., `k`) next to a `kty`.
- `auth_header`: `Bearer` credentials that look like a token (16 bytes or
  more with a digit, or 24 or more, so SAML's "bearer confirmation" is not
  one), and `Basic` credentials that decode to `user:password`.
- `credential_param`: `password=`, `client_secret=`, `access_token=` and the
  other credential names in a query string, form body or logfmt line.
- `credential_field`: a JSON string member whose key the handler would
  redact (the same key rules), unless its value is empty or `[REDACTED]`.
- `url_password`: `scheme://user:password@host`.
- `provider_key`: well-known provider key formats (GitHub, Slack, Stripe,
  Google and model provider keys).
- `known`: a value the test registered (`Known`), raw or base64, base64url,
  hex, URL- or JSON-escaped.

A finding reports the line, the rule and the first four bytes of a value of
12 bytes or more with its length; a registered value is shown by its length
only. A report never carries the secret. Scanning a 230-byte request line
takes about 2 µs: each rule first checks for a substring it needs, and the
two broadest (parameters and JSON members) are hand-written scanners, not
regular expressions.

The scan sees output in three ways:

- **A process tap.** The handler writes through a writer that hands every
  record, after redaction, to the functions registered with `logging.Watch`.
  `internal/platform/audit` hands over every record it appends, under its
  lock, so in chain order. With nothing registered this costs one atomic load
  (about 2 ns, no allocations); no server registers anything.
- **`logtest.Check(t)`**, the test hook. It watches the tap while the test
  runs. `Writer` wraps a logger's writer that does not go through the
  handler, `File` scans an audit file when the test ends, and `Known` adds
  the test's own client secrets, cookie keys and API keys. Any finding fails
  the test. The audit tests of the gateway, the authorization API and both
  subcommands use it.
- **The CI step "Secret scan"** runs every suite again built with
  `-tags secretscan`. In that build, `logging` registers a watcher at start
  that prints each finding to stderr as a `SECRET-SCAN:` line.
  `scripts/secret-scan.go` reads `go test -json` and fails the test that
  printed one, and it also scans all test output itself (`t.Log`, and
  whatever the code under test writes to stdout and stderr). Findings that
  are the point of a test are listed in `scripts/secretscan-allow.txt` as
  package, test and rule; an entry that matches nothing fails the step. The
  only entries are logtest's own tests, which leak on purpose.

Today the tap covers what goes through the platform handler and the audit
log. serve, gateway and mcp still log through their own slog handlers; once
they move to the platform handler, their log lines come under the CI scan
without any change to their tests.

## One metrics registry (internal/platform/metrics)

grantd, wicket and toolgate each carried a copy of the same small registry
(`internal/metrics`, `internal/authn/metrics`, `internal/agents/metrics`, all
byte-identical). In week 2 (#77) they became `internal/platform/metrics`, and
`authz serve`, `authz gateway`, `authz mcp` and `authz mcpfake` all use it.

**The exposition is unchanged.** Counters come first, then gauges, then
histograms, each in series order, with one `# HELP` and `# TYPE` per family.
`testdata/tracks.golden` registers every family the three tracks use, with
their label sets and help texts, and was recorded with the old package before
it was removed; the new registry writes the same bytes. A second test scans
the tracks' sources for every `Counter`, `Histogram`, `Gauge` and `count`
call and checks the golden file holds exactly those names, so a metric added
to a track without updating the golden file fails the build. The serve golden
transcript's `# TYPE` lines and the old `TestExposition` pass unchanged.

What the registry adds:

- **Settable gauges** (`GaugeSeries`, with labels) next to the scrape-time
  function gauges, and **histograms with their own buckets**
  (`HistogramBuckets`). Every series of a family shares one bucket layout.
- **Series caps.** Each family may hold `DefaultLimit` (2,000) label sets,
  or what `Limit` or `LimitFamily` sets. A label set past the cap is folded
  into the family's `{overflow="true"}` series, so counts are kept, and
  `authz_metrics_overflow_total{metric="NAME"}` counts the folded lookups.
  That family appears only once something has overflowed. Label values that
  come from outside, such as an upstream's tool names, can no longer grow
  memory without bound.
- **Checks at registration.** A family registered under two types, an
  invalid metric or label name, a malformed label set, a repeated label, `le`
  on a histogram or two bucket layouts for one family panic when the series is
  created. These are programming errors and tests hit them. `Labels(k, v,
  ...)` escapes values the way the exposition format requires (`\\`, `\"`,
  `\n`, invalid UTF-8 replaced); toolgate's upstream, tool, outcome, event,
  server and route labels are built with it. For printable values it gives
  the same text as the `%q` it replaced.
- **No lock held during gauge functions.** `Write` snapshots the series
  under a read lock, releases it and then calls the gauge functions, so a
  function may read or create other metrics.

Lookups take a read lock, and only a new series takes the write lock. On a
4-core 2.1 GHz Xeon, under `RunParallel`, finding and incrementing a counter
by name and labels takes about 124 ns (the old registry took about 180 ns,
behind one mutex), and a histogram observation takes about 110 ns either way.
Writing 530 series takes about 0.39 ms, the same as before within noise.

Three old test files merging into one is something git's rename detection
can't express, so `scripts/testbody-merge.txt` pairs each of them with
`internal/platform/metrics/metrics_test.go`. The test-body check compares
each one with it in full. The suite-count steps map both old package paths
to the new one.

## One rate limiter (internal/platform/ratelimit)

The gateway's per-agent and per-tool buckets, the sign-on gateway's
per-client login limit and `authz serve`'s per-key limit are one GCRA
limiter (week 2, #78). Each key stores only its theoretical arrival time
(TAT) as an int64 of nanoseconds; with interval T = 1/rate and tolerance
τ = T·(burst−1), a take at t is admitted when max(TAT, t) − t ≤ τ and moves
TAT on by T. That is an exact token bucket with no floating-point refill.
`TakeN` takes several tokens at once or none.

- Keys come from `ratelimit.Key(dims...)`, which writes each dimension as its
  length, a colon and its bytes. ("agent", "a", "tool") can never meet
  ("agent", "a\x00tool"), as the gateway's old NUL-joined keys could have.
- Time is measured from the limiter's creation, on Go's monotonic clock, so a
  wall-clock step neither drains nor refills a bucket. An injected clock is
  clamped to the latest time seen: wicket's limiter guarded against a step
  back draining a bucket, toolgate's against one minting tokens, and both
  tests pass against the one limiter.
- Memory is bounded by `MaxKeys` (100,000 by default). A key whose TAT has
  passed is a full bucket and is dropped by a sweep, which runs whenever the
  table has doubled since the last one and on `Sweep`. When the table is
  still full of live keys, the half with the earliest TAT, the ones closest
  to full, is forgotten; a forgotten key starts again full, so those keys
  lose the least. `Evicted` counts them.
- `Set` and `Tokens` restore and read a bucket as tokens at a time, for
  handing state over.

toolgate's limiter tests run unchanged against it. wicket's three limiter
tests read the old bucket map directly; ten lines now read the limiter
through `Len`, `Set` and `Tokens` instead, with the same assertions, listed in
scripts/testbody-allow.txt. A take on a held key costs about 95 ns with no
allocations on a 4-core 2.1 GHz Xeon (190 ns across 4 goroutines on one
mutex), and inserting new keys into a full table, sweeps and evictions
included, about 470 ns.

## One clock (internal/platform/clock)

Code that reads the time or waits on it takes a `clock.Clock` (week 2,
#76): `Now`, `Since`, `NewTimer`, `AfterFunc` and `NewTicker`.
`clock.Real()` is the wall clock and measures durations on Go's monotonic
clock; `clock.Or(c)` turns an optional `Clock` field into the wall clock
when it is nil. It replaced jonboulle/clockwork, which wicket used for one
call into goxmldsig.

`clock.Fake` only moves when a test calls `Advance` or `Set`, and never
backwards. Timers, tickers and `AfterFunc` calls come due in deadline order
as it moves, ties in creation order, with `Now` reading each deadline as it
fires, so one `Advance(time.Hour)` over a ten-second ticker sees each tick
at its own instant. Channels hold one value and drop the rest, as
`time.Ticker` does, and `Stop` and `Reset` drain them, as Go's timers have
since 1.23. `AfterFunc` functions that come due run on the goroutine
calling `Advance`, before it returns, so a test that advances the clock
knows their effects are in place. `BlockUntil(ctx, n)` waits until n timers
are pending: a test starts a goroutine, waits for its ticker, then advances,
without a sleep.

The key rotation scheduler (`keys.Scheduler.Clock`) and the configuration
watcher (`config.WatchOptions.Clock`) run on it; their tests step through
rotation periods and reload intervals one tick at a time. Packages that
took a `now func() time.Time` before week 2 keep it; a `Clock`'s `Now`
method value fits it.

## One HTTP server (internal/platform/httpserver)

`authz serve`, `authz gateway` and `authz mcp` each built their own
`http.Server`, with their own timeouts and their own shutdown. Since week 2
(#77) each describes its listeners as `httpserver.Spec`s, and one
`httpserver.Group` binds them, serves them and drains them together.

- **Limits.** Every listener gets the same defaults: 5 s to read the
  headers, 15 s to read the request, 30 s to write the response, 120 s idle
  and 16 KiB of headers. A listener overrides only what it must, and the
  overrides are the values each subcommand already had: `authz serve`
  writes for the longest watch poll plus 15 s, the sign-on gateway's public
  listener allows 45 s and 32 KiB of headers (large cookies), and the agent
  gateway allows 6 minutes, the worst case for one tool call at the
  configuration maximums.
- **TLS.** `<PREFIX>TLS_CERT` and `<PREFIX>TLS_KEY` (`GRANTD_`, `WICKET_`,
  `TOOLGATE_` or `AUTHZ_MCP_`) serve every listener of the subcommand over
  TLS 1.2 or later with Go's default cipher suites and key exchanges (only
  forward-secret AEAD suites; the hybrid post-quantum group first) and
  HTTP/2. The files are checked for a renewal at most every 10 s during
  handshakes and reloaded when their modification times change, so a
  renewed certificate needs no restart; a renewal that fails to load (a new
  certificate with the old key, half-way through a rotation) keeps the
  certificate in use until both files match. `<PREFIX>TLS_CLIENT_CA`
  requires client certificates signed by those CAs. Without the variables
  the listeners serve plain HTTP, as before.
- **Readiness.** A Spec may name a readiness path. `authz serve` keeps its
  own `/readyz`, which reports the log's health; the two gateways get
  `/readyz` on their admin listeners. Once shutdown begins the group
  answers that path with 503 `{"status":"draining"}` itself.
- **Bounded drain.** On SIGINT or SIGTERM the group flips readiness and
  turns keep-alives off, so each client's next request opens a new
  connection a load balancer can route elsewhere. For `<PREFIX>DRAIN_DELAY`
  (default 0) the listeners keep accepting, so requests sent before the load
  balancer saw the probe still land. Then the listeners close and in-flight
  requests finish, for at most `<PREFIX>DRAIN_TIMEOUT` (default 20 s, the
  bound every subcommand had). Requests still running at the bound have
  their connections closed, and the subcommand exits 1 saying how many.
- **One failure stops the group.** If any listener fails, the others close
  and the subcommand exits with that error, as each subcommand did.

The startup and shutdown log lines are unchanged, so the golden replays of
all three subcommands still match byte for byte. The package's tests cover
the limits (431 for oversized headers, a slow client cut at the header
timeout), the probe before and during a drain, a request in flight across
the drain, the bound, a listener failing during the delay, certificate
renewal and a failed renewal, and mutual TLS; each subcommand has a test
that serves over TLS, sees `/readyz` turn 503 on shutdown and stops cleanly.

### Several subcommands in one process (authz run)

`authz run` starts `authz serve`, `authz gateway` and `authz mcp serve` in
one process (#77). The subcommands' startup code is the same code that runs
alone; what changes is what each takes from its process, a `part.Host`:

- **One listener group.** `httpserver.Shared` is one Group that several
  parts join. Each part binds through `Shared.Part(i)`, a `Binder` with the
  same signature as `httpserver.Bind`, and waits there until every part has
  joined; the last one to join binds every listener in one `Listen`, in
  part order whatever order they joined in, so either all five listeners
  (the API, the gateway's public and admin listeners, the agent and admin
  listeners of mcp) are bound or none is. The process then calls
  `Shared.Serve` once: one readiness flip, one drain delay and one drain
  bound for every listener. Each part's `Serve` returns when that drain is
  over, so a part closes its store, session log or approval log only after
  the last request that could write to it has been answered.
- **One metrics registry.** Every part writes to the same
  `metrics.Registry`, so `/metrics` on the API, on the gateway's admin
  listener and on mcp's admin listener all answer with the union of the
  three tracks' families. The family names never collided: each track's
  metrics carry its own prefix (`grantd_`, `wicket_`, `toolgate_`), and
  `internal/platform/metrics/testdata/tracks.golden` holds the union.
- **One log output.** Every line carries `subcommand` (`serve`, `gateway`,
  `mcp`, or `run` for the process's own `running` and `stopped` lines).
  Alone, a subcommand adds nothing, so its lines and the golden replays are
  unchanged.
- **Settings set once.** TLS and draining are per process, from
  `AUTHZ_TLS_*` and `AUTHZ_DRAIN_*`. A part's own setting (`GRANTD_TLS_CERT`,
  a section's `tls_cert`, `WICKET_DRAIN_DELAY`) is refused, by the command
  for the variables and by `Shared` for anything else, rather than ignored:
  ignoring a TLS setting would serve plain HTTP where TLS was asked for.
- **Failure.** A part that cannot start aborts the group: the parts waiting
  to join fail with `ErrAborted`, nothing is bound, and the command prints
  the one error that caused it. A part that stops after binding ends the
  process context, which drains the others as SIGTERM does.

SIGHUP goes to the gateway, which reloads its configuration, and to mcp,
which reloads its policy.

`TestRunSurvivesSIGKILLMidWrite` (cmd/authz) holds the shared process to
the crash guarantees each part has alone. Four times, while all three parts
are writing (relationship writes to `grantd.wal`, SAML sign-ins to the
session log, approval decisions to `approvals.wal`), the process is killed
with SIGKILL once every part has acknowledged writes in that round, and
restarted on the same files. After every restart each relationship serve
answered 200 for is checked allowed at a fully consistent snapshot, each
session cookie the gateway set still passes forward-auth, each approval and
denial mcp acknowledged is still decided that way, and each request left
undecided is still pending. The MCP audit chain verifies at the end. Run
with the session file removed, the test fails on the first lost session.
