# Changelog

Changes that operators and users can see, newest first. Each week's entries
link the roadmap issue they come from.

## Unreleased

### Authorization (authz)

- **One module and one binary** ([#74](https://github.com/laiwf94/authz/issues/74)).
  The module is `github.com/laiwf94/authz` (it was `github.com/laiwf94/grantd`),
  and wicket's and toolgate's modules are folded into it. `authz` is the one
  binary, with a subcommand per part: `serve`, `check`, `ctl`, `gateway`,
  `mcp` and `version` (`authz help` lists them). Each subcommand has its own
  `-h`, and a usage error exits 2.
- **grantd is now `authz serve`.** Its packages live at `internal/authz/*`.
  The `GRANTD_*` variables, the data directory and its `grantd.wal`, issued
  consistency tokens, endpoints, headers, error codes and messages, `grantd_*`
  metric names and log lines are unchanged, so an existing deployment
  upgrades in place. The one difference is that `authz serve` rejects
  command-line arguments (exit 2) where grantd ignored them.
- `authz check [-serve] [-schema file] [-relationships file]` validates the
  serve environment, a schema file and a relationships file against that
  schema, and reports every problem with `file:line:col`.
- `authz ctl` is a client for a running server: `schema read|write`,
  `rel touch|create|delete|read`, `check` (exits 3 when denied) and
  `lookup`, with the key in `AUTHZ_API_KEY` and the address in `AUTHZ_URL`.
- `authz version [-json]` prints the stamped version, or the module and VCS
  build information.
- The image is built from base images pinned by digest, runs as nonroot,
  has a `/data` directory for `GRANTD_DATA_DIR`, and takes
  `--build-arg VERSION=`. It is 15.19 MB uncompressed (5.68 MB compressed),
  and CI fails above 25 MB (`bench/image-baseline.json`).
- One CI workflow for the whole module: build, gofmt, vet, staticcheck,
  race tests with a 93.5% coverage floor, every fuzz target, the test-body
  and test-count checks of the move, govulncheck, and a golden replay of
  grantd's recorded end-to-end transcript and README demo through
  `authz serve`, including a restart on a data directory grantd wrote.
- **One HTTP server setup for every subcommand**
  ([#77](https://github.com/laiwf94/authz/issues/77)). `authz serve`,
  `authz gateway` and `authz mcp` share listener setup, timeouts, header
  limits and shutdown. New optional variables, under each subcommand's
  prefix (`GRANTD_`, `WICKET_`, `TOOLGATE_`/`AUTHZ_MCP_`): `TLS_CERT` and
  `TLS_KEY` serve TLS 1.2+ and HTTP/2 with certificate renewal picked up
  without a restart, `TLS_CLIENT_CA` requires client certificates,
  `DRAIN_DELAY` keeps accepting after SIGTERM while `/readyz` answers 503,
  and `DRAIN_TIMEOUT` (default 20s) bounds the drain. Both gateways now
  answer `/readyz` on their admin listener.
- **`authz run`: serve, gateway and mcp in one process**
  ([#77](https://github.com/laiwf94/authz/issues/77)). Each part reads the
  configuration its own subcommand reads. They share one listener group
  (bound all or none, one readiness flip and one drain on SIGTERM) and one
  metrics registry (`/metrics` on any part shows all three tracks'
  metrics), and each log line has a `subcommand` attribute. TLS and drain
  settings come from `AUTHZ_TLS_CERT`, `AUTHZ_TLS_KEY`, `AUTHZ_TLS_CLIENT_CA`,
  `AUTHZ_DRAIN_DELAY` and `AUTHZ_DRAIN_TIMEOUT`; a part's own TLS or drain
  setting is refused (exit 2). `-parts` runs a subset. A part that cannot
  start stops the others before anything is bound (exit 1). Killed with
  SIGKILL while all three parts write and restarted, no acknowledged
  relationship, session or approval decision is lost.

### Sign-on (authn)

- **wicket is now `authz gateway`** ([#73](https://github.com/laiwf94/authz/issues/73)).
  The wicket packages live at `internal/authn/*` in the root module, and
  `cmd/wicket` and `cmd/fakeidp` are the `authz gateway` and `authz fakeidp`
  subcommands. The config file, the `WICKET_*` variables, the endpoints, the
  `__Host-wicket` cookies, the session file, the logs, SIGHUP reload and the
  exit codes are unchanged, so existing sessions survive the upgrade.
- Both images ship `/wicket` as a link to `/authz`. Run under that name, the
  binary is `authz gateway`, so `wicket check`, `wicket genkey` and a
  `/wicket` entrypoint keep working. The gateway image's entrypoint is
  `/authz gateway`.
- `authz gateway -h` prints the full environment reference.
- `authz fakeidp`: an undefined flag now exits 2 instead of 1, like every
  other subcommand.
- Proxy configurations and a "Moving from wicket" guide are in
  [docs/proxies.md](docs/proxies.md).
- CI holds the move to the old behaviour: golden transcripts of every
  end-to-end response, recorded from wicket before the move, are replayed
  through `authz gateway` started from a wicket config file; every wicket
  test, subtest and fuzz seed must still pass (338 cases); moved test files
  may change only their imports and package clause; and the nginx demo runs
  through the new binary.
- **Consistency token keys rotate** ([#76](https://github.com/laiwf94/authz/issues/76)).
  `GRANTD_TOKEN_KEY` takes a comma-separated list, newest first: the first
  key signs new tokens and the rest still verify, so a restart with a new key
  in front keeps every outstanding token valid until its key leaves the list.
  The token format and a single key's tokens are unchanged. The keys sit on
  an HS256 ring from `internal/platform/keys`, and pooled HMAC states make
  issuing and verifying a token about twice as fast (Encode 790 to 330 ns,
  Decode 730 to 310 ns, 9 and 7 allocations down to 4 and 2).
- **`authz serve` rotates its consistency token keys on its own** ([#76](https://github.com/laiwf94/authz/issues/76)).
  `keys_file` in the serve section (or `GRANTD_KEYS_FILE`) names the
  process's key ring file, in place of `token_key`. Tokens are MACed from its
  `consistency` ring, which is created when the file lacks it, rotates every
  `token_rotate_every` (default 24h, `GRANTD_TOKEN_ROTATE_EVERY`) and keeps
  retired keys verifying for `token_overlap` (default 168h,
  `GRANTD_TOKEN_OVERLAP`). The file is saved, mode 0600, after every
  rotation, so a restart keeps verifying the tokens issued before it. A
  file that changed under the process (another process using it) is not
  overwritten: the failure is logged and the running keys are kept.
  `authz check` checks the file and the policy. Under `authz run`, parts
  naming the same file share its rings. `token_key` and `GRANTD_TOKEN_KEY`
  work as before; setting both is an error.
- **Cookie keys and agent token keys can sit on key rings** ([#76](https://github.com/laiwf94/authz/issues/76)).
  `seal.FromRing` seals with an A256GCM ring's current key and opens with its
  next key and its retired keys inside their overlap; `identity.Config.Ring`
  does the same for HS256 agent tokens. A cookie key or a `kid=` signing key
  moved from its list onto a ring keeps its id, so values and tokens issued
  before the move still open and verify. A test rotates the session,
  upstream, consistency and agent rings every second under load, with a
  replica reloading the ring file and refusing broken versions of it, and no
  credential younger than the overlap is ever refused. The subcommands still
  read their key lists; they move onto rings in a later task.
- **One configuration file schema** ([#76](https://github.com/laiwf94/authz/issues/76)).
  `internal/platform/config` reads a versioned JSON document
  (`{"version": 1, "serve": {...}, "gateway": {...}, "mcp": {...}}`) with a
  section per subcommand. Every problem is reported at once with its JSON
  path and line and column; a document for a newer version is refused.
  Any member outside arrays and maps can be overridden from the environment
  (`$.serve.addr` is `AUTHZ_SERVE_ADDR`), and misspelt variables are warned
  about. Secrets are never written in the file: they are `{"file": ...}` or
  `{"env": ...}` references, or `AUTHZ_..._FILE` variables. A watcher
  reloads the file and every secret file it references within a second of
  a change, refuses an invalid version and keeps the configuration it has.
- **`authz check -config file [-online] [-timeout 10s]`** ([#76](https://github.com/laiwf94/authz/issues/76))
  validates the serve, gateway and mcp sections of that document, with the
  `AUTHZ_*` overrides and the secrets it references, and prints every
  problem as `file:line:col: severity: path: message` (or
  `VARIABLE: severity: path: message` for an override). The serve and mcp
  sections hold the `GRANTD_*` and `TOOLGATE_*` settings under their
  `AUTHZ_SERVE_*` and `AUTHZ_MCP_*` names; the `AUTHZ_MCP_*` variables the
  MCP gateway already reads are the same overrides. The gateway section holds
  the `WICKET_*` settings and, inline, the members of a wicket file
  (`public_url`, `session`, `providers`, `apps`…), checked by wicket's own
  rules, and `-online` runs `authz gateway check -online`'s metadata checks
  with paths under `$.gateway`.
- **`authz serve -config file`** ([#76](https://github.com/laiwf94/authz/issues/76)),
  or `AUTHZ_CONFIG=file`, starts the server from the serve section, which
  gains `key_rate`, `key_burst` and the TLS and drain settings. The file
  may hold the gateway and mcp sections too; serve reads past them. The file and the secret files it
  names are watched: a change to `api_keys` or `log_level` applies within
  about a second with no failed requests, an invalid change is logged and
  refused, and other members are logged as applying on restart. Without a
  file the `GRANTD_*` variables work as before; with one they are ignored,
  and the log names them.
- **`authz gateway -config file`** ([#76](https://github.com/laiwf94/authz/issues/76)),
  or `AUTHZ_CONFIG=file`, starts the sign-on gateway from the gateway
  section, which gains the TLS and drain settings, with the serve and mcp
  sections skipped. While it runs, a change to `cookie_keys` (new key first
  to rotate, then drop the old one) or `log_level` applies within about a
  second, providers, apps and the other wicket members are rebuilt, and
  SIGHUP or `POST /admin/reload` read the file at once. An invalid change
  is logged and refused with no failed requests; members such as the
  listeners and signing keys are logged as applying on restart. Without a
  file the `WICKET_*` variables and wicket files work as before; with one
  they are ignored, and the log names them.
- **`authz mcp serve -config file`** ([#76](https://github.com/laiwf94/authz/issues/76)),
  or `AUTHZ_CONFIG=file`, starts the MCP gateway from the mcp section, with
  the serve and gateway sections skipped. The file, its secret files, the
  agents config and the policy are watched: changes to the agents, token
  settings and limits in the agents config, to `signing_keys` (a token from
  a removed key stops verifying), to the policy and to `log_level` apply
  within about a second with no failed requests, and SIGHUP reads them at
  once. An invalid change, a broken policy included, is logged and refused
  and the running configuration kept; upstreams, approvals, the listeners
  and the other members are logged as applying on restart. Without a file
  the `TOOLGATE_*` and `AUTHZ_MCP_*` variables work as before; with one the
  `TOOLGATE_*` names are ignored, the log names them, and the `AUTHZ_MCP_*`
  names override the section's members.
- `config.Checker.ReadFile`: a file a section's check reads (the mcp
  section's agents config and policy) becomes one of the configuration's
  watched sources.
- **`authz gateway` rotates its cookie and upstream signing keys on its own** ([#76](https://github.com/laiwf94/authz/issues/76)).
  `keys_file` in the gateway section (or `WICKET_KEYS_FILE`) names the
  process's key ring file. Cookies are sealed from its A256GCM `session`
  ring (`cookie_rotate_every`, default 24h; `cookie_overlap`, default 48h)
  and upstream tokens signed from its ES256 `upstream` ring
  (`signing_rotate_every` and `signing_overlap`, both 24h by default; the
  `WICKET_COOKIE_*` and `WICKET_SIGNING_*` variables set the same).
  `/.well-known/jwks.json` publishes the next signing key a period before it
  signs and retired keys until their overlap ends, and is rebuilt after
  every rotation. On the first start with a keys file, `cookie_keys` and
  `signing_keys` seed the new rings, so nobody is signed out and upstreams
  keep the keys they cached; once the file holds the rings the lists are
  ignored, with a warning. `authz check` checks the file and warns about an
  overlap shorter than the absolute session lifetime or the upstream token
  lifetime. Under `authz run`, the gateway and serve can share one file.
  Without a keys file, `WICKET_COOKIE_KEYS` and `WICKET_SIGNING_KEYS` work as
  before, the signing keys as a configured ring, and `WICKET_COOKIE_KEYS` is
  no longer required when `WICKET_KEYS_FILE` is set. A cached upstream token
  is re-signed once its key stops signing.
- **`authz mcp` rotates its agent token signing keys on its own** ([#76](https://github.com/laiwf94/authz/issues/76)).
  `keys_file` in the mcp section (or `TOOLGATE_KEYS_FILE`, also
  `AUTHZ_MCP_KEYS_FILE`) names the process's key ring file, and signed agent
  tokens are minted and verified on its HS256 `agent` ring through
  `identity.Config.Ring` (`signing_rotate_every` and `signing_overlap`, both
  24h by default, or `TOOLGATE_SIGNING_ROTATE_EVERY` and
  `TOOLGATE_SIGNING_OVERLAP`). On the first start with a keys file
  `signing_keys` seeds the ring under its key ids, so tokens already issued
  keep verifying; once the file holds the ring the keys are ignored, with a
  warning, and a change to them applies on restart. `authz mcp token mint`
  signs with the file's current key without writing the file. `authz check`
  checks the file and the agents config's tokens section and warns about an
  overlap shorter than the longest token lifetime. Under `authz run` the
  parts share one file. Without a keys file, `TOOLGATE_SIGNING_KEYS` works as
  before, as a configured ring.

### Agent gateway (agents)

- **Audit query** ([#81](https://github.com/laiwf94/authz/issues/81)).
  `authz audit query [-full] [-limit N] [-count] [-read-only] FILE TERM...`
  prints the records of every segment that all terms match, as their JSON
  lines, checking the chain as it reads and failing with `FAIL FILE: reason`
  (exit 1) where it breaks. Terms are `KEY=VALUE` or `KEY!=VALUE` over
  `track`, `event`, `tenant`, `actor`, `subject`, `action`, `decision`,
  `correlation`, an agent's `agent`, `tool` and `rule`, any payload field
  as `data.NAME`, and `since`/`until` (RFC 3339, a date or `-24h`); values
  take comma lists, quotes and a trailing `*`. toolgate's records, which
  have no envelope, are read from their payload (actor the agent, subject
  `tool:NAME`). The first query to read a rotated-out segment writes a sparse
  time index beside it (`FILE.<first record>.idx`, an entry every 64 KiB),
  and later queries bounded in time skip what lies outside their window:
  16 ms instead of 176 ms for the last tenth of 50,000 records. The summary
  on standard error says how many records were skipped unread.
- **Inclusion and consistency proofs over the audit log** ([#81](https://github.com/laiwf94/authz/issues/81)).
  `internal/platform/merkle` makes and checks RFC 6962 inclusion and
  consistency proofs (RFC 9162 verification), checked against the published
  test vectors and the RFC's recursion, in one pass over the leaves with
  O(log n) memory. `GET /admin/audit/proof?record=N` (or `?from=M`, with an
  optional `&size=S`) on the mcp admin API serves a JSON proof against the
  newest signed checkpoint, which it carries; `authz audit prove -record
  N|-from M [-size S] FILE` makes the same from the files, and `authz audit
  prove -check PROOF -key KEY [-checkpoint NOTE] [-old NOTE]` checks one with
  only the public key.
- **A Merkle tree over the audit log** ([#81](https://github.com/laiwf94/authz/issues/81)).
  `internal/platform/merkle` is the RFC 6962 tree (leaf and node hashing
  with the 0x00 and 0x01 prefixes, checked against the published test
  vectors) kept as a compact range of at most 64 hashes. With a signing key
  every record, across all segments, is a leaf, and every checkpoint now
  carries the tree head: the third line is the base64 tree head as in a
  transparency log's checkpoint, followed by `chain <base64 last record
  hash>` and `time ...`. Checkpoints in the four-line form of the previous
  entry no longer open; a log replaces its own on open. The range is saved
  to `FILE.tree` before each checkpoint, so a restart reads only the active
  segment; a missing, damaged or stale one is rebuilt from every segment.
  `authz audit verify -key` also checks that the checkpoint's tree head is
  the root of the records it counts, and a subcommand refuses to open a log
  whose own checkpoint carries a tree head its records do not have.
- **Signed audit checkpoints** ([#81](https://github.com/laiwf94/authz/issues/81)).
  With `AUTHZ_AUDIT_SIGNING_KEY` (or `AUTHZ_AUDIT_SIGNING_KEY_FILE`), an
  Ed25519 key in signed-note form that the new `authz audit keygen -out FILE
  NAME` makes, `authz serve`, `authz gateway` and `authz mcp` sign the audit
  log's state (record count and last record's hash) as a checkpoint in the
  signed note format of the Go checksum database and transparency logs. One
  is written to `FILE.checkpoint` on open, every
  `AUTHZ_AUDIT_CHECKPOINT_INTERVAL` (default 1m, at least 1s) when records
  were added, after each rotation and on shutdown, and covers only records
  already on disk. `GET /admin/audit/checkpoint` on the mcp admin API serves
  the newest one. `authz audit verify -key PUBLIC_KEY [-checkpoint NOTE]
  FILE` checks that the log still holds every record a checkpoint covers,
  unchanged, so records cut from the end are caught with only the public
  key; a subcommand with the key refuses to open a log shorter than its own
  checkpoint. A malformed key or interval stops every subcommand at start
  and is reported by `authz check`. Log lines that carry a note signing key
  now fail the secret scan.
- **Audit rotation in the binary and `authz audit verify`**
  ([#81](https://github.com/laiwf94/authz/issues/81)). `audit_rotate_bytes`
  and `audit_rotate_age` in the serve, gateway and mcp sections, and
  `GRANTD_AUDIT_ROTATE_BYTES`/`_AGE`, `WICKET_AUDIT_ROTATE_BYTES`/`_AGE` and
  `AUTHZ_MCP_AUDIT_ROTATE_BYTES`/`_AGE`, rotate the audit log by size (at
  least 4096 bytes) or age (at least 1m); malformed limits, or limits
  without an audit log, are refused at start and by `authz check`. Segment
  start records carry the limits they were cut under, and a subcommand set
  to other limits than the file's active segment was cut under refuses to
  start; `authz check -config` refuses sections that share a file with
  different limits. The new `authz audit verify [-head HASH] FILE` checks
  every segment as one chain and every record against its schema;
  `authz mcp audit verify` is unchanged.
- **Audit log segments** ([#81](https://github.com/laiwf94/authz/issues/81)).
  `internal/platform/audit` can cut the log into segments by size or age
  (`Options.Rotation`; off unless set). The configured path stays the
  newest segment; older ones sit beside it as `FILE.<first record number>`,
  and each later segment opens with an `audit.segment_started` record that
  continues the chain and names the segment before it. Rotation runs under
  the append lock and fsyncs the old file, the new file and the directory;
  other processes sharing the file follow it into the new segment, and a
  crashed rotation is cleaned up on open. `authz mcp audit verify` checks a
  rotated log across all its segments and names a segment that was removed,
  renamed, reordered or replaced; a log that was never rotated prints as
  before.
- **One audit chain for the platform** ([#78](https://github.com/laiwf94/authz/issues/78)).
  toolgate's hash-chained log is now `internal/platform/audit`, and
  `authz serve` (`GRANTD_AUDIT_LOG`), `authz gateway` (`WICKET_AUDIT_LOG`) and
  `authz mcp` (`TOOLGATE_AUDIT_LOG`) all write it. They may point at the same
  file: appends lock it, read what the other processes wrote and chain after
  it, so one host keeps one chain. Records may carry an envelope (tenant,
  actor, subject, action, decision, correlation ID) and each event type has
  a typed payload schema, which all three enforce before writing and
  `VerifyWith` checks afterwards. Logs written by toolgate keep their bytes
  and head and are continued.
  - serve records schema changes (hash and size, never the text) and
    relationship writes, with the API key's `api_key:` ID as the actor.
  - `GRANTD_AUDIT_CHECKS=true` (section: `audit_checks`) also records every
    answered check as an `authz.check_decided` decision record before
    answering; a check whose record cannot be written gets 503.
  - The gateway records sign-ins, failed and refused sign-ins, logouts,
    admin revocations, forward-auth denials and config loads, and keeps its
    log lines as wicket wrote them.
  - A failed append after a committed write is counted
    (`grantd_audit_failures_total`, `wicket_audit_failures_total`) and turns
    `/healthz` to 503.
- **Correlation IDs across serve, gateway and mcp.** Each request's ID is the
  trace ID of its `traceparent`, or a new one. It is on the request's log
  lines and in its audit records, `authz mcp` sends it upstream as a
  `traceparent` with its own parent ID, and the gateway's allowed
  forward-auth answer returns one when the proxy sent one (docs/proxies.md
  shows the nginx, Traefik and Envoy settings to pass it on).
- **One log handler** (`internal/platform/logging`): JSON lines with the
  correlation ID and tenant from the request, live level changes, and
  redaction of secret values, secret-named keys and struct fields tagged
  `log:"secret"`. With no request values its output is the same as before,
  so no existing log line changed.
- **One rate limiter** (`internal/platform/ratelimit`): GCRA with bounded
  memory, now behind wicket's login limit and toolgate's per-agent and
  per-tool buckets, with their old tests passing against it. `authz serve`
  gains an optional per-API-key limit (`GRANTD_KEY_RATE`,
  `GRANTD_KEY_BURST`): over it a request gets 429 `resource_exhausted` with
  `Retry-After`, counted in `grantd_rate_limited_total`.
- **Secret scan in CI.** Every suite runs again with every log line and
  audit record scanned for keys, tokens and passwords; a finding fails the
  test that wrote it.

- **toolgate is now `authz mcp`** ([#75](https://github.com/laiwf94/authz/issues/75)).
  The toolgate packages live at `internal/agents/*` in the root module, and
  `cmd/toolgate` and `cmd/mcpfake` are the `authz mcp` and `authz mcpfake`
  subcommands. The config and policy files, the `TOOLGATE_*` and `MCPFAKE_*`
  variables, both listeners and their endpoints, the audit record format,
  the tool pins, SIGHUP reload and the exit codes are unchanged. Audit logs
  written by toolgate verify under `authz mcp audit verify` and are
  continued on start.
- Every `TOOLGATE_*` variable may also be spelled `AUTHZ_MCP_*`, and every
  `MCPFAKE_*` one `AUTHZ_MCPFAKE_*`. Setting both spellings of one variable
  to different values stops the command at start with exit 2.
- A binary run as `toolgate` or `mcpfake` is `authz mcp` or
  `authz mcpfake` and names itself the old way in its messages. The toolgate
  image ships `/toolgate` and `/mcpfake` as links to `/authz`, and its
  entrypoint is `/authz mcp`.
- `authz mcp -h` and `authz mcpfake -h` print help and exit 0; a flag before
  the subcommand is a usage error with exit 2.
- A "Moving from the toolgate binary" guide is in
  [toolgate/README.md](toolgate/README.md#moving-from-the-toolgate-binary).
- CI holds the move to the old behaviour: the demo's 23 decisions, recorded
  from toolgate before the move, must come out identical through
  `authz mcp`; every toolgate test, subtest and fuzz seed must still pass
  under the race detector (133 cases); moved test files may change only
  their imports and package clause; `authz mcp serve` is killed with SIGKILL
  under load and must lose no acknowledged audit record; and the README's
  two-container example runs through the image's old entry points.
