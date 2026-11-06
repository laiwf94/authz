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

### Agent gateway (agents)

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
