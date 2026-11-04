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
