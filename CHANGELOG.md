# Changelog

Changes that operators and users can see, newest first. Each week's entries
link the roadmap issue they come from.

## Unreleased

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
