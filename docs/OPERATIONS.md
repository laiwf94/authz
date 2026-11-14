# Operating authz

This guide covers running authz in production: its keys, how they rotate,
and how configuration changes reach a running process. The design behind
them is in [DESIGN.md](DESIGN.md); each subcommand's `-h` lists every
variable it reads.

## Keys

authz holds four kinds of keys. Each sits on a key ring with a current key
that signs or seals, a next key that is already published, and retired keys
that keep verifying until their overlap ends (`internal/platform/keys`).

| Ring          | Algorithm | Part             | What it protects                             |
|---------------|-----------|------------------|----------------------------------------------|
| `consistency` | HS256     | `authz serve`    | consistency tokens (`written_at`, `checked_at`, ...) |
| `session`     | A256GCM   | `authz gateway`  | session and sign-in state cookies            |
| `upstream`    | ES256     | `authz gateway`  | the JWT passed to apps, published at `/.well-known/jwks.json` |
| `agent`       | HS256     | `authz mcp`      | signed agent tokens (`authz mcp token mint`) |

### Two ways to hold keys

**Configured keys** (the default, and how grantd, wicket and toolgate
always worked): `GRANTD_TOKEN_KEY`, `WICKET_COOKIE_KEYS`,
`WICKET_SIGNING_KEYS` and `TOOLGATE_SIGNING_KEYS` list the keys. The first
key signs and every listed key verifies. Nothing rotates on its own; you
rotate by putting a new key first, keeping the old ones listed for as long
as credentials they issued may still be in use, then removing them. Cookie
keys and agent signing keys in a platform file are applied while the process
runs; the others apply on restart.

**A key ring file** rotates every key on its own. Name it in each part:

| Part     | Section field (`-config`) | Variable                                   |
|----------|---------------------------|--------------------------------------------|
| serve    | `serve.keys_file`         | `GRANTD_KEYS_FILE`                         |
| gateway  | `gateway.keys_file`       | `WICKET_KEYS_FILE`                         |
| mcp      | `mcp.keys_file`           | `TOOLGATE_KEYS_FILE` or `AUTHZ_MCP_KEYS_FILE` |

and set how often each ring rotates and how long a retired key verifies:

| Ring          | Rotation period (default)                                  | Overlap (default)                               |
|---------------|------------------------------------------------------------|-------------------------------------------------|
| `consistency` | `token_rotate_every`, `GRANTD_TOKEN_ROTATE_EVERY` (24h)    | `token_overlap`, `GRANTD_TOKEN_OVERLAP` (168h)  |
| `session`     | `cookie_rotate_every`, `WICKET_COOKIE_ROTATE_EVERY` (24h)  | `cookie_overlap`, `WICKET_COOKIE_OVERLAP` (48h) |
| `upstream`    | `signing_rotate_every`, `WICKET_SIGNING_ROTATE_EVERY` (24h) | `signing_overlap`, `WICKET_SIGNING_OVERLAP` (24h) |
| `agent`       | `signing_rotate_every`, `TOOLGATE_SIGNING_ROTATE_EVERY` (24h) | `signing_overlap`, `TOOLGATE_SIGNING_OVERLAP` (24h) |

A period of `0s` never rotates. The shortest period is 1s, and a ring that
rotates must have an overlap. Choose the overlap from the longest-lived
credential the ring protects:

- `consistency`: as long as clients hold on to a token. A token whose key
  has gone is refused with 400 `invalid consistency token`, and the client
  must read again without it.
- `session`: at least the absolute session lifetime, or sessions end early.
  `authz check` warns when it is shorter.
- `upstream`: at least `upstream_token_ttl`, and apps should refetch the
  JWKS more often than the rotation period. The gateway publishes the next
  key a whole period before it signs, so an app that refetches once a period
  never sees an unknown key. `authz check` warns about a period under the
  5-minute JWKS cache and an overlap under the token lifetime.
- `agent`: at least the longest agent token lifetime in the agents config's
  tokens section. `authz check` warns when it is shorter.

### Moving to a key ring file

The first start with a keys file creates the file (mode 0600) and its
rings. A ring the file lacks starts from the configured keys when they are
set: the first key stays current and the others are retired for the
overlap. So the move signs nobody out, refuses no agent token and leaves
apps with the JWKS keys they cached. Consistency tokens are the exception:
`GRANTD_TOKEN_KEY` and `GRANTD_KEYS_FILE` cannot both be set, so tokens
issued under the old key are refused after the move, and clients read again
without them.

Once the file holds a ring, the configured keys are ignored and a warning
says they can be removed. `keys_file` and the rotation settings apply on
restart.

```console
$ export WICKET_KEYS_FILE=/var/lib/authz/keys.json WICKET_COOKIE_KEYS=...   # first start: seeds the rings
$ authz check -config authz.json                                          # checks the file and the policies
$ authz gateway
{"level":"INFO","msg":"starting the ring from cookie_keys","keys_file":"/var/lib/authz/keys.json","ring":"session","keys":1}
```

### One file per process

A ring file belongs to one process. Under `authz run`, every part naming the
same path shares one set of rings, rotated and saved once; point serve,
gateway and mcp at one file there. Separate processes need separate files:
before each save a process checks that the file still holds what it last
read or wrote, and if another process has changed or removed it, the save is
refused and logged (`key ring check failed; the rings keep their keys`). The
running rings keep their keys and verify as before, but they stop rotating
until the process restarts on its own file.

Rings are per process. Replicas of one part behind a load balancer do not
share a ring file, so a cookie sealed by one replica does not open on
another. Run replicas on configured keys (the same `WICKET_COOKIE_KEYS` and
so on everywhere) and rotate them by hand as above.

### What to watch

Each rotation is logged at info, with the ring and, for signing rings, the
new key id:

```
{"level":"INFO","msg":"key ring rotated","subcommand":"gateway","keys_file":"/var/lib/authz/keys.json","ring":"upstream","signing_kid":"..."}
```

Alert on `key ring check failed; the rings keep their keys` (the file could
not be saved) and on `refreshing the published keys failed` (the gateway
could not rebuild its JWKS). A process restarted inside the overlap reads
the saved file and keeps every retired key it held.

### Retiring a compromised key

There is no command yet to drop a single key from a running process. Stop
the process (every part, under `authz run`), then either:

- delete the key's entry from its ring's `previous` list in the file, if
  the key has already been retired: credentials it issued are refused from
  the restart on; or
- delete the whole ring from the file: on restart it is created with fresh
  keys, and every credential that ring protects is refused (everyone signs
  in again, agents get new tokens, apps refetch the JWKS). Unset the
  configured keys first, or the new ring starts from them again.

The file is JSON (`{"version":1,"rings":[...]}`); a file that no longer
matches its keys is refused at start with the reason. Check it with
`authz check -config` before starting.

### Verified end to end

`TestRunRotatesEveryKey` (cmd/authz/keyrotation_test.go) runs `authz run`
with serve, the gateway and mcp on one keys file, every ring rotating each
second with a four-second overlap, for six seconds. Meanwhile clients sign
in over SAML, call forward-auth with session cookies sealed up to 2.5 s
earlier and verify each upstream token against a JWKS fetched at most a
period earlier. Other clients write relationships and check them with the
consistency token of the write, held up to 2.5 s, and call tools through mcp
with agent tokens minted from the file up to 2.5 s earlier. Every ring
rotates several times, about half of all requests use a credential from a
key that has since stopped signing, and no request fails (a run on a
development machine: 23,064 forward-auths, 40,859 checks and 37,353 MCP
calls). With the overlap cut to one second, the same test fails within two
seconds with refused cookies and consistency tokens.

## Configuration changes

`authz serve`, `authz gateway` and `authz mcp serve` started with `-config
file` (or `AUTHZ_CONFIG`) watch the file and the secret files it references
(`*_file` fields) once a second and apply a change within a second or two.
What applies live:

- serve: API keys and the log level;
- gateway: providers, apps, cookie keys (without a keys file) and the log
  level;
- mcp: the agents config, the policy, signing keys (without a keys file)
  and the log level.

Anything else is logged as applying on restart. A file that is half written,
fails its schema or fails a part's checks is refused: the error is logged
with its JSON path, and the process keeps the configuration it had, so no
request fails. Fix the file and the next poll applies it. `authz check
-config file` runs the same checks before you deploy a change, and `-online`
also fetches each provider's metadata.

SIGHUP reloads the gateway's configuration and the MCP policy at once,
under `authz run` too.
