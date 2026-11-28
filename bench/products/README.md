# bench/products

The products the benchmark compares with authz (#86), each at a pinned
version with its recommended production settings, all taking the same
seeded dataset (`bench/datasets`) and answering the same checks.

This directory holds the authorization products (authz, SpiceDB and
OpenFGA) and the identity products: Keycloak, oauth2-proxy signing in
through it, and Zitadel, which the gateway's sign-ins and forward-auth
decisions are compared with. The MCP gateways (agentgateway, Kong) are the
next task of week 5.

| Path | What it is |
| --- | --- |
| `compose.yaml` | Every product and its database, pinned by version and digest, on the same limits |
| `verify.sh` | Brings the authorization products up, loads one dataset into each and fails on any differing answer |
| `verify-identity.sh` | Brings Keycloak, oauth2-proxy and Zitadel up, imports the sign-in population and proves sign-ins and forward-auth on them |
| `keycloak/Dockerfile` | Keycloak's optimized production image, built from the pinned release |
| `keycloak.go` | The realm, client and user import through Keycloak's admin API |
| `zitadel.go` | The project, application, roles and user import through Zitadel's APIs, and a sign-in that reads the ID token |
| `openfga-model.json` | The dataset's model as OpenFGA's API takes it, made by the pinned OpenFGA CLI |
| `products.go` | The Go side: setup, write formats and checks for each product's HTTP API |
| `crosscheck.go` | Sampled questions and the cross-check |

## Versions

| Product | Image | Datastore | Compared on |
| --- | --- | --- | --- |
| authz | `authz:bench`, built from this checkout | its own write-ahead log on a volume | everything |
| SpiceDB | `authzed/spicedb:v1.57.1` | PostgreSQL | check, bulk check, lookup, write |
| OpenFGA | `openfga/openfga:v1.23.0` | PostgreSQL | check, bulk check, lookup, write |
| PostgreSQL | `postgres:17.12-alpine` | | the datastore of SpiceDB and OpenFGA |
| OpenFGA CLI | `openfga/cli:v0.9.0` | | turns the model into `openfga-model.json` |
| Keycloak | `keycloak/keycloak:26.8.2`, built into `authz-bench-keycloak:26.8.2` | PostgreSQL | sign-in |
| oauth2-proxy | `quay.io/oauth2-proxy/oauth2-proxy:v7.15.6` | Redis, for sessions | sign-in through Keycloak, forward-auth |
| Redis | `redis:8.12.0-alpine` | | oauth2-proxy's session store |
| Zitadel | `ghcr.io/zitadel/zitadel:v4.20.6` | PostgreSQL | sign-in |

Each image is pinned by tag and digest in `compose.yaml` (the digest of the
multi-platform index, read from the registry on 2026-11-22, and on
2026-11-28 for Keycloak, oauth2-proxy, Redis and Zitadel). Keycloak is run from an
image built by `keycloak/Dockerfile`, whose every `FROM` is pinned the same
way. A test fails when an image there is not pinned that way or this table
does not name its version. The versions were each product's newest release
on that day. A new
version is a change to this file and to `compose.yaml` in one commit, and
the next published run says which versions it measured.

## Limits

Every server and every database gets the same `BENCH_CPUS` (default 2) and
`BENCH_MEMORY` (default 4 GB). authz keeps its store in its own process, so
its one container holds what SpiceDB and OpenFGA split between their server
and a PostgreSQL container: the comparison gives the competitors twice the
resources, and the report says so next to each number. The same holds for
sign-ins: Keycloak and Zitadel each run with their own PostgreSQL, and
oauth2-proxy with its own Redis. Ports are bound to 127.0.0.1 only: 18080
authz, 18443 SpiceDB's HTTP gateway, 18081 OpenFGA's HTTP API, 18180
Keycloak (19000 its management port, with health and metrics), 14180
oauth2-proxy, 18280 Zitadel.

## Production settings

What each product's own production guidance recommends, and what the
benchmark changes on top of it. A default not listed here is left as it
ships.

**authz** (`authz serve`)

- `GRANTD_DATA_DIR=/data`: durable writes to the write-ahead log, fsynced
  before a write is answered, as in production. Without it the store is
  memory only, which would flatter the write numbers.
- `GRANTD_TOKEN_KEY`: a fixed consistency-token key, required with a data
  directory.
- `GRANTD_LOG_LEVEL=warn`: no log line for each request.
- The check cache (`GRANTD_CACHE_SIZE`, 100,000 results) and the
  `minimize_latency` quantum stay at their defaults.

**SpiceDB** (`spicedb serve`)

- `--datastore-engine=postgres`: SpiceDB's documentation recommends
  PostgreSQL or CockroachDB in production and calls the memory datastore a
  development tool. `spicedb migrate head` runs first, as the operator
  does.
- `--datastore-conn-pool-read-max-open=40`, `--datastore-conn-pool-write-max-open=20`:
  twice the defaults (20 and 10) so that the pool is not the limit at the
  benchmark's concurrency; PostgreSQL allows 200 connections.
- `--http-enabled --http-addr=:8443`: the HTTP gateway, so that every
  product is measured through the same kind of client (JSON over HTTP/1.1).
  It adds a translation step over SpiceDB's gRPC API; gRPC is measured
  once authz has it (W19), and the report says which protocol each figure
  used.
- `--grpc-preshared-key`: the API key; the gateway takes it as a bearer
  token.
- `--telemetry-endpoint=`: no telemetry reports from the benchmark.
- `--log-format=json --log-level=warn`: structured logs, none per request.
- The dispatch cache, schema cache and revision quantization (5 s) stay at
  their defaults, which are SpiceDB's production recommendations. One node,
  so no dispatch cluster.

**OpenFGA** (`openfga run`)

- `--datastore-engine=postgres`: OpenFGA's production guide recommends
  PostgreSQL or MySQL; memory is for development. `openfga migrate` runs
  first.
- `--datastore-max-open-conns=60 --datastore-max-idle-conns=60`: the guide
  recommends sizing the pool to the database and keeping idle connections
  equal to open ones, so that connections are not churned under load.
- `--authn-method=preshared --authn-preshared-keys`: the guide's
  requirement to turn authentication on; the key is a bearer token.
- `--playground-enabled=false`: the guide's requirement for production.
- `--check-query-cache-enabled --check-iterator-cache-enabled
  --list-objects-iterator-cache-enabled --cache-controller-enabled`: the
  caches the guide recommends for read-heavy workloads, with the cache
  controller invalidating them after writes. Requests with
  `HIGHER_CONSISTENCY` skip them.
- `--log-format=json --log-level=warn`: structured logs, none per request.
- `--max-tuples-per-write` stays at 100, so the loader writes 100 tuples a
  request.
- `--listObjects-max-results=100` (`BENCH_LOOKUP_LIMIT`): ListObjects has
  no limit in the request, and its default of 1,000 results would have it
  answer ten times what SpiceDB and authz are asked for (authzbench's
  `-lookup-limit`, 100). authzbench fails an answer over its limit, so the
  two settings cannot drift apart unnoticed. `--max-checks-per-batch-check`
  stays at 50, so a bulk check has at most 50 items.

**Keycloak** (`kc.sh start --optimized`)

- An optimized image: Keycloak's production guide has the build-time
  options fixed by `kc.sh build` in a custom image, so that a start does
  not rebuild (which would add tens of seconds to the cold start the
  benchmark measures). Built in are `KC_DB=postgres` (the guide's
  production databases are PostgreSQL and the others it lists; the
  development database is for development only), `KC_HEALTH_ENABLED` and
  `KC_METRICS_ENABLED` (readiness on the management port, as a production
  probe uses it) and `KC_CACHE=local`: one node, so no cluster
  discovery, as the guide says for a single instance.
- `--db-pool-min-size=20 --db-pool-initial-size=20 --db-pool-max-size=40`:
  the guide recommends a fixed pool (equal initial and minimum sizes), so
  that connections are not opened under load, and a maximum sized for the
  concurrency, here the same 40 as SpiceDB's read pool.
- `--hostname=http://127.0.0.1:18180 --hostname-backchannel-dynamic=true`:
  the issuer is the address the benchmark's browser uses, and services in
  the compose network (oauth2-proxy) reach the token and keys endpoints at
  `keycloak:8080`, as a backchannel inside a cluster does.
- `--http-enabled=true --proxy-headers=xforwarded`: plain HTTP behind a
  TLS-terminating proxy, the guide's edge setup; the benchmark measures
  every product without TLS.
- `--log-level=warn --log-console-output=json`: structured logs, none per
  request.
- The heap stays at Keycloak's container default, 70% of the memory limit
  (`JAVA_OPTS_KC_HEAP`), with the initial heap at 50%.
- The realm (`bench`) keeps Keycloak's default password policy, Argon2
  hashing, and has brute-force detection on, as the server administration
  guide recommends. Its client `bench-proxy` is confidential, has only the
  authorization code flow, requires PKCE (S256) and puts the user's group
  names in a `groups` claim of the ID token, the access token and userinfo.

**oauth2-proxy** (`oauth2-proxy`)

- `--provider=keycloak-oidc` with the realm as issuer: the provider its
  documentation names for Keycloak. Discovery is skipped and each endpoint
  is named (`--login-url` at the browser's address, `--redeem-url` and
  `--oidc-jwks-url` at `keycloak:8080`), because the browser and
  oauth2-proxy reach Keycloak at different addresses; the issuer of every
  token is still checked.
- `--code-challenge-method=S256`: PKCE, which its documentation recommends
  and the client requires.
- `--reverse-proxy=true --upstream=static://200`: behind a reverse proxy
  that asks `/oauth2/auth` before passing a request on (202 with a valid
  session, 401 without), the forward-auth setup of its nginx and Traefik
  guides; `--set-xauthrequest` answers the user, email and groups in
  `X-Auth-Request-*` headers. `--skip-provider-button` goes straight to
  Keycloak.
- `--cookie-secure=true --cookie-samesite=lax` and a 32-byte
  `--cookie-secret`: its production cookie settings.
- `--session-store-type=redis`: its documentation recommends Redis once
  sessions carry an OIDC provider's tokens: in cookies, Keycloak's access,
  ID and refresh tokens pass the 4 KB cookie limit and are split, and every
  request carries all of them. The session cookie then holds only a ticket.
- `--request-logging=false --auth-logging=false --standard-logging=false`:
  no log line for each request.

**Zitadel** (`zitadel`), configured by environment variables as its
self-hosting guide does, following its production checklist where it
applies to one node:

- `start-from-init --masterkeyFromEnv --tlsMode disabled`: one process that
  creates its database and user (with the admin account of its
  PostgreSQL), sets up the first instance and serves, the guide's
  single-node start; the master key comes from the environment, not the
  command line. TLS is off for the same reason as Keycloak's: the benchmark
  measures every product without TLS.
- `ZITADEL_EXTERNALDOMAIN=localhost`, `ZITADEL_EXTERNALPORT=18280`,
  `ZITADEL_EXTERNALSECURE=false`: Zitadel picks the instance by the host a
  request names, so the external address is the one the benchmark's
  browser and the import use, and the issuer is `http://localhost:18280`.
- `ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS=20` and `MAXIDLECONNS=20`: a
  fixed pool, as for Keycloak, instead of the default 10 open and 5 idle.
- The first instance has the organization `bench` and a machine user
  `bench-admin`, an instance administrator, whose personal access token
  Zitadel writes to `/bootstrap/admin.pat` (`ZITADEL_FIRSTINSTANCE_PATPATH`),
  the guide's way to automate an instance. The image has no shell, so a
  one-shot `zitadel-bootstrap` container makes that volume writable for
  Zitadel's user (1000) first.
- `ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED=false`, and the
  application asks for login v1: the login Zitadel serves itself. v4's
  new login is a separate Next.js service, and the comparison is of one
  identity server each. Login v1 asks for the name and the password on two
  pages; `ops.Login` fills both, as a browser does.
- Passwords are hashed with argon2id at 19 MiB, 2 iterations and 1 thread
  (`ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_*`), OWASP's first
  recommendation for argon2id, instead of Zitadel's default bcrypt at cost
  14, which takes about a second of CPU a sign-in. Keycloak also hashes
  with Argon2 by default, so both sign-ins measure a modern hash of about
  the same cost, not the products' different defaults.
- The password policy asks for 12 characters and no character classes
  (`PASSWORDCOMPLEXITYPOLICY_*`), as NIST SP 800-63B recommends; the
  dataset's passwords have no capital letters, which Zitadel's default
  policy requires.
- The login policy allows no self-registration, no external identity
  providers and no passwordless sign-in, does not tell unknown user names
  apart (`IGNOREUNKNOWNUSERNAMES`), and does not prompt to set up a second
  factor (`MFAINITSKIPLIFETIME=0s`), the same as the Keycloak realm, which
  offers none. Ten wrong passwords lock an account
  (`LOCKOUTPOLICY_MAXPASSWORDATTEMPTS`), as brute-force detection does in
  Keycloak; the benchmark signs in only with right passwords.
- `ZITADEL_LOG_LEVEL=warn`: no log line for each request.

Zitadel has no groups, so the import makes each graph group a role of the
project `bench` (its key is the group's ID, `g12`) and gives each user one
user grant of its groups' roles. The project asserts its roles, and the
application `bench-login` puts them and the userinfo claims in the ID
token, so `urn:zitadel:iam:org:project:roles` there is keyed by the user's
groups in the graph. The application is a web application with PKCE and no
secret (auth method none), the authorization code flow only, in
development mode, which allows the benchmark's `http://` redirect URI.

**Redis**, oauth2-proxy's session store: no persistence (`--save ""
--appendonly no`), as for a cache, and `noeviction`, so that a full store
refuses new sessions instead of dropping signed-in ones.

**PostgreSQL**, the same for every product that has one: `shared_buffers=1GB` (a quarter of the
memory limit, PostgreSQL's own starting point), `effective_cache_size=3GB`,
`max_connections=200`, `track_commit_timestamp=on` (SpiceDB's Watch API needs
it) and synchronous commits, so that a write is durable when it is answered,
as authz's is.

## Loading and checking

`authzdata` loads the dataset into any of them through its write API:

```
export AUTHZBENCH_API_KEY=bench-authz-key-0123456789
export AUTHZBENCH_SPICEDB_KEY=bench-spicedb-key-0123456789
export AUTHZBENCH_OPENFGA_KEY=bench-openfga-key-0123456789
docker compose -f bench/products/compose.yaml --profile authz --profile spicedb --profile openfga up -d
./authzdata load -size 10m -api http://127.0.0.1:18080 -schema
./authzdata load -size 10m -target spicedb -api http://127.0.0.1:18443 -schema -workers 8
./authzdata load -size 10m -target openfga -api http://127.0.0.1:18081 -workers 16
./authzdata crosscheck -size 10m -n 5000 -authz http://127.0.0.1:18080 \
  -spicedb http://127.0.0.1:18443 -openfga http://127.0.0.1:18081
```

- **SpiceDB** takes the dataset's schema (`datasets.Schema`) as it is, with
  `POST /v1/schema/write`, and the relationships as `OPERATION_TOUCH`
  updates of `POST /v1/relationships/write`, 1,000 a request (its default
  limit). A wildcard subject is object ID `*`.
- **OpenFGA** keeps data in a store: the loader finds the store named
  `authz-bench` or creates it, and writes `openfga-model.json` unless the
  store's newest model already is that model, so running it again changes
  nothing. OpenFGA reads a model back with every unset field filled in
  (`module`, `source_info`, `condition`, empty `relations` and
  `metadata`), so the comparison leaves out empty values, except a direct
  assignment's `this: {}`; `testdata/openfga-readback.json` is a model as
  v1.23.0 answered it. Tuples go to `POST /stores/{id}/write`, 100 a request, with
  `on_duplicate: ignore`, so a write is idempotent like a touch and a load
  can be repeated or resumed with `-from`. Checks name the model.
- **Checks**: `crosscheck` draws questions from the seed (two in three
  `view` or `edit` of a random document for a random user, one in three
  about a document relationship found at a random place in the graph: an
  owner, an editor, a banned user or an editing group's members), asks
  every product each one with its freshest read (`fully_consistent`,
  `fullyConsistent`, `HIGHER_CONSISTENCY`), and fails on the first differing
  answer.

## verify.sh

```
bench/products/verify.sh                 # SIZE=100k N=2000
SIZE=1m N=5000 bench/products/verify.sh
AUTHZ_URL=http://127.0.0.1:18080 bench/products/verify.sh   # a running authz instead of the image
```

It checks `openfga-model.json` against the pinned CLI's
`fga model transform` of `authzdata schema -format openfga`, starts the
three products on fresh volumes, loads the dataset into each, loads part of
it again, and cross-checks. Last it runs `authzbench` against each
product's own API: check 40, bulk check 20, lookup 20 and write 20 at
`BENCH_RATE` (20 a second) for `BENCH_DURATION` (10 s), which must keep up
with no error at all (the result files are left in the work directory
with `KEEP=1`). That is a proof that every operation of the benchmark
works on every product, not a measurement. Its runs on a 4 vCPU container, with authz
running on the host (`AUTHZ_URL`) and SpiceDB, OpenFGA and their databases
in Docker:

| Size | authz load | SpiceDB load | OpenFGA load | Questions | Allowed | Disagreements |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100k | 0.4 s, 266k/s | 3.7 s, 27k/s | 28 s, 3.6k/s | 2,000 | 972 | 0 |
| 1m | 3.6 s, 277k/s | 34.7 s, 29k/s | 2 min 4 s, 8.1k/s | 5,000 | 1,829 | 0 |

SpiceDB was loaded with 8 writes in flight and OpenFGA with 16, authz with
4. After the 1m load the containers held 83 MB (SpiceDB) and 676 MB (its
PostgreSQL), 47 MB (OpenFGA) and 1.1 GB (its PostgreSQL). These are load
times through each product's write API, not benchmark results: the
measured numbers come from `authzbench` on these setups, with the
collection and report of the following tasks.

The authzbench step at 100k, 20 requests a second for 10 s, Zipf 1.1 (200
requests each, 0 errors, 0 unsent), p50 and p99 in milliseconds:

| Operation | authz | SpiceDB | OpenFGA |
| --- | ---: | ---: | ---: |
| check | 1.5 / 2.4 | 17.4 / 300.5 | 2.5 / 5.3 |
| bulk check (10) | 4.4 / 7.2 | 23.1 / 322.5 | 11.1 / 24.2 |
| lookup (100) | 32.1 / 55.3 | 200.5 / 493.9 | 8.2 / 18.5 |
| write | 1.5 / 2.8 | 5.1 / 82.2 | 3.1 / 4.4 |

Too few requests for a p99 to mean much, but two things show already.
SpiceDB's LookupResources costs about 170 ms of CPU at this size, so lookups
at 20 a second take most of its 2 CPUs and slow its checks too; at 100
requests a second it fell 13 s behind. authz's lookups are four times
slower than OpenFGA's ListObjects, the first target for W11.

## Importing users

`authzdata import` creates the realm and the client in Keycloak, or brings
them back to these settings when they exist, and imports the first `-n` of
the dataset's sign-in population (`datasets.User`) with Keycloak's partial
import: first every group the users are in, in one request, then the users
200 to a request, 4 requests at a time, each with its password, email
(verified) and groups. Existing groups and users are skipped, so an import
can be repeated or resumed; `-verify` reads users back and fails on one
that is missing or differs from the graph.

```
export AUTHZBENCH_KEYCLOAK_ADMIN_PASSWORD=bench-keycloak-admin-0123456789
export AUTHZBENCH_KEYCLOAK_CLIENT_SECRET=bench-keycloak-client-0123456789
docker compose -f bench/products/compose.yaml --profile keycloak up -d --build
./authzdata import -size 1m -n 5000 -api http://127.0.0.1:18180
./authzdata users -size 1m -n 5000 -format credentials -o credentials
./authzbench -mix oidc_login=1 -rate 20 -login-credentials @credentials \
  -login-start 'http://127.0.0.1:14180/oauth2/start?rd=%2F' -login-cookie _oauth2_proxy
```

Keycloak hashes each imported password with the realm's policy, as a
sign-up would, so an import costs what that many sign-ups cost: on 2 CPUs,
about 50 to 60 users a second (2,000 users in 32 s). A group is named by
its graph ID (`g12`), the value of the `groups` claim, so the groups a
provider asserts are the user's direct groups in the graph.

With `-target zitadel`, the import reads the instance administrator's
token from `AUTHZBENCH_ZITADEL_TOKEN`, creates the project and the
application (or brings them back to these settings), prints the
application's client ID, adds a role for each group the users are in, and
then writes each user with its password, a verified email and its user
grant, 8 at a time: Zitadel takes one user per request. A user that exists
and a grant that exists are skipped, so an import can be repeated or
resumed. Zitadel's reads trail its writes, so `-verify` reads a user again
for up to 30 s until it shows. `authzdata signin` then signs sampled users
in through the application as a browser does (the authorization code flow
with PKCE), redeems the code and fails unless the ID token names the user,
the user's email and exactly the user's groups as roles.

```
docker compose -f bench/products/compose.yaml --profile zitadel up -d
docker compose -f bench/products/compose.yaml --profile zitadel cp zitadel:/bootstrap/admin.pat admin.pat
export AUTHZBENCH_ZITADEL_TOKEN=$(cat admin.pat)
./authzdata import -target zitadel -size 1m -n 5000 -api http://localhost:18280
./authzdata signin -target zitadel -size 1m -n 5000 -api http://localhost:18280
```

## verify-identity.sh

```
bench/products/verify-identity.sh                # SIZE=100k USERS=500
SIZE=1m USERS=5000 bench/products/verify-identity.sh
```

It starts Keycloak, oauth2-proxy and Zitadel on fresh volumes, imports
`USERS` users into Keycloak and into Zitadel, imports them again (every
user, group and role must be skipped) and reads every one back. Then it
signs `u0` in through oauth2-proxy with curl and checks that
`/oauth2/auth` accepts the session and asserts the user's email and
exactly the user's groups in the graph, and signs 5 users in through
Zitadel with `authzdata signin`, which checks the same of each ID token.
Last it runs `authzbench` with no error allowed: sign-ins straight at
Keycloak (which end at its account page with the `KEYCLOAK_IDENTITY`
cookie set), through oauth2-proxy (ending with its session cookie) and
straight at Zitadel (ending at the redirect with the code, `-login-done`),
each at `LOGIN_RATE` (10 a second), and
forward-auth decisions of oauth2-proxy at `BENCH_RATE` (200 a second) with
20 signed-in sessions (202) and with none (401), each for `BENCH_DURATION`
(10 s). A run on the 4 vCPU container, everything in Docker at 2 CPUs a
container, at 100k with 500 users:

| Step | Result |
| --- | --- |
| first import | 500 users and 46 groups in 9.6 s, 52 users/s |
| second import | 546 skipped, 0 added, in 0.5 s |
| read back | 500 users, email and groups as in the graph |
| sign-in at Keycloak | 100, 0 errors, p50 48 ms, p99 71 ms |
| sign-in through oauth2-proxy | 100, 0 errors, p50 48 ms, p99 82 ms |
| forward-auth, signed in (202) | 2,000, 0 errors, p50 1.3 ms, p99 2.1 ms |
| forward-auth, no session (401) | 2,000, 0 errors, p50 1.1 ms, p99 1.8 ms |

Afterwards Keycloak held 715 MB, its PostgreSQL 126 MB, oauth2-proxy 9 MB
and Redis 6 MB. Zitadel's image cannot be pulled where that run was made,
so its part of the script is proved by the bench-products workflow, which
runs the whole script on every change to these setups. As for the authorization products, these runs prove the
setups; the measured numbers come from the collection and report tasks.
