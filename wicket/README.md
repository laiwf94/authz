# wicket

A single sign-on gateway that puts OpenID Connect and SAML 2.0 login in front
of any web application, through the forward-auth hook of nginx, Traefik or
Envoy. The app gets an authenticated user, as headers and as a signed token
it can verify, without containing any authentication code.

Written in Go. The only dependencies are an XML signature library and its XML
tree package (see [why](docs/DESIGN.md#dependencies)); OpenID Connect, JWT,
cookies and sessions are implemented on the standard library.

```json
{
  "public_url": "https://app.example.com/_wicket",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://login.example.com",
     "client_id": "wicket", "client_secret_env": "CORP_SECRET"},
    {"id": "partner", "type": "saml", "idp_metadata_url": "https://idp.partner.example/metadata",
     "sp_key_file": "sp-key.pem", "sp_cert_file": "sp.pem"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["app.example.com"], "providers": ["corp", "partner"],
     "allow": {"groups": ["eng"], "email_domains": ["example.com"]}}
  ]
}
```

```console
$ curl -s -o /dev/null -w '%{http_code} %header{x-auth-redirect}\n' localhost:4180/auth -H 'X-Forwarded-Host: app.example.com'
401 https://app.example.com/_wicket/login?app=wiki&rd=https%3A%2F%2Fapp.example.com%2F
$ curl -s -o /dev/null -w '%{http_code} %header{x-auth-user} %header{x-auth-groups}\n' localhost:4180/auth \
    -H 'X-Forwarded-Host: app.example.com' -b "__Host-wicket=$COOKIE"
200 alice eng,admins
```

## Putting wicket in front of an app

The proxy asks `/auth` about every request. A signed-in, permitted user gets
a 200 with `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`, `X-Auth-Provider`
and `X-Auth-Token`; anyone else gets a 401 that points at the login page, or a
403 if they are signed in but not allowed. nginx needs the 401 turned into a
redirect itself; Traefik and Envoy can pass wicket's own redirect straight to
the browser while API calls still get JSON. Configurations for all three are
in [docs/proxies.md](../docs/proxies.md).

Each app lists the identity providers it accepts and who may use it (exact
emails, email domains, groups, or anyone from those providers). Nothing is
allowed by default. One config can mix providers of both kinds.

OpenID Connect providers are used with the authorization code flow and PKCE.
The ID token is checked the way OpenID Connect Core says a relying party must,
against an algorithm allow-list that can't contain `none` or HMAC. Signing
keys are cached and re-fetched when a provider rotates them, at most once a
minute.

SAML identity providers get SP-initiated, optionally signed requests and
answer with signed, optionally encrypted assertions. The verification order
is built to defeat XML signature wrapping; assertions are single-use and must
answer the request this browser made.

The browser only ever holds a sealed cookie with a random session id. Sessions
live on the server, in memory with an optional append-only log, so they
survive restarts and can be revoked. `X-Auth-Token` is a two-minute ES256 JWT
that the app can verify against `/.well-known/jwks.json`, which matters
because headers are easy to forge for anything that reaches the app without
going through the proxy.

Around that sit an admin API for listing and revoking sessions and reloading
the config, an audit log line for every login, failure, logout and
revocation, Prometheus metrics, and rate limits on the login endpoints.
`authz fakeidp` is a small but strict identity provider speaking both
protocols, which the tests and the demo run against.

## Running the demo, then your own

The demo needs Go, Docker, curl and python3. It builds everything, starts
fakeidp, a tiny app, wicket and nginx (in Docker), then walks through an
OpenID Connect login, a SAML login with an encrypted assertion, a 403, header
spoofing attempts, admin revocation, a `kill -9` restart and logout, checking
each step:

```console
$ ./examples/demo.sh
...
== 2. alice signs in with OpenID Connect (code flow + PKCE)
   ok: callback set the session cookie and returned to https://localhost:8443/hello?x=1
   whoami says: {"headers":{"X-Auth-Email":"alice@example.org","X-Auth-Groups":"eng,admins","X-Auth-User":"alice"},...}
   ok: the upstream verified wicket's ES256 token (not just the headers)
...
All demo steps passed.
```

To run it with your own config:

```console
$ go build -o authz ./cmd/authz       # from the repository root
$ export WICKET_COOKIE_KEYS=$(./authz gateway genkey) CORP_SECRET=...
$ WICKET_CONFIG=wicket.json ./authz gateway
```

Or with Docker (distroless, non-root):

```console
$ docker build -t wicket .
$ docker run -p 4180:4180 -v $PWD/wicket.json:/etc/wicket.json:ro \
    -e WICKET_CONFIG=/etc/wicket.json -e WICKET_COOKIE_KEYS -e CORP_SECRET wicket
```

Check a config before deploying it. `authz gateway check` validates the file the
way startup would, without starting anything, and lists every problem with
its JSON path and position rather than stopping at the first: unknown or
mistyped fields, provider references, hosts that overlap between apps,
return URLs, and the key, certificate, CA and metadata files the providers
name. `-online` also fetches each provider's discovery document, signing
keys and SAML metadata URL. It exits 1 on errors; warnings (an unused
provider, an app nobody may use, a certificate about to expire) exit 0:

```console
$ ./authz gateway check wicket.json
wicket.json:9:22: error: $.providers[1].sp_cert_file: other.pem is not the certificate for sp-key.pem
wicket.json:14:5: warning: $.apps[1].allow: nobody is allowed: set any_user or list emails, email_domains or groups
wicket.json:14:31: error: $.apps[1].hosts[0]: host "wiki.example.com:443" overlaps $.apps[0].hosts[0]: each host belongs to one app
wicket.json: 2 errors, 1 warning (offline checks)
$ CORP_SECRET=... ./authz gateway check -online wicket.json
wicket.json: ok, 2 providers and 1 app, 0 warnings (online checks)
```

Settings that are not about identity providers or apps (listen addresses,
keys, the session log, trusted proxies, the admin token) come from the
environment and are listed by `authz gateway -h` and in
[cmd/authz/internal/gateway/gateway.go](../cmd/authz/internal/gateway/gateway.go).

## Endpoints

Public listener (`WICKET_ADDR`, default `:4180`):

| Endpoint | Purpose |
|---|---|
| `GET /auth` | Forward-auth for nginx and Traefik. App from `?app=` or `X-Forwarded-Host`; `?redirect=1` redirects browsers. |
| `ANY /auth/envoy/{path}` | Forward-auth for Envoy `ext_authz` (original path appended, original Host). |
| `GET /login?app=&rd=[&provider=]` | Start a login; shows a provider chooser when the app accepts several. |
| `GET /callback/{provider}` | OpenID Connect redirect URI. |
| `POST /saml/{provider}/acs` | SAML assertion consumer service (HTTP-POST). |
| `GET /saml/{provider}/metadata` | SP metadata to give the identity provider. |
| `GET /logout`, `POST /logout` | Confirmation page; the POST (with its CSRF token) ends the session. |
| `GET /.well-known/jwks.json` | Keys that verify `X-Auth-Token`. |
| `GET /healthz` | Liveness. |

Admin listener (`WICKET_ADMIN_ADDR`, default `127.0.0.1:4181`; bearer token
required when `WICKET_ADMIN_TOKEN` is set):

| Endpoint | Purpose |
|---|---|
| `GET /admin/sessions[?subject=&limit=]` | List live sessions. |
| `DELETE /admin/sessions/{id}` | Revoke one session. |
| `POST /admin/sessions/revoke` `{"subject","provider"}` | Revoke all of a user's sessions. |
| `POST /admin/reload` | Reload the config file; on any error the running one stays (also on `SIGHUP`). |
| `GET /metrics` | Prometheus metrics. |

Errors are `{"error":{"code":"...","message":"...","request_id":"..."}}`.
Browser-facing failures render a page with the request ID instead; the
details go only to the audit log.

## What the tests cover

| What | How |
|---|---|
| End to end | wicket and fakeidp over real TLS listeners: OIDC and SAML logins (signed, encrypted, signed requests), forward-auth in nginx, Traefik and Envoy modes, 403, logout, admin revocation, reload, rate limiting. The demo repeats this through a real nginx in Docker. |
| Golden transcripts | Every byte the gateway sends on those paths (status, headers, cookie attributes, pages) is pinned in [internal/authn/golden/e2e/testdata/golden](../internal/authn/golden/e2e/testdata/golden), recorded from wicket before it became `authz gateway`. CI replays them in process and through `authz gateway` started from `WICKET_*` variables and a wicket config file; any difference fails with a line diff. |
| Attacks | Table-driven suites, one case per known attack and the exact rejection reason it must produce (listed below). |
| SAML integrity | Property test: random structural mutations of signed responses (delete, duplicate or move any element, edit text or attributes). Many are still accepted, but never with an identity other than the one the IdP signed. |
| Policy | Property test against an independent, deliberately naive reference evaluator on 50,000 random rules and identities. Deliberately broken evaluators fail it. |
| Return URLs | Property test that every accepted URL, read the way a browser reads it, stays on an allowed host (checked by an independent matcher), and that validation is idempotent. |
| JWT and cookies | Property tests: signed tokens round-trip; any single-character change to a token, or any bit flip in a sealed cookie, is rejected. |
| Session log | Truncated at every byte offset: recovery yields exactly the complete records. Damage mid-file stops startup; write failures are injected and a failed repair blocks further writes. |
| Parsers | Go fuzzing of the JWS parser, JWK sets, the cookie codec, the return-URL validator, SAML responses and metadata. |
| Concurrency | The whole suite runs under the race detector. Coverage is 93% of statements. |

Each attack in the suites must be rejected, with a specific reason.

On the JWT and OpenID Connect side that means `alg: none` (even when listed),
HS256 signed with the RSA public key (key confusion), an RSA token checked
with an EC key and vice versa, a P-384 token on a P-256 key, a key pinned to
another algorithm, an encryption key, a token signed by an unknown key or
naming an unknown kid, wrong `aud`, an extra untrusted audience, wrong `azp`,
wrong `iss`, expired, not yet valid, issued in the future or too long ago, a
nonce replayed from another login or missing, an access token
(`typ: at+jwt`) passed as an ID token, an `at_hash` mismatch, a userinfo
response for another user, and discovery metadata claiming another issuer or
downgrading to plain HTTP or no PKCE.

The login flow is attacked with login CSRF (a callback or SAML POST into a
browser that never started the login), a swapped authorization code (PKCE
binds it to the other browser's verifier), a replayed callback or SAML POST,
a tampered state, an expired login and IdP-initiated SAML responses.

SAML signatures face eight XML signature wrapping variants (an evil assertion
beside the signed one, the signed assertion hidden in Extensions or in the
evil assertion's Advice, an evil assertion reusing the signed ID, a Reference
to another element, an extra Reference, a signed Response nested inside an
evil one, with and without a top-level assertion), two signatures on one
element, a stripped signature, content changed after signing, a self-signed
attacker certificate, RSA-SHA1, the comment in NameID truncation trick
(CVE-2017-11427 class), DOCTYPE and entities, and processing instructions.

SAML conditions are covered by assertion replay (also across a configuration
reload), wrong Destination, Recipient and Audience, a second
AudienceRestriction that excludes us, InResponseTo for another request (on
the Response and on the confirmation), wrong Issuer, expired or not-yet-valid
assertions, bearer confirmations with NotBefore or without an expiry, and
markup inside attribute values. SAML encryption is covered by AES-CBC outside
a signed Response (padding oracle), RSA PKCS#1 v1.5 key transport, tampered
GCM ciphertext and malformed EncryptedData.

About thirty open-redirect forms are tried against return URLs, including
`//host`, backslashes, user info, `@` after `#` or `?`, look-alike suffixes
and prefixes, percent-encoded hosts, control characters and other schemes.
Cookies are tested tampered, sealed for another purpose, sealed with an
unknown key, sealed with a rotated-out key, as a valid seal around an unknown
session, with idle- and absolute-expired sessions, with a forged logout token
(which must not even clear the cookie), and with cross-origin logout.

```console
$ go test -race ./internal/authn/... ./cmd/authz/...   # from the repository root
$ go test -run=^$ -bench=. ./internal/authn/...
```

## Benchmarks

Apple M4 Max, Go 1.27:

| Operation | Time |
|---|---|
| Forward-auth decision (`/auth`, valid session, allowed, cached token) | 3.4 µs |
| Same, all 16 cores in parallel | 1.1 µs per decision (about 900,000/s) |
| Session lookup | 0.14 µs |
| Open a sealed cookie (AES-256-GCM) | 0.48 µs (seal and open) |
| Policy check, user in 151 groups | 0.97 µs |
| Return-URL validation | 0.30 µs |
| Verify an RS256 ID token, all claims | 32 µs |
| Sign an upstream ES256 token | 17 µs (reused until half its lifetime) |
| Validate a signed SAML response | 200 µs |
| Create a persisted session (fsync) | 4 ms (disk-bound) |

The hot path is the forward-auth decision, which never does network I/O or
public-key cryptography once a session's upstream token is cached.

## Where the code lives

The reasoning behind the code is in [docs/DESIGN.md](docs/DESIGN.md): the
request flows, the SAML verification order and why it defeats signature
wrapping, the session store and its log, key rotation, failure modes, limits,
the threat model and what would change to run many replicas. Proxy
configurations are in [docs/proxies.md](../docs/proxies.md).

```text
cmd/authz/internal/gateway  authz gateway: entry point, environment configuration and check
cmd/authz/internal/fakeidp  authz fakeidp: test identity provider (OIDC + SAML) and demo certificates
internal/authn/server     forward-auth, login, logout, admin API, rate limiting, audit
internal/authn/oidc       OpenID Connect relying party: discovery, PKCE, ID tokens, JWKS cache
internal/authn/saml       SAML service provider: requests, metadata, response validation, decryption
internal/platform/jose    JWS/JWK/JWT verification and ES256 signing (shared with authz mcp)
internal/authn/session    server-side sessions and their append-only log
internal/platform/seal    AES-256-GCM cookie sealing with key rotation
internal/authn/policy     per-app access rules
internal/authn/redirect   return-URL validation
internal/authn/config     JSON configuration: schema and semantic checks with JSON paths
internal/authn/check      offline file checks and online provider checks behind authz gateway check
internal/authn/keyfile    SP keys, certificates and CA bundles from PEM files
internal/authn/fakeidp    the test identity provider
internal/authn/metrics    Prometheus text exposition
internal/authn/golden     normalised HTTP transcripts compared with golden files
internal/authn/golden/e2e the end-to-end golden scenarios and their transcripts
examples (wicket/), examples/whoami  demo script, nginx config, demo configs, a verifying upstream app
docs (wicket/)            design notes and proxy configurations
```

## License

MIT
