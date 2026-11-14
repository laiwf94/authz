# wicket design

A request should reach an app only for a user who completed a login with an
identity provider the app accepts, and only as that user. wicket makes every
check the OpenID Connect and SAML specifications require of a relying party,
and the app needs no authentication code of its own: it trusts the proxy, or
better, verifies a short-lived token with a public key.

Unsafe choices are not configurable. There is no way to accept `alg: none`,
HMAC-signed ID tokens, SHA-1 XML signatures, unsigned SAML assertions,
IdP-initiated SAML, plain-HTTP identity providers or open redirects. Every
input is bounded in size, count and time, and the per-request path does no
network I/O and no public-key operation. Operating it means one binary, one
JSON file for providers and apps, environment variables for secrets, atomic
reload and an audit log.

This version does not run as several replicas sharing sessions (see
[Several replicas](#several-replicas)), and it leaves out SAML Single Logout,
IdP-initiated SAML, bearer-token (API key) authentication, and acting as an
identity provider.

## Request flows

### Forward-auth

```text
browser ──GET /page──▶ proxy ──GET /auth (headers, cookie)──▶ wicket
                         ◀── 200 + X-Auth-* ── (signed in and allowed)
                         ◀── 401 + X-Auth-Redirect ── (not signed in)
                         ◀── 403 ── (signed in, not allowed)
```

wicket rebuilds the original URL from `X-Original-URL`, or
`X-Forwarded-Proto/-Host/-Uri` (nginx, Traefik), or the `/auth/envoy/` path
suffix and `Host` (Envoy). It picks the app by `?app=` or by host, opens the
session cookie, looks up the session, and evaluates the app's policy.

The 401 carries the login URL, with the original URL as the return address
if it passes the redirect check. nginx's `auth_request` can only act on 401,
so nginx turns it into a redirect itself. Traefik and Envoy pass the auth
server's answer to the client, so with `?redirect=1` (always on the Envoy
endpoint) wicket answers browser page loads with a 302. "Browser page load"
means GET or HEAD, `Accept` containing `text/html`, and no
`X-Requested-With`; anything else gets a 401 JSON error, because redirecting
an API call to an HTML login page helps no one.

An unknown host gets 403: deny by default, including for configuration
mistakes.

### OpenID Connect login (Core 1.0, RFC 6749, RFC 7636, RFC 9700)

1. `GET /login`: wicket draws a random `state`, `nonce` and PKCE
   `code_verifier` (32 bytes each), seals them with the app, provider, return
   URL and a 10-minute expiry into a cookie named after a hash of the state,
   and redirects to the authorization endpoint with `code_challenge`
   (S256).
2. `GET /callback/{provider}`: the cookie named by the returned `state` must
   exist (login CSRF otherwise), open, match the state in constant time, be
   for this provider, be unexpired, and not have been used before (a
   bounded set of consumed states). The cookie is cleared immediately.
3. The code is redeemed at the token endpoint with the verifier and client
   authentication (`client_secret_basic`, `client_secret_post`, or none). A
   stolen or swapped code is useless without the verifier, which never left
   the browser's sealed cookie.
4. The ID token is validated as Core section 3.1.3.7 requires: algorithm in
   the provider's allow-list, signature with a key from the provider's JWKS
   that fits that algorithm, `iss` exactly, `aud` containing the client id
   and no untrusted extra audience, `azp` when present (and required with
   several audiences), `exp`, `nbf` and `iat` with bounded skew, `iat` at
   most 10 minutes old, `nonce` in constant time, `sub` 1-255 printable
   ASCII, `at_hash` when present. A `typ` other than `JWT` is refused so an
   access token can't pass as an ID token (RFC 8725 section 3.11).
5. Optionally userinfo is fetched; its `sub` must equal the ID token's
   (Core section 5.3.2) before its claims fill gaps.

An email the provider marks `email_verified: false` is dropped before policy
evaluation, so an unverified address can't match an `emails` rule.

### SAML login (SAML 2.0 Core, Bindings, Profiles)

1. `GET /login`: wicket creates an AuthnRequest with a random ID and sends
   it over HTTP-Redirect (deflate, base64, optional RSA-SHA256 query
   signature over the exact parameter string, Bindings section 3.4.4.1). The
   request ID and a random RelayState are sealed into a cookie as above.
2. `POST /saml/{provider}/acs`: the IdP's form POST is cross-site, so this
   cookie is `SameSite=None` (still Secure, HttpOnly, sealed, single-use,
   10 minutes). The RelayState selects the cookie; the response must answer
   exactly the request ID inside it.

Validation order matters; it is the core of the defense against XML
signature wrapping:

1. Base64-decode within a size limit; parse after a token-level scan that
   rejects DOCTYPE (no entities, external or internal), comments,
   processing instructions, more than 48 levels of nesting and more than
   50,000 tokens.
2. Count `Assertion` and `EncryptedAssertion` elements **anywhere** in the
   document. Anything but exactly one is rejected. This alone defeats the
   classic wrapping layouts, which need a second assertion somewhere (in
   `Extensions`, `ds:Object`, `Advice`, a nested Response).
3. If the Response has a signature as a direct child, verify it (below) and
   **replace the Response with the element rebuilt from the signed bytes**.
   From here on, nothing from the original tree is read.
4. Check Status (Success), Destination (required when the Response is
   signed, Profiles 4.1.4.5), InResponseTo when present, and Issuer.
5. Take the single assertion, which must be a direct child; decrypt it if
   it is an `EncryptedAssertion`.
6. If the assertion has its own signature, verify it and again continue
   only with the rebuilt, signed element.
7. Require that at least one of the two signatures was present.
8. Check the assertion: Issuer, Conditions time window, every
   `AudienceRestriction` contains our entity id (Core 2.5.1.4), a bearer
   `SubjectConfirmation` whose data has our ACS as Recipient, our request ID
   as InResponseTo, no NotBefore, and an unexpired NotOnOrAfter at most
   24 hours away (Profiles 4.1.4.2), exactly one AuthnStatement.
9. Claim the assertion ID in the replay cache until it expires.
10. Read NameID and attributes. Every value must be plain text: an element
    with child elements is refused, and split character data (text, CDATA,
    text) is joined so no part can be dropped.

Signature verification is delegated to goxmldsig, but only after wicket
holds the signature to a narrow shape: the `ds:Signature` is a direct child
of the element it signs, there is exactly one, it has exactly one
`Reference`, the Reference URI is `#` plus the element's own ID, that ID
appears exactly once in the whole document, the only transforms are
enveloped-signature and exclusive canonicalization without comments, and
the signature and digest algorithms are SHA-256 or stronger. The certificate
must be one from the IdP's metadata and currently within its validity
period; a certificate in the message's `KeyInfo` is only used if it is
byte-for-byte one of those.

These checks follow the attack catalogue in Somorovsky, Mayer, Schwenk,
Kampmann and Jensen, ["On Breaking SAML: Be Whoever You Want to Be"][xsw],
and the earlier McIntosh and Austel, ["XML Signature Element Wrapping
Attacks and Countermeasures"][mcintosh]. Their central observation: wrapping
works whenever the code that verifies the signature and the code that reads
the data can be made to look at different elements. Using only the rebuilt
signed element closes that gap; the shape checks and the assertion count
close it a second time, so neither defense depends on the other. The test
suite has one case per layout; the mutation property test checks the general
claim.

Comments are rejected outright because of the truncation attack (CVE-2017-11427
and related): exclusive canonicalization without comments ignores
`<!---->`, so `alice@example.com<!---->.evil.com` verifies as signed, and a
parser that returns only the first text node reads `alice@example.com`.
No legitimate IdP needs comments in a response.

Encrypted assertions follow XML Encryption 1.1. The content key is
transported with RSA-OAEP (`rsa-oaep-mgf1p` or `xenc11#rsa-oaep`,
SHA-1/256/512 digests and MGF1 variants); RSA PKCS#1 v1.5 key transport is
refused because of Bleichenbacher-style oracles. Content is AES-128/256-GCM,
or AES-128/256-CBC **only when the Response signature has already been
verified**, since that signature covers the ciphertext. Decrypting
unauthenticated CBC ciphertext is the padding oracle in Jager and
Somorovsky, ["How to Break XML Encryption"][xmlenc]; with the rule, an
attacker can't submit chosen ciphertext at all. Every failure after the
algorithm checks returns the same error.

### Sessions and cookies

After a successful login the previous session (if any) is revoked and a new
one created, so a session id never survives a login (session fixation). The
browser receives:

```text
__Host-wicket = base64url( 0x01 | key id (4) | nonce (12) | AES-256-GCM(session secret) | tag )
                additional data: 0x01 | key id | purpose ("session")
```

The plaintext is a random 256-bit secret. The server stores sessions under
`hex(SHA-256(secret))[:32]`, the public session id used in logs and the admin
API. Neither the log file nor the admin API holds anything that could be
replayed as a cookie, and stealing the cookie-sealing keys alone does not
give access to any session.

The purpose in the additional data means a value sealed for one use (a login
state, a logout CSRF token) can never be presented as another. Key ids are
derived from the keys, so rotation is: put the new key first in
`WICKET_COOKIE_KEYS` (it seals; all keys open), wait for the absolute
session timeout, remove the old key. Random 96-bit GCM nonces bound one key
to about 2^32 seals before the collision risk matters; rotating keys
periodically keeps far below that.

Cookies are `Secure; HttpOnly; SameSite=Lax; Path=/` with the `__Host-`
prefix, which also forbids a `Domain`. With `cookie_domain` set (single
sign-on across subdomains), the session cookie becomes `__Secure-wicket`
with that domain; login-state cookies always stay `__Host-`.

### Session store

Sessions are in memory: a map by id and an index by (provider, subject).
Each session has an idle timeout (refreshed on every `/auth`) and an
absolute expiry, capped further by SAML `SessionNotOnOrAfter`. A user keeps
at most 20 sessions (the oldest are revoked); the store holds at most
100,000 and refuses new logins beyond that rather than evicting live users.

With `WICKET_SESSION_FILE`, every change is appended to a log, one line per
record, framed like a write-ahead log:

```text
<crc32c of the JSON, 8 hex digits> <JSON record>\n
records: {"op":"create","session":{...}}  {"op":"touch","id":...,"t":...}  {"op":"revoke","id":...}
```

- Creates and revocations are fsynced before the request completes. A
  revocation is applied in memory first, so it takes effect even if the disk
  fails; the admin API then reports that it may not survive a restart.
- Touches (idle-timer refreshes) are written at most once a minute per
  session and not fsynced. A lost touch only makes a session expire earlier
  after a crash, never later.
- On start the log is replayed. A torn last line is a write that never
  completed and is dropped; a bad line anywhere else is damage, and startup
  stops instead of guessing. The live sessions are then written to a
  temporary file, fsynced and renamed over the log. The periodic sweep
  compacts it the same way once it holds more than twice as many records as
  live sessions, plus 1,024.
- If a failed append can't be truncated away, the log refuses all further
  writes instead of appending after garbage.

The test suite cuts the log at every byte offset and checks that recovery
returns exactly the sessions whose records are complete.

One mutex guards the store, which is a trade-off. A lookup is a map access
plus a timestamp update, about 140 ns, and the parallel forward-auth
benchmark still reaches roughly 900,000 decisions per second on 16 cores.
Sharding is easy if a deployment ever needs more.

### Revalidation

Without revalidation a session lives until it expires even after the user
is disabled at the provider. With `"revalidate": {"interval": "5m"}` on an
OpenID provider the gateway asks the provider about every session at that
interval, with the session's refresh token (RFC 6749 section 6):

- At login the refresh token is sealed with the session key ring (purpose
  `refresh`) around a 16-byte hash of the provider and subject, and stored
  with the session; providers without `revalidate` get no token stored. The
  session log carries it on the create record and on a `revalidate` record
  (`{"op":"revalidate","id":...,"t":...,"refresh":...}`) when the provider
  rotates it. A rotated token is fsynced before the pass moves on, since the
  provider may already refuse the old one; a confirmation without rotation
  is not, because losing it only makes the session due again sooner.
  Compaction keeps the latest token and confirmation time. The token is not
  in `GET /admin/sessions`, and no log line or error carries it.
- Every 10 seconds a pass takes, per provider and oldest confirmation
  first, up to 2,000 sessions last confirmed an interval ago, and redeems
  their tokens with 8 requests in flight at most. Passes never overlap and
  stop after 2 minutes; whatever is left goes in the next one.
- `invalid_grant` is the provider saying no: the session ends at once and
  `authn.session_ended` is audited with reason `refresh_refused`. So is a
  new ID token for another subject (OpenID Connect Core 12.2: same issuer,
  audience, signature and subject; no nonce is expected).
- Anything else is no answer: the provider down, a 5xx, a timeout, a
  client error such as `invalid_client`, a bad ID token, or a session with
  no usable token (the provider issued none, or it no longer opens). With
  `on_failure` `end` (the default) the session ends with reason
  `refresh_failed` (or `no_refresh_token`, `refresh_token_unreadable`). With
  `grace` it is kept, retried every pass, and ended once `interval + grace`
  has passed since its last confirmation.

Refresh tokens longer than 3,000 bytes or with characters outside printable
ASCII are not kept (the sealed value must fit seal's 4,096-byte limit); such
a session follows `on_failure` at its first revalidation, and the login
logs a warning. Some providers issue refresh tokens only for the
`offline_access` scope; add it to `scopes` for them.

### JWKS cache

Keys are fetched from the discovered `jwks_uri` on first use and cached for
the response's `max-age`, clamped to 5 minutes - 24 hours (1 hour without
one). A token whose `kid` is unknown triggers one re-fetch, because
providers rotate keys, but at most once a minute: a stream of tokens with
invented kids can't turn wicket into a request amplifier. If a refresh fails,
the previous keys keep working; the first fetch failing is an error. A token
without `kid` is accepted only when exactly one cached key fits its
algorithm. Discovery metadata is cached for an hour, with failures
remembered for 30 seconds.

Back-channel requests (discovery, token, JWKS, userinfo, SAML metadata) use
a 10-second timeout, a 1 MiB response limit, TLS 1.2+, and never follow
redirects: the client secret and access token are only ever sent to the
endpoint they were meant for. Endpoints must be https, and the discovery
document's `issuer` must equal the configured issuer (Discovery 1.0
section 4.3), so a provider can't redirect wicket's credentials elsewhere.
`ca_file` pins a provider to a private CA instead of the system roots.

### Identity for upstreams

On success, wicket returns:

| Header | Value |
|---|---|
| `X-Auth-User` | the subject (`sub` or NameID) |
| `X-Auth-Email` | the verified email, lower-cased |
| `X-Auth-Groups` | groups, comma-separated |
| `X-Auth-Provider` | the identity provider id |
| `X-Auth-Token` | ES256 JWT: `iss` (public URL), `aud` (app id), `sub`, `email`, `name`, `groups`, `idp`, `sid`, `iat`, `nbf`, `exp` |

Header values percent-encode everything outside printable ASCII, and `%`
and `,`, so a group name can't add a group or break a header.

Headers alone are not enough, because a header is just text. Any client
that can reach the app without passing through the proxy (another service
on the same network, a misrouted path, a second proxy rule without
forward-auth) can send `X-Auth-User: admin`. Even through the proxy, a
configuration that forgets to strip client copies passes them on. The
proxy configurations in [docs/proxies.md](../../docs/proxies.md) always overwrite or remove
the headers. The token closes the remaining gap: an app that verifies it
against `/.well-known/jwks.json` (signature, `iss`, its own `aud`, `exp`)
accepts identity only from wicket. `aud` is the app id, so a token captured
from one app is useless at another. Subjects are only unique per provider,
so apps should key users by `idp` and `sub` together.

Tokens live 2 minutes by default (`upstream_token_ttl`, 10 seconds to 15
minutes, never past the session) and are reused until half their lifetime
has passed, so signing stays off the hot path. Revoking a session stops new
tokens immediately; an already-issued token stays valid until it expires,
which is why the lifetime is short. Signing keys are P-256; the `kid` is the
key's RFC 7638 thumbprint, so it is stable without configuration. Several
keys can be published (`WICKET_SIGNING_KEYS`, the first signs) for
rotation.

### Return URLs

A return URL must be absolute https (or a path starting with a single `/`,
resolved against the public URL), with no user info, a host on the
allow-list (app hosts, the public URL host, `redirect_hosts`, where `*.domain`
needs at least one extra label and a port-less entry means 443), and no
backslash, whitespace, control character or percent-encoded host. wicket
returns Go's re-serialization of the parsed URL, never the input string, so
the browser follows exactly what was checked. These are the techniques
RFC 9700 section 4.11 and the OAuth threat literature list for open
redirectors.

### Logout

`GET /logout` shows a confirmation page whose form carries a token sealed
with the "logout" purpose around the session id. `POST /logout` needs that
token for the current session; a browser that sends `Origin` must be on the
gateway's origin. Nothing is cleared until the token checks out, so a forged
POST can't even sign the browser out. The session is revoked server-side;
for OpenID Connect providers with an `end_session_endpoint` the browser then
continues there (RP-Initiated Logout 1.0, with `client_id` and an optional
registered `post_logout_redirect_uri`). SAML sessions end locally: SAML
Single Logout is out of scope.

### Configuration and reload

Providers and apps come from one JSON file, decoded strictly and validated
as a whole: ids, https URLs, durations within limits, hosts unique across
apps, every app's providers defined, secrets present. Secrets are never in
the file; `client_secret_env` or `client_secret_file` name where they are.

Validation collects every problem instead of stopping at the first, and
each one carries a JSON path (`$.apps[1].hosts[0]`) and a line and column.
It runs in two passes. The schema pass walks the token stream against the
`Config` type, so it can report what `encoding/json` hides or reports
without a location: unknown fields (with a suggestion for a near miss),
duplicate keys, field names in the wrong case (which `encoding/json` would
silently accept), wrong types, bad durations, trailing data. It drops
those values and hands the rest to the semantic pass, which checks the
meaning: provider references, hosts that overlap once `host` and
`host:443` are seen as the same origin, host syntax exactly as the return
URL validator parses it, each app's `default_url` against the same
validator a login's `rd` goes through, client authentication against the
secret, scopes and algorithms. Things that are allowed but probably wrong
(an unused provider, an app with no allow rule, a provider listed twice)
are warnings and never stop a load.

Startup, reload and `wicket check` share that code, so the checker can't
pass a file the gateway would refuse. `wicket check` adds what startup only
finds when it builds the runtime: it reads the CA bundles, SP keys and
certificates (key size, the certificate matching the key, expiry) and SAML
metadata files, and with `-online` it fetches each provider's discovery
document and signing keys (at least one must fit the allowed algorithms)
and SAML metadata URL, with a time limit per provider and the providers
checked in parallel.

A reload (`SIGHUP` or `POST /admin/reload`) builds a complete new runtime
(provider clients, SAML metadata, compiled policies, redirect allow-list)
and swaps one pointer. Requests in flight finish with the old one. Any error
keeps the old configuration and is audited. Sessions survive reloads; a
session from a provider an app no longer accepts is simply denied by the
policy. The SAML replay cache and the consumed-state set live outside the
runtime, so a reload doesn't reopen a replay window.

### Policy

An app accepts a list of providers and allows a user when both the
session's provider is accepted and one of: `any_user`, an exact email
(case-insensitive), the email's domain (exact, so `sub.example.com` doesn't
match `example.com`), or a group (exact, case-sensitive, because groups are
identifiers). An app with no allow rules allows nobody. Rules compile to
hash sets, so evaluation is linear in the user's groups.

### Rate limiting and client addresses

Login, callback, ACS and logout share a token bucket per client address
(30 per minute by default). The client address is the TCP peer unless the
peer is in `WICKET_TRUSTED_PROXIES`, in which case `X-Forwarded-For` is read
right to left past trusted hops; a client can't pick its own rate-limit key
by sending the header. The bucket map is bounded (idle buckets are dropped
first). A clock that steps backwards does not drain buckets. `/auth` is not
rate limited: it is called by the proxy for every request and does no
expensive work.

## Failure modes

| Failure | Behavior |
|---|---|
| Identity provider down | New logins fail with a 502 page and an audit reason (`discovery_failed`, `token_exchange_failed`, `jwks_failed`). Existing sessions are unaffected: `/auth` never calls the provider. With `revalidate`, sessions due for revalidation end (`on_failure` `end`) or live on for the grace (`grace`). Cached metadata and keys keep working while they are fresh, and stale ones keep working if a refresh fails. |
| Provider rotates keys | The first token with the new `kid` triggers a re-fetch. |
| Disk full or failing | Logins fail cleanly (503); revocations take effect in memory and the admin API says they were not saved. A log that can't be repaired refuses writes until restart. |
| Crash or `kill -9` | Sessions and revocations that were acknowledged are recovered; a torn last record is dropped. Idle timers may be up to a minute older. |
| Bad configuration on reload | Refused; the running configuration stays; `config_load_failed` is audited. |
| Session store full | New logins get 503 (`session_store_full`); existing users are not evicted. |
| Replay or consumed-state set full | Fails closed: the login is refused rather than forgetting what was used. Filling either needs valid IdP logins or many client addresses past the rate limit; see Limits. |
| Clock skew | `clock_skew` (default 2 minutes, at most 10) applies to every time comparison. |
| Proxy misrouting headers | The upstream token still has to verify; header-only apps are exposed, which is why the proxy configurations strip them. |

## Limits

| Limit | Value | Why |
|---|---|---|
| Config file | 1 MiB, 64 providers, 1,024 apps, 10,000 allow entries per app | Bounds startup and reload work. |
| Login lifetime | 10 minutes; 5 pending logins per browser | Bounds the window for a stolen state cookie; stops a page from filling the cookie jar and evicting the session cookie. |
| Consumed login states | 100,000 | Single-use states; fails closed. |
| Session timeouts | idle 8 h, absolute 24 h (defaults; absolute at most 30 days) | Configurable per deployment. |
| Sessions | 100,000 total, 20 per user | Memory bound; per-user cap limits a stolen-credential spree. |
| Session log record | 64 KiB | Replay never buffers unbounded lines. |
| Cookie value | 4,096 bytes; 16 keys in the ring | Browser limits; rotation needs few keys. |
| JWS | 64 KiB, asymmetric algorithms only | |
| JWK set | 1 MiB, 100 keys, RSA 2,048-8,192 bits | Bounds parse cost. |
| ID token age | `iat` at most 10 minutes old | Tokens come straight from the token endpoint. |
| Subject / groups | `sub` 255 ASCII bytes; 256 groups of 256 bytes | Header and token size. |
| SAML response | 256 KiB XML, 48 levels, 50,000 tokens; ACS form 512 KiB | Bounds parse cost. |
| SAML values | NameID and attribute values 512 bytes; 256 values per attribute | |
| SAML confirmation | NotOnOrAfter at most 24 hours ahead | Bounds replay-cache retention. |
| Replay cache | 100,000 assertion IDs | Fails closed when full. |
| Back-channel calls | 10 s each, 1 MiB responses, 25 s per callback | |
| Revalidation | interval 30 s - 24 h, grace at most 24 h; 2,000 sessions per provider per pass, 8 requests in flight, 2 min per pass; refresh tokens 3,000 bytes | Bounds the load on the provider and the session record. |
| Upstream token | 10 s - 15 min (default 2 min); 100,000 cached | |
| Login rate | 30 per minute per client address (default) | |
| HTTP server | 32 KiB headers, 15 s read, 45 s write | |
| Admin API | 64 KiB JSON bodies, 1,000 sessions per listing | |

## Threat model and hardening

Attackers may control browsers (their own and, through links and pages, the
requests a victim's browser makes), send arbitrary traffic to every public
endpoint, hold valid accounts at an identity provider, capture messages that
pass through browsers (authorization codes, SAML responses), and reach
upstream apps directly. They do not control the identity providers' signing
keys, the gateway's host, or TLS.

Beyond the protocol checks above, client secrets come from the environment or
files and cookie keys from the environment, and nothing secret is logged.
Provider error messages are truncated to printable text before logging, and
errors shown to browsers carry only a request id. State, nonce, `at_hash`,
logout tokens and the admin token are compared in constant time (the admin
token as SHA-256 digests).

The admin API is on a separate listener, loopback-only unless
`WICKET_ADMIN_TOKEN` (at least 16 characters) is set; wicket refuses to start
with a non-loopback admin address and no token. Metrics are there too, since
session counts are operational data.

wicket's few HTML pages use `html/template` and a Content-Security-Policy of
`default-src 'none'` with the one stylesheet allowed by hash,
`frame-ancestors 'none'`, and no scripts. Every response has
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and HSTS.

The audit log is one JSON line per event with `"audit":true`:
`login_succeeded`, `login_failed` (with a reason code such as
`state_cookie_missing`, `nonce_mismatch`, `signature_wrapping`,
`assertion_replayed`), `login_rejected`, `access_denied`, `logout`,
`logout_rejected`, `session_revoked`, `session_ended` (a session the
provider refused or could not vouch for at revalidation, with its reason),
`config_loaded`, `config_load_failed`.
Entries carry the request id, provider, subject, email, public session id and
client address. They contain personal data; the session log does too, and is
created with mode 0600.

### Dependencies

Two modules, both pinned: `github.com/russellhaering/goxmldsig` v1.6.1 for
XML signature verification and `github.com/beevik/etree` v1.8.1, the element
tree it works on (plus `github.com/jonboulle/clockwork`, which goxmldsig
uses for its clock). Everything else, including JOSE, OpenID Connect and XML
Encryption, is built on the standard library.

The exception is deliberate. Verifying an XML signature means implementing
Exclusive XML Canonicalization and the XML-DSig processing model, and
hand-written versions of exactly those have been a recurring source of
authentication bypasses in SAML libraries (the wrapping and comment-handling
attacks cited above were found in many independent implementations).
goxmldsig is small, focused, maintained, has a public security policy, and
returns the canonical signed bytes, which is what makes the "use only the
signed element" rule possible. wicket still does not rely on it alone: the
shape checks, the assertion count and the parser restrictions above stand
on their own. `govulncheck` runs in CI.

## Several replicas

Running more than one replica would change six things.

The in-memory map and log would be replaced by a session store all replicas
use, keyed by the hashed session id: Redis with TTLs, or a SQL table with an
expiry index. Revocation becomes a delete visible to all replicas.
Idle-timer touches should stay coarse (once a minute) to keep write load low.

The SAML replay cache and consumed login states need an atomic "insert if
absent with TTL" across replicas (Redis `SET NX PX`, or a unique-key insert).

All replicas need the same cookie keys and upstream signing keys; the
configuration already supports lists for rotation. Moving keys to a KMS would
remove them from the environment.

JWKS, discovery and upstream tokens stay per-replica caches; they are correct
without coordination.

Per-replica rate-limit buckets multiply the limit by the replica count, so a
shared limiter or the proxy's own limiter at the edge would take over.

With a shared store, accepting OIDC back-channel logout tokens and SAML
LogoutRequests becomes a lookup by provider session id, which would then need
storing. That would make SAML Single Logout and back-channel logout possible.

[xsw]: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
[mcintosh]: https://doi.org/10.1145/1103022.1103026
[xmlenc]: https://doi.org/10.1145/2046707.2046756
