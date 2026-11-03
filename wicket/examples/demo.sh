#!/usr/bin/env bash
# End-to-end demo: nginx (in Docker) in front of a tiny "whoami" app, with
# `authz gateway` (formerly wicket) as the auth_request backend and
# `authz fakeidp` as both an OpenID Connect provider and a SAML identity
# provider. curl plays the browser, keeping a cookie jar and posting the login
# forms. CI runs it after replaying the golden transcripts through the same
# binary (cmd/authz/internal/gateway, TestGoldenGateway).
#
# Needs: go, docker, curl, python3. Uses ports 4180, 4181, 8081, 8443, 9443.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE="$(cd "$ROOT/.." && pwd)" # the Go module root, which builds the binaries
WORK="$(mktemp -d)"
NGINX_IMAGE="nginx:1.27.3-alpine"
export DEMO_CLIENT_SECRET="demo-client-secret-0123456789"
APP="https://localhost:8443"
PIDS=()

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  docker rm -f wicket-demo-nginx >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
ok() { printf '   ok: %s\n' "$*"; }
fail() { printf '   FAILED: %s\n' "$*"; exit 1; }

# curl as a browser: one cookie jar per user, never follows redirects.
browse() { # jar, curl args...
  local jar="$WORK/$1.jar"; shift
  curl -sS --cacert "$WORK/certs/ca.pem" -b "$jar" -c "$jar" -H 'Accept: text/html' "$@"
}
status_of() { browse "$1" -o /dev/null -w '%{http_code}' "${@:2}"; }
location_of() { browse "$1" -o /dev/null -w '%{redirect_url}' "${@:2}"; }

# form FILE: print the form action, then key=value lines (URL-encoded).
form() {
  python3 - "$1" <<'PY'
import html, re, sys, urllib.parse
body = open(sys.argv[1]).read()
action = re.search(r'<form method="post" action="([^"]+)"', body).group(1)
print(html.unescape(action))
for k, v in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)">', body):
    print(urllib.parse.quote(html.unescape(k)) + "=" + urllib.parse.quote(html.unescape(v), safe=""))
PY
}

# submit_login JAR LOGIN_FORM_URL USER PASS: fill in the IdP's login form.
submit_login() {
  local jar=$1 url=$2 user=$3 pass=$4
  browse "$jar" -o "$WORK/page.html" "$url"
  local f=() line
  while IFS= read -r line; do f+=("$line"); done < <(form "$WORK/page.html")
  local data="username=$user&password=$pass"
  for kv in "${f[@]:1}"; do data="$data&$kv"; done
  browse "$jar" -o "$WORK/page.html" -w '%{http_code} %{redirect_url}\n' -X POST --data "$data" "${f[0]}"
}

wait_for() { # url
  for _ in $(seq 1 50); do
    curl -sk -o /dev/null "$1" && return 0
    sleep 0.2
  done
  fail "timed out waiting for $1"
}

step "Build authz (gateway and fakeidp) and whoami; generate a throwaway CA and keys"
(cd "$MODULE" && go build -o "$WORK/bin/" ./cmd/authz ./examples/whoami)
"$WORK/bin/authz" fakeidp gencert -dir "$WORK/certs" -hosts localhost,127.0.0.1,host.docker.internal
chmod 644 "$WORK/certs/tls.pem" "$WORK/certs/tls-key.pem" # readable by nginx in the container
cp "$ROOT/examples/wicket.json" "$ROOT/examples/fakeidp.json" "$WORK/"
ok "binaries in $WORK/bin"

step "Start fakeidp (OIDC + SAML), whoami, authz gateway, and nginx in Docker"
cd "$WORK"
"$WORK/bin/authz" fakeidp -config fakeidp.json -addr 127.0.0.1:9443 -tls-cert certs/tls.pem -tls-key certs/tls-key.pem 2>"$WORK/fakeidp.log" &
PIDS+=($!)
wait_for https://localhost:9443/healthz
WHOAMI_ADDR=0.0.0.0:8081 WHOAMI_ISSUER="$APP/_wicket" "$WORK/bin/whoami" 2>"$WORK/whoami.log" &
PIDS+=($!)
COOKIE_KEY="$("$WORK/bin/authz" gateway genkey)"
"$WORK/bin/authz" gateway gensigningkey >"$WORK/signing.pem"
WICKET_CONFIG=wicket.json WICKET_COOKIE_KEYS="$COOKIE_KEY" WICKET_ADDR=0.0.0.0:4180 \
  WICKET_SESSION_FILE="$WORK/sessions.log" WICKET_SIGNING_KEYS="$WORK/signing.pem" \
  WICKET_TRUSTED_PROXIES=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
  "$WORK/bin/authz" gateway >"$WORK/wicket.log" 2>&1 &
PIDS+=($!)
wait_for http://127.0.0.1:4180/healthz
docker run -d --name wicket-demo-nginx --add-host host.docker.internal:host-gateway -p 8443:8443 \
  -v "$ROOT/examples/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$WORK/certs:/etc/nginx/certs:ro" "$NGINX_IMAGE" >/dev/null
wait_for "$APP/_wicket/healthz"
ok "nginx on $APP, the gateway on :4180 (admin on 127.0.0.1:4181), fakeidp on :9443"

step "1. Anonymous request: nginx asks the gateway, gets 401, redirects to the login page"
loc=$(location_of alice "$APP/hello?x=1")
[[ "$loc" == "$APP/_wicket/login?app=whoami&rd="* ]] || fail "expected a login redirect, got '$loc'"
ok "302 -> $loc"
browse alice -o "$WORK/page.html" "$loc"
grep -q "Corporate SSO" "$WORK/page.html" && grep -q "Partner (SAML)" "$WORK/page.html" || fail "no provider chooser"
ok "the login page offers both identity providers"

step "2. alice signs in with OpenID Connect (code flow + PKCE)"
auth=$(location_of alice "$loc&provider=corp")
[[ "$auth" == https://localhost:9443/authorize?* && "$auth" == *code_challenge_method=S256* ]] || fail "bad authorize URL"
read -r code cb < <(submit_login alice "$auth" alice alice-pass)
[[ "$code" == 302 ]] || fail "IdP login returned $code"
back=$(location_of alice "$cb")
[[ "$back" == "$APP/hello?x=1" ]] || fail "callback returned to '$back'"
ok "callback set the session cookie and returned to $back"
body=$(browse alice "$APP/hello?x=1")
echo "   whoami says: $body"
echo "$body" | grep -q '"sub":"alice"' || fail "whoami did not verify alice's token"
ok "the upstream verified the gateway's ES256 token (not just the headers)"

step "3. Spoofed identity headers get nowhere"
code=$(status_of mallory -H 'X-Auth-User: alice' -H 'X-Auth-Groups: eng' "$APP/hello")
[[ "$code" == 302 ]] || fail "spoofed headers through nginx: $code"
ok "through nginx: still sent to login ($code); nginx overwrites X-Auth-*"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Auth-User: alice' http://127.0.0.1:8081/hello)
[[ "$code" == 401 ]] || fail "spoofed headers straight to whoami: $code"
ok "straight to the app: 401, because there is no valid signed token"

step "4. bob signs in but is not in the 'eng' group: 403"
auth=$(location_of bob "$APP/_wicket/login?app=whoami&provider=corp")
read -r code cb < <(submit_login bob "$auth" bob bob-pass)
location_of bob "$cb" >/dev/null
code=$(status_of bob "$APP/hello")
[[ "$code" == 403 ]] || fail "bob got $code"
ok "bob is authenticated but forbidden ($code)"

step "5. carol signs in with SAML (signed AuthnRequest, signed + encrypted assertion)"
sso=$(location_of carol "$APP/_wicket/login?app=whoami&provider=partner")
[[ "$sso" == https://localhost:9443/saml/sso?SAMLRequest=* && "$sso" == *Signature=* ]] || fail "bad SSO URL"
read -r code _ < <(submit_login carol "$sso" carol carol-pass)
[[ "$code" == 200 ]] || fail "IdP SAML login returned $code"
f=(); while IFS= read -r line; do f+=("$line"); done < <(form "$WORK/page.html") # the IdP's auto-submitting POST form
data=$(IFS='&'; echo "${f[*]:1}")
read -r code back < <(browse carol -o /dev/null -w '%{http_code} %{redirect_url}\n' -X POST --data "$data" "${f[0]}")
[[ "$code" == 303 && "$back" == "$APP/" ]] || fail "ACS returned $code $back"
body=$(browse carol "$APP/")
echo "   whoami says: $body"
echo "$body" | grep -q '"idp":"partner"' || fail "carol's SAML identity not seen upstream"
ok "SAML login accepted at the ACS; carol reaches the app"
code=$(browse carol -o /dev/null -w '%{http_code}' -X POST --data "$data" "${f[0]}")
[[ "$code" == 400 ]] || fail "replayed SAMLResponse got $code"
ok "posting the same SAMLResponse again is refused ($code)"

step "6. The admin API lists sessions and revokes carol's"
curl -s http://127.0.0.1:4181/admin/sessions | python3 -c 'import json,sys; [print("   session", s["id"], s["identity"]["provider"], s["identity"]["sub"]) for s in json.load(sys.stdin)["sessions"]]'
revoked=$(curl -s -X POST -H 'Content-Type: application/json' -d '{"subject":"carol@partner.example"}' http://127.0.0.1:4181/admin/sessions/revoke)
echo "   $revoked"
code=$(status_of carol "$APP/")
[[ "$code" == 302 ]] || fail "revoked session got $code"
ok "carol's next request is sent back to login ($code)"

step "7. Sessions survive a crash: kill -9 the gateway and start it again"
{ kill -9 "${PIDS[2]}" && wait "${PIDS[2]}"; } 2>/dev/null || true
WICKET_CONFIG=wicket.json WICKET_COOKIE_KEYS="$COOKIE_KEY" WICKET_ADDR=0.0.0.0:4180 \
  WICKET_SESSION_FILE="$WORK/sessions.log" WICKET_SIGNING_KEYS="$WORK/signing.pem" \
  WICKET_TRUSTED_PROXIES=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
  "$WORK/bin/authz" gateway >>"$WORK/wicket.log" 2>&1 &
PIDS[2]=$!
wait_for http://127.0.0.1:4180/healthz
[[ "$(status_of alice "$APP/")" == 200 ]] || fail "alice lost her session"
[[ "$(status_of carol "$APP/")" == 302 ]] || fail "carol's revocation was lost"
ok "alice is still signed in; carol is still revoked"

step "8. alice signs out (POST with a CSRF token, then RP-initiated logout at the IdP)"
browse alice -o "$WORK/page.html" "$APP/_wicket/logout"
f=(); while IFS= read -r line; do f+=("$line"); done < <(form "$WORK/page.html")
data=$(IFS='&'; echo "${f[*]:1}")
idp_logout=$(browse alice -o /dev/null -w '%{redirect_url}' -X POST --data "$data" "${f[0]}")
[[ "$idp_logout" == https://localhost:9443/logout?* ]] || fail "expected the IdP end_session_endpoint, got $idp_logout"
final=$(location_of alice "$idp_logout")
ok "gateway -> IdP end-session -> $final"
[[ "$(status_of alice "$APP/")" == 302 ]] || fail "alice still signed in"
ok "alice's next request is sent back to login"

step "Audit log (from the gateway)"
grep '"audit":true' "$WORK/wicket.log" | python3 -c '
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    extra = " ".join(f"{k}={e[k]}" for k in ("reason", "provider", "sub", "app") if k in e)
    print("  ", e["event"], extra)'
printf '\nAll demo steps passed.\n'
