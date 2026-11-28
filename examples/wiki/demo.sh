#!/usr/bin/env bash
# A wiki behind the sign-on gateway, end to end through the built binary
# (#82): `authz run -parts serve,gateway` in one process, the fake IdP for
# OpenID Connect sign-ins, and curl playing both the browser and Traefik's
# ForwardAuth middleware (the request Traefik sends to /auth?redirect=1:
# X-Forwarded-Host, -Uri, -Method and -Proto, with the browser's cookie).
#
# The wiki (gateway.json) has public pages, a relationship rule for writing
# a page, an admin area that needs the admins group and a sign-in with a
# one-time code, and one admin action nobody may take:
#
#   /static, GET /pages     public
#   PUT, DELETE /pages/{id} edit on page:{id} in the authorization engine
#   /admin                  group admins, step-up to urn:fakeidp:acr:mfa
#   DELETE /admin/audit     denied
#   everything else         any signed-in user
#
# It loads wiki.schema and a few relationships with `authz ctl`, then checks
# every decision for a signed-out visitor, bob (no rights), carol (an editor
# through the eng group) and alice (the page's owner and an admin), alice's
# step-up from a password sign-in to one with her one-time code, and
# POST /admin/explain for the same requests, which must give the answer
# forward-auth gave, with the engine's trace for the relationship rule.
#
# Needs: go, curl, python3. Uses ports 4180, 4181, 8080 and 9443.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MODULE="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
GW=https://localhost:4180
ADMIN=https://localhost:4181
APP=https://localhost:8443
export WIKI_CLIENT_SECRET="wiki-client-secret-0123456789"
ADMIN_TOKEN="wiki-admin-token-0123456789"
API_KEY="wiki-api-key-0123456789"
PIDS=()

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
ok() { printf '   ok: %s\n' "$*"; }
fail() {
  printf '   FAILED: %s\n' "$*"
  printf '\n-- authz run log\n'; tail -n 30 "$WORK/run.log" || true
  exit 1
}

# json EXPR: evaluate a Python expression over the JSON on stdin (as j).
json() {
  python3 -I -c 'import json, sys
j = json.load(sys.stdin)
v = eval(sys.argv[1], {"j": j})
print(json.dumps(v) if isinstance(v, (bool, list, dict)) or v is None else v)' "$1"
}

# browse JAR curl-args...: curl with the user's cookie jar, never
# following redirects.
browse() {
  local jar="$WORK/$1.jar"; shift
  curl -sS --cacert "$WORK/certs/ca.pem" -b "$jar" -c "$jar" "$@"
}

# auth JAR METHOD PATH [curl args]: what Traefik asks the gateway for a
# request to the wiki. Sets CODE, LOCATION (the redirect, if any) and
# HEADERS (the file of response headers).
auth() {
  local jar=$1 method=$2 path=$3; shift 3
  HEADERS="$WORK/headers"
  local out
  out=$(browse "$jar" -o "$WORK/body" -D "$HEADERS" -w '%{http_code} %{redirect_url}' \
    -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: localhost:8443' \
    -H "X-Forwarded-Uri: $path" -H "X-Forwarded-Method: $method" "$@" "$GW/auth?redirect=1")
  CODE=${out%% *}
  LOCATION=${out#* }
}
header() { sed -n "s/^$1: //Ip" "$HEADERS" | tr -d '\r'; }

# expect JAR METHOD PATH STATUS USER [curl args]: forward-auth answers
# STATUS; on 200 the app would get X-Auth-User USER ("" for nobody).
expect() {
  local jar=$1 method=$2 path=$3 want=$4 user=$5; shift 5
  auth "$jar" "$method" "$path" "$@"
  [[ "$CODE" == "$want" ]] || fail "$method $path as ${jar}: status $CODE, want $want ($(cat "$WORK/body"))"
  if [[ "$want" == 200 ]]; then
    [[ "$(header X-Auth-User)" == "$user" ]] || fail "$method $path as ${jar}: X-Auth-User '$(header X-Auth-User)', want '$user'"
  fi
}

# expect_login JAR METHOD PATH: a browser is sent to the gateway's login
# page with the original URL to return to. Sets LOGIN.
expect_login() {
  auth "$1" "$2" "$3" -H 'Accept: text/html'
  [[ "$CODE" == 302 && "$LOCATION" == "$GW/login?"* ]] || fail "$2 $3 as $1: status $CODE to '$LOCATION', want 302 to the login page"
  [[ "$LOCATION" == *"rd=$(python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$APP$3")"* ]] ||
    fail "$2 $3: the login URL $LOCATION does not return to $APP$3"
  LOGIN=$LOCATION
}

# form FILE: print the form action, then key=value lines (URL-encoded).
form() {
  python3 -I - "$1" <<'PY'
import html, re, sys, urllib.parse
body = open(sys.argv[1]).read()
action = re.search(r'<form method="post" action="([^"]+)"', body).group(1)
print(html.unescape(action))
for k, v in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)">', body):
    print(urllib.parse.quote(html.unescape(k)) + "=" + urllib.parse.quote(html.unescape(v), safe=""))
PY
}

# sign_in JAR USER PASS LOGIN_URL [OTP]: the login page, the fake IdP's
# form (with the one-time code when it asks for one) and the callback; sets
# SIGNED_IN_TO to where the callback sends the browser.
sign_in() {
  local jar=$1 user=$2 pass=$3 login=$4 otp=${5:-}
  local idp
  idp=$(browse "$jar" -o /dev/null -w '%{redirect_url}' -H 'Accept: text/html' "$login")
  [[ "$idp" == https://localhost:9443/authorize?* ]] || fail "$user: the login page sent the browser to '$idp'"
  browse "$jar" -o "$WORK/page.html" "$idp"
  local f=() line
  while IFS= read -r line; do f+=("$line"); done < <(form "$WORK/page.html")
  local data="username=$user&password=$pass"
  if grep -q 'name="otp"' "$WORK/page.html"; then
    [[ -n "$otp" ]] || fail "$user: the IdP asked for a one-time code"
    data="$data&otp=$otp"
  else
    [[ -z "$otp" ]] || fail "$user: the IdP did not ask for the one-time code"
  fi
  for kv in "${f[@]:1}"; do data="$data&$kv"; done
  local cb
  cb=$(browse "$jar" -o /dev/null -w '%{redirect_url}' -X POST --data "$data" "${f[0]}")
  [[ "$cb" == "$GW/callback/corp?"* ]] || fail "$user: the IdP returned to '$cb'"
  SIGNED_IN_TO=$(browse "$jar" -o "$WORK/body" -w '%{redirect_url}' "$cb")
  [[ "$SIGNED_IN_TO" == "$APP/"* ]] || fail "$user: the callback answered '$(cat "$WORK/body")', not a redirect to the wiki"
}

# admin METHOD PATH [JSON]: the gateway's admin API.
admin() {
  browse admin -f -X "$1" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    ${3:+--data "$3"} "$ADMIN$2"
}
# session_of USER: the ID of USER's newest live session.
session_of() {
  admin GET "/admin/sessions?subject=$1" | json 'sorted(j["sessions"], key=lambda s: s["created_at"])[-1]["id"]'
}
# explain JSON: POST /admin/explain; the answer is in $WORK/explain.json.
explain() {
  admin POST /admin/explain "$1" >"$WORK/explain.json" || fail "explain $1 failed"
}
ex() { json "$1" <"$WORK/explain.json"; }

wait_for() { # url
  for _ in $(seq 1 100); do
    curl -s -o /dev/null --cacert "$WORK/certs/ca.pem" "$1" && return 0
    sleep 0.2
  done
  fail "timed out waiting for $1"
}

step "Build authz; start the fake IdP, then serve and the gateway in one process"
(cd "$MODULE" && go build -o "$WORK/bin/" ./cmd/authz)
AUTHZ="$WORK/bin/authz"
"$AUTHZ" fakeidp gencert -dir "$WORK/certs" -hosts localhost,127.0.0.1 >/dev/null
cp "$HERE/gateway.json" "$HERE/fakeidp.json" "$WORK/"
cd "$WORK"
"$AUTHZ" fakeidp -config fakeidp.json -addr 127.0.0.1:9443 -tls-cert certs/tls.pem -tls-key certs/tls-key.pem 2>"$WORK/fakeidp.log" &
PIDS+=($!)
wait_for https://localhost:9443/healthz
"$AUTHZ" gateway check gateway.json >/dev/null || fail "gateway.json does not check"
GRANTD_ADDR=127.0.0.1:8080 GRANTD_API_KEYS="$API_KEY" \
  WICKET_CONFIG=gateway.json WICKET_COOKIE_KEYS="$("$AUTHZ" gateway genkey)" \
  WICKET_ADDR=127.0.0.1:4180 WICKET_ADMIN_ADDR=127.0.0.1:4181 WICKET_ADMIN_TOKEN="$ADMIN_TOKEN" \
  WICKET_TRUSTED_PROXIES=127.0.0.0/8 \
  AUTHZ_TLS_CERT=certs/tls.pem AUTHZ_TLS_KEY=certs/tls-key.pem \
  "$AUTHZ" run -parts serve,gateway >"$WORK/run.log" 2>&1 &
PIDS+=($!)
wait_for "$GW/healthz"
wait_for https://localhost:8080/healthz
ok "serve on :8080, the gateway on :4180 (admin :4181), the fake IdP on :9443"

step "Load the wiki's schema and who may edit page:roadmap"
export AUTHZ_URL=https://localhost:8080 AUTHZ_API_KEY="$API_KEY" SSL_CERT_FILE="$WORK/certs/ca.pem"
"$AUTHZ" ctl schema write "$HERE/wiki.schema" >/dev/null
"$AUTHZ" ctl rel touch page:roadmap#owner@user:alice page:roadmap#editor@group:eng#member group:eng#member@user:carol >/dev/null
ok "alice owns page:roadmap; carol edits it through group:eng; bob has nothing"

step "A signed-out visitor"
expect anon GET /pages/roadmap 200 ""
expect anon HEAD /pages 200 ""
expect anon GET /static/wiki.css 200 ""
ok "public pages are answered with no identity"
expect anon GET /pages/roadmap 200 "" -H 'X-Auth-User: alice'
ok "a client's own X-Auth-User is not passed on"
expect anon PUT /pages/roadmap 401 ""
expect_login anon GET /settings
expect_login anon GET /admin/users
ok "writing a page is not public (401 to an API client), private pages go to the login page"
expect anon GET '/static/../admin/users' 401 ""
expect anon GET '/pages%2F..%2Fadmin' 403 ""
[[ "$(cat "$WORK/body")" == *"path is ambiguous"* ]] || fail "an encoded slash was not refused as ambiguous: $(cat "$WORK/body")"
ok "a traversal out of /static is private (401); an encoded slash is refused (bad_path)"

step "bob and carol sign in with their passwords"
expect_login bob GET /drafts/new?title=Q3
sign_in bob bob bob-pass "$LOGIN"
[[ "$SIGNED_IN_TO" == "$APP/drafts/new?title=Q3" ]] || fail "bob was returned to $SIGNED_IN_TO"
expect_login carol GET /settings
sign_in carol carol carol-pass "$LOGIN"
ok "each is returned to the page they asked for"
expect bob GET /pages/roadmap 200 bob
expect bob PUT /pages/roadmap 403 ""
grep -q '"reason":"check_denied"' "$WORK/run.log" || fail "the gateway logged no check_denied for bob's PUT"
expect carol PUT /pages/roadmap 200 carol
expect carol DELETE /pages/roadmap 200 carol
expect carol PUT /pages/plan 403 ""
ok "public pages name them; the engine lets carol edit page:roadmap (through group:eng) and refuses bob and page:plan"
expect bob GET /admin/users 403 ""
expect carol GET /admin/users 403 ""
ok "/admin refuses users outside admins without asking them to step up"

step "alice: signed in with a password, then stepping up for /admin"
expect_login alice GET /settings
sign_in alice alice alice-pass "$LOGIN"
expect alice PUT /pages/roadmap 200 alice
ok "alice edits the page she owns"
expect alice GET /admin/users 401 ""
[[ "$(header WWW-Authenticate)" == *'error="insufficient_user_authentication"'* &&
   "$(header WWW-Authenticate)" == *'acr_values="urn:fakeidp:acr:mfa"'* ]] ||
  fail "the step-up challenge to an API client was '$(header WWW-Authenticate)'"
[[ "$(header X-Auth-Redirect)" == "$GW/login?"*step_up=* ]] || fail "X-Auth-Redirect: $(header X-Auth-Redirect)"
ok "an API client gets 401 step_up_required with the RFC 9470 challenge"
expect_login alice GET '/admin/users?sort=name'
[[ "$LOGIN" == *"step_up=paths%5B2%5D"* || "$LOGIN" == *"step_up=paths[2]"* ]] || fail "the login URL does not name the step-up rule: $LOGIN"
password_session=$(session_of alice)
sign_in alice alice alice-pass "$LOGIN" 246810
[[ "$SIGNED_IN_TO" == "$APP/admin/users?sort=name" ]] || fail "alice was returned to $SIGNED_IN_TO"
ok "the browser is sent to sign in again, the IdP asks for the one-time code, and alice is back at /admin/users?sort=name"
expect alice GET /admin/users 200 alice
expect alice GET /admin/audit 200 alice
expect alice DELETE /admin/audit 403 ""
ok "/admin lets alice in; DELETE /admin/audit is refused even to her"

step "POST /admin/explain: the same answers, and why"
explain '{"url": "'"$APP"'/pages/roadmap", "method": "GET"}'
[[ "$(ex 'j["status"]') $(ex 'j["decision"]') $(ex 'j["rule"]')" == "200 public paths[0]" ]] || fail "signed out, GET /pages/roadmap: $(cat "$WORK/explain.json")"
ok "a signed-out GET /pages/roadmap: 200, public, rule paths[0]"

explain '{"url": "'"$APP"'/pages/roadmap", "method": "PUT", "session": "'"$(session_of bob)"'"}'
[[ "$(ex 'j["status"]') $(ex 'j["reason"]') $(ex 'j["rule"]')" == "403 check_denied paths[1]" ]] || fail "bob's PUT: $(cat "$WORK/explain.json")"
[[ "$(ex 'j["check"]["resource"] + " " + j["check"]["permission"] + " " + j["check"]["subject"] + " " + j["check"]["result"]')" == "page:roadmap edit user:bob denied" ]] ||
  fail "bob's check: $(ex 'j["check"]')"
[[ "$(ex '[r["rule"] + ":" + r["kind"] + ":" + str(r["selected"]) for r in j["rules"]]')" == '["paths[1]:check:True", "paths[0]:public:False", "allow:allow:False"]' ]] || fail "bob's rule chain: $(ex 'j["rules"]')"
ok "bob's PUT /pages/roadmap: 403 check_denied by paths[1], chain /pages/{id} (selected) > GET /pages > the app's allow, the engine said no to page:roadmap#edit@user:bob"

explain '{"url": "'"$APP"'/pages/roadmap", "method": "PUT", "session": "'"$(session_of carol)"'"}'
[[ "$(ex 'j["status"]') $(ex 'j["check"]["result"]')" == "200 allowed" ]] || fail "carol's PUT: $(cat "$WORK/explain.json")"
python3 -I - "$WORK/explain.json" <<'PY' || fail "carol's trace does not show the path through group:eng: $(cat "$WORK/explain.json")"
import json, sys
root = json.load(open(sys.argv[1]))["check"]["trace"]["root"]
seen = []
def walk(n):
    seen.append(json.dumps(n))
    for c in n.get("children") or []:
        walk(c)
walk(root)
assert any("group:eng" in s for s in seen), seen
PY
ok "carol's PUT: 200, the engine's trace goes through group:eng#member"

explain '{"url": "'"$APP"'/admin/users", "method": "GET", "session": "'"$(session_of alice)"'"}'
[[ "$(ex 'j["status"]') $(ex 'j["rule"]') $(ex 'j["step_up"]["acr"]') $(ex 'j["step_up"]["satisfied"]')" == "200 paths[2] urn:fakeidp:acr:mfa true" ]] ||
  fail "alice after stepping up: $(cat "$WORK/explain.json")"
ok "alice's GET /admin/users after the step-up: 200, her acr urn:fakeidp:acr:mfa meets paths[2]"
if admin GET "/admin/sessions?subject=alice" | json '[s["id"] for s in j["sessions"]]' | grep -q "\"$password_session\""; then
  fail "alice's password session is still live after the step-up"
fi
explain '{"url": "'"$APP"'/admin/users", "method": "GET", "identity": {"provider": "corp", "sub": "alice", "groups": ["eng", "admins"]}, "auth": {"time": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'", "acr": "urn:fakeidp:acr:password"}}'
[[ "$(ex 'j["status"]') $(ex 'j["reason"]') $(ex 'j["step_up"]["satisfied"]')" == "401 step_up_acr false" ]] || fail "alice with a password: $(cat "$WORK/explain.json")"
[[ "$(ex 'j["login_url"]')" == "$GW/login?"* ]] || fail "no login URL: $(cat "$WORK/explain.json")"
ok "a synthetic alice signed in with a password: 401 step_up_acr, with the login URL forward-auth would send"
explain '{"url": "'"$APP"'/admin/audit", "method": "DELETE", "session": "'"$(session_of alice)"'"}'
[[ "$(ex 'j["status"]') $(ex 'j["reason"]') $(ex 'j["rule"]')" == "403 denied_by_rule paths[3]" ]] || fail "DELETE /admin/audit: $(cat "$WORK/explain.json")"
ok "DELETE /admin/audit: 403, denied by paths[3]"

step "Explaining changed nothing"
expect bob PUT /pages/roadmap 403 ""
expect carol PUT /pages/roadmap 200 carol
expect alice GET /admin/users 200 alice
ok "forward-auth answers as before"

printf '\nAll wiki checks passed.\n'
