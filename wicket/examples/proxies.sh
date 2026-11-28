#!/usr/bin/env bash
# Public paths and path rules through real proxies: nginx (auth_request),
# Traefik (ForwardAuth) and Envoy (ext_authz), each with the configuration
# docs/proxies.md gives (wicket/examples/proxies/), in front of an app that
# echoes what reached it. `authz gateway` decides, with an app whose /static
# and GET /wiki are public, whose /admin needs the admins group and whose
# DELETE /admin/audit is refused for everyone (proxies/wicket.json).
#
# For each proxy in turn, on the same address, curl plays the browser and
# checks what the app receives: anonymous visitors reach the public pages
# with no identity even when they send their own X-Auth-* headers; a
# traversal out of a public prefix is judged as the path it resolves to; a
# path two servers could read differently never reaches the app; private
# pages send browsers to the login page and API clients get 401; signed-in
# users are named on public pages too, by the gateway and never by a
# client header; and each path rule decides by group and method.
#
# PROXIES="nginx envoy" runs only those.
#
# Needs: go, docker, curl, python3. Uses ports 4180, 4181, 8081, 8443, 9443.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE="$(cd "$ROOT/.." && pwd)"
CONF="$ROOT/examples/proxies"
WORK="$(mktemp -d)"
NGINX_IMAGE="nginx:1.27.3-alpine"
TRAEFIK_IMAGE="traefik:v3.3.4"
ENVOY_IMAGE="envoyproxy/envoy:v1.33.2"
CONTAINER="wicket-proxies"
export DEMO_CLIENT_SECRET="demo-client-secret-0123456789"
APP="https://localhost:8443"
PIDS=()

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
ok() { printf '   ok: %s\n' "$*"; }
fail() {
  printf '   FAILED: %s\n' "$*"
  printf '\n-- proxy log\n'; docker logs --tail 40 "$CONTAINER" 2>&1 || true
  printf '\n-- gateway log\n'; tail -n 20 "$WORK/gateway.log" || true
  exit 1
}

# curl as a browser: one cookie jar per user and proxy, never follows
# redirects, sends the path exactly as written (--path-as-is).
browse() { # jar, curl args...
  local jar="$WORK/$1.jar"; shift
  curl -sS --path-as-is --cacert "$WORK/certs/ca.pem" -b "$jar" -c "$jar" "$@"
}
# req JAR METHOD PATH [curl args]: a browser navigation; prints the status,
# the redirect target and the echo app's answer on one line each.
req() {
  local jar=$1 method=$2 path=$3; shift 3
  local how=(-X "$method")
  [[ "$method" == HEAD ]] && how=(--head)
  rm -f "$WORK/headers"
  browse "$jar" -o /dev/null -D "$WORK/headers" -w '%{http_code}\n%{redirect_url}\n' "${how[@]}" -H 'Accept: text/html' "$@" "$APP$path" 2>/dev/null || true
  # The echo app's answer, from its X-Echo header; empty for anyone else's.
  sed -n 's/^[Xx]-[Ee]cho: //p' "$WORK/headers" | tr -d '\r'
  echo
}
# field JSON NAME: a field of the echo app's answer, or "-" when the answer
# did not come from the app.
field() {
  python3 -I -c 'import json,sys
try: v = json.loads(sys.argv[1]).get(sys.argv[2], "-")
except Exception: v = "-"
print(str(v).lower() if isinstance(v, bool) else v)' "$1" "$2"
}

# expect_app JAR METHOD PATH USER [curl args]: the request reaches the app,
# which sees USER ("" for nobody) as X-Auth-User, a token exactly when
# someone is named, and the method it was sent.
expect_app() {
  local jar=$1 method=$2 path=$3 user=$4; shift 4
  local out code body
  out=$(req "$jar" "$method" "$path" "$@")
  code=$(sed -n 1p <<<"$out"); body=$(sed -n 3p <<<"$out")
  [[ "$code" == 200 ]] || fail "$method $path as '${jar#*-}': status $code, want 200 from the app"
  [[ "$(field "$body" method)" == "$method" ]] || fail "$method $path did not reach the app: $body"
  [[ "$(field "$body" user)" == "$user" ]] || fail "$method $path: the app saw X-Auth-User '$(field "$body" user)', want '$user'"
  local want_token=false
  [[ -n "$user" ]] && want_token=true
  [[ "$(field "$body" token)" == "$want_token" ]] || fail "$method $path: the app saw a token: $(field "$body" token), want $want_token"
  [[ "$(field "$body" provider)" == "$([[ -n "$user" ]] && echo corp)" ]] || fail "$method $path: the app saw X-Auth-Provider '$(field "$body" provider)'"
  LAST_PATH=$(field "$body" path)
}

# expect_login JAR METHOD PATH: a browser is sent to the gateway's login
# page with the original URL to return to.
expect_login() {
  local out code loc
  out=$(req "$1" "$2" "$3")
  code=$(sed -n 1p <<<"$out"); loc=$(sed -n 2p <<<"$out")
  [[ "$code" == 302 && "$loc" == "$APP/_wicket/login?app=wiki&rd="* ]] || fail "$2 $3: status $code to '$loc', want 302 to the login page"
  LAST_LOGIN=$loc
}

# expect_status JAR METHOD PATH WANT...: the answer is one of WANT, and it
# is not the app's.
expect_status() {
  local jar=$1 method=$2 path=$3; shift 3
  local out code body
  out=$(req "$jar" "$method" "$path")
  code=$(sed -n 1p <<<"$out"); body=$(sed -n 3p <<<"$out")
  [[ " $* " == *" $code "* ]] || fail "$method $path: status $code, want one of: $*"
  [[ "$(field "$body" method)" == "-" ]] || fail "$method $path reached the app: $body"
  [[ -z "$(sed -n 2p <<<"$out")" ]] || fail "$method $path: redirected to $(sed -n 2p <<<"$out")"
  LAST_STATUS=$code
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

# sign_in JAR USER PASS LOGIN_URL: through the proxy to the fake IdP and
# back; the browser ends at the page it first asked for.
sign_in() {
  local jar=$1 user=$2 pass=$3 login=$4
  local auth
  auth=$(browse "$jar" -o /dev/null -w '%{redirect_url}' -H 'Accept: text/html' "$login&provider=corp")
  [[ "$auth" == https://localhost:9443/authorize?* ]] || fail "$user: the login page sent the browser to '$auth'"
  browse "$jar" -o "$WORK/page.html" "$auth"
  local f=() line
  while IFS= read -r line; do f+=("$line"); done < <(form "$WORK/page.html")
  local data="username=$user&password=$pass"
  for kv in "${f[@]:1}"; do data="$data&$kv"; done
  local cb back
  cb=$(browse "$jar" -o /dev/null -w '%{redirect_url}' -X POST --data "$data" "${f[0]}")
  [[ "$cb" == "$APP/_wicket/callback/corp?"* ]] || fail "$user: the IdP returned to '$cb'"
  back=$(browse "$jar" -o /dev/null -w '%{redirect_url}' "$cb")
  [[ "$back" == "$APP/"* ]] || fail "$user: the callback returned to '$back'"
  SIGNED_IN_TO=$back
}

wait_for() { # url
  for _ in $(seq 1 100); do
    curl -sk -o /dev/null "$1" && return 0
    sleep 0.2
  done
  fail "timed out waiting for $1"
}

start_proxy() { # name
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  local run=(docker run -d --name "$CONTAINER" --add-host host.docker.internal:host-gateway -p 8443:8443
    -v "$CONF:/etc/proxy:ro" -v "$WORK/certs:/etc/proxy-certs:ro")
  case $1 in
  nginx) "${run[@]}" -v "$CONF/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null ;;
  traefik) "${run[@]}" "$TRAEFIK_IMAGE" --configFile=/etc/proxy/traefik.yml >/dev/null ;;
  envoy) "${run[@]}" "$ENVOY_IMAGE" -c /etc/proxy/envoy.yaml --log-level warn >/dev/null ;;
  esac
  wait_for "$APP/_wicket/healthz"
  # The file provider loads the routers a moment after the port opens.
  for _ in $(seq 1 50); do
    [[ "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/certs/ca.pem" "$APP/static/ready")" == 200 ]] && return 0
    sleep 0.2
  done
  fail "$1 never served the public /static/ready"
}

step "Build authz; start the fake IdP, the echo app and the gateway"
(cd "$MODULE" && go build -o "$WORK/bin/" ./cmd/authz)
"$WORK/bin/authz" fakeidp gencert -dir "$WORK/certs" -hosts localhost,127.0.0.1,host.docker.internal >/dev/null
chmod 755 "$WORK/certs" # readable inside the containers, where Envoy is not root
chmod 644 "$WORK/certs/tls.pem" "$WORK/certs/tls-key.pem"
cp "$CONF/wicket.json" "$CONF/fakeidp.json" "$WORK/"
cd "$WORK"
"$WORK/bin/authz" fakeidp -config fakeidp.json -addr 127.0.0.1:9443 -tls-cert certs/tls.pem -tls-key certs/tls-key.pem 2>"$WORK/fakeidp.log" &
PIDS+=($!)
wait_for https://localhost:9443/healthz
python3 -I "$CONF/echo.py" 0.0.0.0 8081 2>"$WORK/echo.log" &
PIDS+=($!)
"$WORK/bin/authz" gateway check wicket.json >/dev/null || fail "the gateway config does not check"
"$WORK/bin/authz" gateway gensigningkey >"$WORK/signing.pem"
WICKET_CONFIG=wicket.json WICKET_COOKIE_KEYS="$("$WORK/bin/authz" gateway genkey)" WICKET_ADDR=0.0.0.0:4180 \
  WICKET_SIGNING_KEYS="$WORK/signing.pem" \
  WICKET_TRUSTED_PROXIES=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
  "$WORK/bin/authz" gateway >"$WORK/gateway.log" 2>&1 &
PIDS+=($!)
wait_for http://127.0.0.1:4180/healthz
ok "gateway on :4180, fake IdP on :9443, echo app on :8081"

for proxy in ${PROXIES:-nginx traefik envoy}; do
  anon="$proxy-anonymous" alice="$proxy-alice" bob="$proxy-bob"
  step "$proxy: start it on $APP"
  start_proxy "$proxy"
  ok "$proxy serves the gateway under /_wicket and the app everywhere else"

  step "$proxy: anonymous visitors"
  expect_app "$anon" GET /wiki/home ""
  expect_app "$anon" HEAD /wiki ""
  expect_app "$anon" POST /static/app.css ""
  ok "public paths reach the app with no identity"
  expect_app "$anon" GET /wiki/home "" -H 'X-Auth-User: alice' -H 'X-Auth-Token: forged' -H 'X-Auth-Provider: corp'
  ok "a client's own X-Auth-* headers are removed on a public path"
  expect_login "$anon" GET /admin/users
  expect_login "$anon" GET '/static/../admin/users'
  ok "a private page, and a traversal out of /static into one, go to the login page"
  # nginx turns every 401 into the login redirect (error_page 401); Traefik
  # and Envoy pass the gateway's 401 to an API client.
  case $proxy in
  nginx) expect_login "$anon" POST /wiki/home ;;
  *) expect_status "$anon" POST /wiki/home 401 ;;
  esac
  ok "writing the wiki is not public ($proxy: $([[ $proxy == nginx ]] && echo 302 || echo 401))"
  # The gateway answers 403 bad_path; a proxy may refuse first (nginx says
  # 400 to a bad escape, Traefik resets the HTTP/2 stream: curl's 000).
  for p in '/static%2F..%2Fadmin/users' '/wiki%2F..%2Fadmin' '/static%5C..%5Cadmin' '/static/..;/admin' '/admin%zz'; do
    expect_status "$anon" GET "$p" 000 400 403
    printf '   ok: %s never reaches the app (%s)\n' "$p" "$LAST_STATUS"
  done

  step "$proxy: alice (admins) and bob sign in through the proxy"
  expect_login "$alice" GET /admin/users
  sign_in "$alice" alice alice-pass "$LAST_LOGIN"
  [[ "$SIGNED_IN_TO" == "$APP/admin/users" ]] || fail "alice was returned to $SIGNED_IN_TO"
  expect_login "$bob" GET /settings
  sign_in "$bob" bob bob-pass "$LAST_LOGIN"
  ok "both return to the page they asked for"

  step "$proxy: path rules for signed-in users"
  expect_app "$alice" GET /wiki/home alice
  expect_app "$bob" GET /wiki/home bob
  ok "a public page names a signed-in user, with a token"
  expect_app "$bob" GET /wiki/home bob -H 'X-Auth-User: alice' -H 'X-Auth-Groups: admins'
  ok "the gateway's identity replaces the client's own headers"
  expect_app "$bob" POST /wiki/home bob
  ok "bob may write the wiki (the app-wide rule)"
  expect_app "$alice" GET /admin/users alice
  expect_status "$bob" GET /admin/users 403
  ok "/admin lets alice in and refuses bob"
  expect_app "$alice" GET /admin/audit alice
  expect_status "$alice" DELETE /admin/audit 403
  ok "DELETE /admin/audit is refused even for alice; GET is not"
  expect_app "$alice" GET '/wiki/a%20b?q=1' alice
  [[ "$LAST_PATH" == '/wiki/a%20b?q=1' ]] || fail "the app got $LAST_PATH"
  ok "the app gets the path the gateway judged, as the client sent it"
  # The gateway decides on the resolved path. nginx and Traefik pass the
  # client's path on unchanged, so the app must resolve it the same way;
  # Envoy, with normalize_path and merge_slashes, resolves it for both.
  expect_app "$alice" GET '/static/../admin//users' alice
  want='/static/../admin//users'
  [[ $proxy == envoy ]] && want=/admin/users
  [[ "$LAST_PATH" == "$want" ]] || fail "the app got $LAST_PATH, want $want"
  expect_app "$anon" GET '/wiki//./x' ''
  want='/wiki//./x'
  [[ $proxy == envoy ]] && want=/wiki/x
  [[ "$LAST_PATH" == "$want" ]] || fail "the app got $LAST_PATH, want $want"
  ok "dot segments and doubled slashes: decided as resolved, the app got $LAST_PATH"
  docker rm -f "$CONTAINER" >/dev/null
done

printf '\nAll proxy checks passed.\n'
