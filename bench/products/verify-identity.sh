#!/usr/bin/env bash
# Proves the identity products' setups before anything is measured on
# them. It brings up Keycloak with oauth2-proxy, and Zitadel, from
# compose.yaml on fresh volumes, sets up each provider's client (a realm
# and client in Keycloak, a project and application in Zitadel), imports
# the first USERS of the dataset's sign-in population with their groups
# into each, imports them again to show an import changes nothing the
# second time, and reads every one back. Then it signs one user in
# through oauth2-proxy with curl and checks that the groups oauth2-proxy
# asserts are the user's groups in the graph, signs users in through
# Zitadel's login and checks that each ID token names the user's groups
# as roles, and runs short authzbench mixes, which must have no errors:
# sign-ins straight at Keycloak, through oauth2-proxy and straight at
# Zitadel, and forward-auth decisions of oauth2-proxy with a signed-in
# session (202) and without one (401).
#
#   bench/products/verify-identity.sh             # SIZE=100k USERS=500
#   SIZE=1m USERS=5000 bench/products/verify-identity.sh
#
# KEEP=1 leaves the containers and volumes up afterwards. Needs docker
# with compose, jq, curl and go. Uses ports 14180, 18180, 18280 and 19000
# on 127.0.0.1.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
SIZE=${SIZE:-100k}
USERS=${USERS:-500}
WORK="$(mktemp -d)"
compose() { docker compose -f "$DIR/compose.yaml" "$@"; }
profiles=(--profile keycloak --profile zitadel)

cleanup() {
  if [[ ${KEEP:-0} != 1 ]]; then
    compose "${profiles[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

go build -o "$WORK/authzdata" "$REPO/bench/cmd/authzdata"
go build -o "$WORK/authzbench" "$REPO/bench/cmd/authzbench"
data="$WORK/authzdata"

echo "== start ${profiles[*]}"
compose "${profiles[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
compose "${profiles[@]}" up -d --build --quiet-pull

export AUTHZBENCH_KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-bench-keycloak-admin-0123456789}
export AUTHZBENCH_KEYCLOAK_CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET:-bench-keycloak-client-0123456789}
keycloak=http://127.0.0.1:18180
proxy=http://127.0.0.1:14180

wait_up() { # NAME URL
  for _ in $(seq 1 240); do
    if curl -fsS -o /dev/null "$2" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  compose "${profiles[@]}" logs >&2 || true
  fail "$1 did not become ready at $2"
}
wait_up keycloak http://127.0.0.1:19000/health/ready
wait_up oauth2-proxy "$proxy/ping"
# Zitadel answers discovery once its first instance is set up; the
# instance is found by the host, so it is asked at localhost.
zitadel=http://localhost:18280
wait_up zitadel "$zitadel/.well-known/openid-configuration"
for _ in $(seq 1 60); do
  if compose "${profiles[@]}" cp zitadel:/bootstrap/admin.pat "$WORK/zitadel.pat" >/dev/null 2>&1 && [[ -s $WORK/zitadel.pat ]]; then break; fi
  sleep 1
done
[[ -s $WORK/zitadel.pat ]] || fail "Zitadel wrote no admin token"
AUTHZBENCH_ZITADEL_TOKEN=$(<"$WORK/zitadel.pat")
export AUTHZBENCH_ZITADEL_TOKEN

echo "== import $USERS users of $SIZE into Keycloak"
"$data" import -size "$SIZE" -n "$USERS" -api "$keycloak" -verify 0 | tee "$WORK/import1"
echo "== import again: every user and group is skipped"
"$data" import -size "$SIZE" -n "$USERS" -api "$keycloak" -verify -1 | tee "$WORK/import2"
grep -q ": 0 added, " "$WORK/import2" || fail "the second import added something"

echo "== import $USERS users of $SIZE into Zitadel"
"$data" import -target zitadel -size "$SIZE" -n "$USERS" -api "$zitadel" -verify 0 | tee "$WORK/zimport1"
echo "== import again: every user and role is skipped"
"$data" import -target zitadel -size "$SIZE" -n "$USERS" -api "$zitadel" -verify -1 | tee "$WORK/zimport2"
grep -q ": 0 added, " "$WORK/zimport2" || fail "the second Zitadel import added something"
client_id=$(sed -n 's/^zitadel project .*, client ID //p' "$WORK/zimport2")
[[ -n $client_id ]] || fail "Zitadel's import named no client ID"

echo "== sign-ins through Zitadel: each ID token names the graph's groups as roles"
"$data" signin -target zitadel -size "$SIZE" -n "$USERS" -sample 5 -api "$zitadel"

echo "== one sign-in through oauth2-proxy: the groups it asserts are the graph's"
user=$("$data" users -size "$SIZE" -n 1 | head -1)
name=$(jq -r .username <<<"$user")
jar="$WORK/jar"
curl -fsS -c "$jar" -b "$jar" -L -o "$WORK/login.html" "$proxy/oauth2/start?rd=%2F"
action=$(grep -o 'action="[^"]*"' "$WORK/login.html" | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')
[[ -n $action ]] || fail "Keycloak's sign-in page has no form"
curl -fsS -c "$jar" -b "$jar" -L -o /dev/null --data-urlencode "username=$name" \
  --data-urlencode "password=$(jq -r .password <<<"$user")" "$action"
headers=$(curl -sS -D - -o /dev/null -b "$jar" "$proxy/oauth2/auth" | tr -d '\r')
grep -q '^HTTP/1.1 202' <<<"$headers" || fail "oauth2-proxy did not accept the session: $headers"
got=$(sed -n 's/^X-Auth-Request-Groups: //Ip' <<<"$headers" | tr ',' '\n' | sort | paste -sd,)
want=$(jq -r '.groups | sort | join(",")' <<<"$user")
[[ $got == "$want" ]] || fail "$name: oauth2-proxy asserts groups '$got', the graph has '$want'"
email=$(sed -n 's/^X-Auth-Request-Email: //Ip' <<<"$headers")
[[ $email == "$(jq -r .email <<<"$user")" ]] || fail "$name: oauth2-proxy asserts email '$email'"
echo "$name: groups $got, email $email"

echo "== authzbench: sign-ins and forward-auth decisions"
# Short and slow, not a measurement: it proves every operation of the
# benchmark works on these setups without an error.
"$data" users -size "$SIZE" -n "$USERS" -format credentials -o "$WORK/credentials"
bench() { # LABEL [FLAGS...]
  "$WORK/authzbench" "${@:2}" -login-credentials "@$WORK/credentials" -warmup 1s \
    -duration "${BENCH_DURATION:-10s}" -workers 16 -max-error-rate 0 -label "$1-$SIZE" -out "$WORK/bench-$1.json"
}
# A sign-in straight at Keycloak returns to its account page with a code
# nobody redeems. The client requires PKCE, so it carries a challenge (the
# example of RFC 7636: the sign-in is measured, not the code exchange).
account="$keycloak/realms/bench/account/"
pkce="code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
direct="$keycloak/realms/bench/protocol/openid-connect/auth?client_id=bench-proxy&response_type=code&scope=openid&$pkce&redirect_uri=$(jq -rn --arg u "$account" '$u|@uri')"
bench keycloak-login -mix oidc_login=1 -rate "${LOGIN_RATE:-10}" -login-start "$direct" -login-cookie KEYCLOAK_IDENTITY
# A sign-in straight at Zitadel: its login asks for the name, then the
# password, and the sign-in ends at the redirect with the code, which
# nothing answers at (-login-done), as for Keycloak above.
zdone=http://127.0.0.1:18089/callback
zdirect="$zitadel/oauth/v2/authorize?client_id=$(jq -rn --arg c "$client_id" '$c|@uri')&response_type=code&scope=openid&$pkce&redirect_uri=$(jq -rn --arg u "$zdone" '$u|@uri')"
bench zitadel-login -mix oidc_login=1 -rate "${LOGIN_RATE:-10}" -login-start "$zdirect" -login-user-field loginName -login-done "$zdone"
start="$proxy/oauth2/start?rd=%2F"
bench oauth2-proxy-login -mix oidc_login=1 -rate "${LOGIN_RATE:-10}" -login-start "$start" -login-cookie _oauth2_proxy
bench oauth2-proxy-auth -mix forward_auth=1 -rate "${BENCH_RATE:-200}" -forward-url "$proxy/oauth2/auth" \
  -forward-host app.bench.example -forward-expect 202 -sessions 20 -login-start "$start" -login-cookie _oauth2_proxy
bench oauth2-proxy-deny -mix forward_auth=1 -rate "${BENCH_RATE:-200}" -forward-url "$proxy/oauth2/auth" \
  -forward-host app.bench.example -forward-expect 401

echo "== memory after the import"
docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' \
  $(compose "${profiles[@]}" ps -q) 2>/dev/null || true
echo "verify-identity: PASS"
