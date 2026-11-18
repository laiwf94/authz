#!/usr/bin/env bash
# Interop with Keycloak (#79): OpenID Connect back-channel logout and SAML
# single logout between `authz gateway` and a real Keycloak. It makes a
# throwaway CA and one TLS certificate for localhost and 127.0.0.1 (Keycloak
# serves on https://localhost:8443 and trusts the CA, so it can post logouts
# to the gateway on 127.0.0.1), starts Keycloak with a random admin password,
# and runs the interop tests in cmd/authz/internal/interop, which provision
# their own realms. .github/workflows/interop.yml runs it.
#
# Keycloak runs in Docker (quay.io/keycloak/keycloak, host network), or from
# an unpacked distribution when KEYCLOAK_HOME is set (needs Java 21).
#
# Needs: go, curl, openssl, and docker or KEYCLOAK_HOME. Uses port 8443.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYCLOAK_VERSION="${KEYCLOAK_VERSION:-26.4.2}"
KC_URL="https://localhost:8443"
CONTAINER="authz-interop-keycloak"
WORK="$(mktemp -d)"
KC_PID=""

cleanup() {
  if [ -n "$KC_PID" ]; then kill "$KC_PID" 2>/dev/null || true; wait "$KC_PID" 2>/dev/null || true; fi
  if [ -z "${KEYCLOAK_HOME:-}" ]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

kc_logs() {
  if [ -n "${KEYCLOAK_HOME:-}" ]; then tail -n 200 "$WORK/keycloak.log" || true
  else docker logs --tail 200 "$CONTAINER" 2>&1 || true; fi
}

(cd "$ROOT" && go build -o "$WORK/authz" ./cmd/authz)
"$WORK/authz" fakeidp gencert -dir "$WORK/certs" -hosts localhost,127.0.0.1 >/dev/null
chmod 755 "$WORK/certs"
chmod 644 "$WORK/certs/ca.pem" "$WORK/certs/tls.pem" "$WORK/certs/tls-key.pem" # read by Keycloak's user in the container

export KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export KEYCLOAK_ADMIN_PASSWORD
# An in-memory database: each run starts from an empty Keycloak with this
# run's admin.
args=(start-dev --db=dev-mem --http-enabled=false --https-port=8443 --health-enabled=true)

if [ -n "${KEYCLOAK_HOME:-}" ]; then
  KC_BOOTSTRAP_ADMIN_USERNAME="$KEYCLOAK_ADMIN_USER" KC_BOOTSTRAP_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
    "$KEYCLOAK_HOME/bin/kc.sh" "${args[@]}" \
    --https-certificate-file="$WORK/certs/tls.pem" --https-certificate-key-file="$WORK/certs/tls-key.pem" \
    --truststore-paths="$WORK/certs/ca.pem" >"$WORK/keycloak.log" 2>&1 &
  KC_PID=$!
else
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" --network host -v "$WORK/certs:/certs:ro" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME="$KEYCLOAK_ADMIN_USER" -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
    "quay.io/keycloak/keycloak:$KEYCLOAK_VERSION" "${args[@]}" \
    --https-certificate-file=/certs/tls.pem --https-certificate-key-file=/certs/tls-key.pem \
    --truststore-paths=/certs/ca.pem >/dev/null
fi

echo "waiting for Keycloak $KEYCLOAK_VERSION at $KC_URL"
for i in $(seq 1 180); do
  if curl -sf --cacert "$WORK/certs/ca.pem" -o /dev/null "$KC_URL/realms/master/.well-known/openid-configuration"; then
    break
  fi
  if [ "$i" = 180 ]; then echo "Keycloak did not start in 180s"; kc_logs; exit 1; fi
  if [ -n "$KC_PID" ] && ! kill -0 "$KC_PID" 2>/dev/null; then echo "Keycloak exited"; kc_logs; exit 1; fi
  sleep 1
done

export KEYCLOAK_URL="$KC_URL" INTEROP_CA="$WORK/certs/ca.pem"
export INTEROP_TLS_CERT="$WORK/certs/tls.pem" INTEROP_TLS_KEY="$WORK/certs/tls-key.pem"
cd "$ROOT"
if ! go test -tags interop -count=1 -v "$@" ./cmd/authz/internal/interop; then
  echo "--- Keycloak log"
  kc_logs
  exit 1
fi
