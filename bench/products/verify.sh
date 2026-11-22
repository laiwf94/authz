#!/usr/bin/env bash
# Proves the authorization products' setups before anything is measured on
# them. It checks that openfga-model.json is what the pinned OpenFGA CLI
# makes of the dataset's model, brings up authz, SpiceDB and OpenFGA from
# compose.yaml on fresh volumes, loads the same seeded dataset into each
# through its write API, loads it a second time to show the writes are
# idempotent, and asks all three the same sampled checks: one different
# answer fails the run.
#
#   bench/products/verify.sh            # SIZE=100k N=2000
#   SIZE=1m N=5000 bench/products/verify.sh
#
# AUTHZ_URL uses an authz serve that is already running (its key in
# AUTHZBENCH_API_KEY) instead of building the image. It must hold no other
# data: relationships of another size share the dataset's IDs and change
# its answers. KEEP=1 leaves the
# containers and volumes up afterwards. Needs docker with compose, jq and
# go. Uses ports 18080, 18081 and 18443 on 127.0.0.1.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
SIZE=${SIZE:-100k}
N=${N:-2000}
WORK="$(mktemp -d)"
compose() { docker compose -f "$DIR/compose.yaml" "$@"; }
profiles=(--profile spicedb --profile openfga)
[[ -z ${AUTHZ_URL:-} ]] && profiles+=(--profile authz)

cleanup() {
  if [[ ${KEEP:-0} != 1 ]]; then
    compose "${profiles[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

go build -o "$WORK/authzdata" "$REPO/bench/cmd/authzdata"
data="$WORK/authzdata"

echo "== openfga-model.json is the dataset's model"
"$data" schema -format openfga >"$WORK/model.fga"
chmod 0755 "$WORK" && chmod 0644 "$WORK/model.fga"
compose --profile tools run --rm -v "$WORK:/w:ro" openfga-cli \
  model transform --file /w/model.fga --input-format fga >"$WORK/model.json"
diff <(jq -S . "$WORK/model.json") <(jq -S . "$DIR/openfga-model.json") \
  || fail "openfga-model.json differs from the CLI's transform of 'authzdata schema -format openfga'"

echo "== start ${profiles[*]}"
compose "${profiles[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
compose "${profiles[@]}" up -d --build --quiet-pull

export AUTHZBENCH_API_KEY=${AUTHZBENCH_API_KEY:-${AUTHZ_KEY:-bench-authz-key-0123456789}}
export AUTHZBENCH_SPICEDB_KEY=${SPICEDB_KEY:-bench-spicedb-key-0123456789}
export AUTHZBENCH_OPENFGA_KEY=${OPENFGA_KEY:-bench-openfga-key-0123456789}
authz=${AUTHZ_URL:-http://127.0.0.1:18080}
spicedb=http://127.0.0.1:18443
openfga=http://127.0.0.1:18081

wait_up() { # NAME URL
  for _ in $(seq 1 120); do
    if curl -fsS -o /dev/null "$2" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  compose "${profiles[@]}" logs >&2 || true
  fail "$1 did not become ready at $2"
}
wait_up authz "$authz/readyz"
wait_up spicedb "$spicedb/healthz"
wait_up openfga "$openfga/healthz"

echo "== load $SIZE into each"
"$data" load -size "$SIZE" -api "$authz" -schema
"$data" load -size "$SIZE" -target spicedb -api "$spicedb" -schema -workers 8
"$data" load -size "$SIZE" -target openfga -api "$openfga" -workers 16

echo "== load again: touches and ignored duplicates change nothing"
"$data" load -size "$SIZE" -to 5000 -target spicedb -api "$spicedb" -schema
"$data" load -size "$SIZE" -to 5000 -target openfga -api "$openfga" -schema

echo "== cross-check $N questions"
"$data" crosscheck -size "$SIZE" -n "$N" -authz "$authz" -spicedb "$spicedb" -openfga "$openfga"

echo "== memory after the load"
docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' \
  $(compose "${profiles[@]}" ps -q) 2>/dev/null || true
echo "verify: PASS"
