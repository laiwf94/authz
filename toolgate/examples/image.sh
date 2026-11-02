#!/usr/bin/env bash
# Builds the image from toolgate/Dockerfile and runs the example the README
# gives for it, through the old command names the image keeps as links to
# the one authz binary: `--entrypoint /mcpfake` serves examples/sandbox and
# `--entrypoint /toolgate` is the gateway, configured with TOOLGATE_*
# variables only, as an existing toolgate deployment is. An agent reads a
# sandbox file through the gateway and is refused one outside its policy,
# `toolgate audit verify` checks the log the container wrote, `toolgate
# policy test` runs the example cases, and `docker stop` ends both containers
# with exit status 0.
#
# Needs docker, tar and curl. Uses port 18090 on 127.0.0.1. IMAGE names the image
# (default authz-toolgate-check); BUILD=0 uses that image as it is instead of
# building it. The containers, network and volume it creates are removed at
# exit.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
IMAGE=${IMAGE:-authz-toolgate-check}
RUN=tgcheck-$$
WORK="$(mktemp -d)"
ALICE=tgk_demo_alice_0123456789abcdefghijklmnop
UPSTREAM_TOKEN=image-upstream-secret-0123456789

cleanup() {
  docker rm -f "$RUN-gw" "$RUN-fake" >/dev/null 2>&1 || true
  docker network rm "$RUN" >/dev/null 2>&1 || true
  docker volume rm "$RUN-data" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

if [[ ${BUILD:-1} != 0 ]]; then
  echo "== build $IMAGE"
  docker build -q -t "$IMAGE" -f "$REPO/toolgate/Dockerfile" "$REPO" >/dev/null
fi
# The old names are links, not second copies of the binary, and /data is
# writable by nonroot.
listing=$(docker create "$IMAGE")
files=$(docker export "$listing" | tar tvf -)
docker rm "$listing" >/dev/null
for link in toolgate mcpfake; do
  grep -Eq "^l.* $link -> authz\$" <<<"$files" || fail "/$link in the image is not a link to authz"
  docker run --rm --entrypoint "/$link" "$IMAGE" -h 2>&1 | head -1 | grep -qx "usage: $link.*" \
    || fail "/$link in the image is not the old $link command"
done
grep -Eq "^d.* 65532/65532 .* data/\$" <<<"$files" || fail "/data in the image is not owned by nonroot"

echo "== start mcpfake and toolgate"
docker network create "$RUN" >/dev/null
docker volume create "$RUN-data" >/dev/null
sed 's#127.0.0.1:19100#mcpfake:19100#' "$DIR/config.json" >"$WORK/config.json"
cp "$DIR/policy.json" "$WORK/policy.json"
chmod 0644 "$WORK/config.json" "$WORK/policy.json"
chmod 0755 "$WORK"
docker run -d --name "$RUN-fake" --network "$RUN" --network-alias mcpfake --entrypoint /mcpfake \
  -v "$DIR/sandbox:/sandbox:ro" -e MCPFAKE_ADDR=0.0.0.0:19100 \
  -e MCPFAKE_SANDBOX=/sandbox -e MCPFAKE_TOKEN="$UPSTREAM_TOKEN" "$IMAGE" >/dev/null
docker run -d --name "$RUN-gw" --network "$RUN" -p 127.0.0.1:18090:8080 --entrypoint /toolgate \
  -v "$WORK:/etc/toolgate:ro" -v "$RUN-data:/data" \
  -e TOOLGATE_CONFIG=/etc/toolgate/config.json -e TOOLGATE_POLICY=/etc/toolgate/policy.json \
  -e TOOLGATE_AUDIT_LOG=/data/audit.jsonl -e TOOLGATE_STATE_DIR=/data \
  -e TOOLGATE_AUDIT_KEY="$(printf 'ab%.0s' $(seq 32))" \
  -e TOOLGATE_ADMIN_TOKEN=image-admin-token-0123456789abcdefghij \
  -e FAKE_UPSTREAM_TOKEN="$UPSTREAM_TOKEN" "$IMAGE" >/dev/null

ok=
for _ in $(seq 1 100); do
  if curl -fsS http://127.0.0.1:18090/healthz >/dev/null 2>&1; then ok=1; break; fi
  sleep 0.1
done
[[ -n $ok ]] || { docker logs "$RUN-gw" >&2; fail "the gateway did not become healthy"; }

# call PATH: read one sandbox file as alice; prints the JSON-RPC reply.
call() {
  curl -sS http://127.0.0.1:18090/mcp \
    -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2026-07-28' \
    -H 'Mcp-Method: tools/call' -H 'Mcp-Name: fake.read_file' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake.read_file","arguments":{"path":"'"$1"'"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
}

echo "== calls through /toolgate to the sandbox"
reply=$(call reports/q1.txt)
grep -q 'Q1 revenue grew 12%' <<<"$reply" || fail "reports/q1.txt through the gateway: $reply"
echo "allowed: reports/q1.txt"
reply=$(call secrets/.env)
grep -q 'example-only' <<<"$reply" && fail "secrets/.env leaked through the gateway: $reply"
grep -q '"error"\|"isError":true' <<<"$reply" || fail "secrets/.env was not refused: $reply"
echo "refused: secrets/.env"

echo "== stop"
for c in "$RUN-gw" "$RUN-fake"; do
  docker stop -t 10 "$c" >/dev/null
  code=$(docker inspect -f '{{.State.ExitCode}}' "$c")
  [[ $code == 0 ]] || { docker logs "$c" >&2; fail "$c exited with $code, want 0"; }
done
echo "both containers exited 0"

echo "== toolgate audit verify and policy test in the image"
docker run --rm -v "$RUN-data:/data:ro" --entrypoint /toolgate "$IMAGE" audit verify /data/audit.jsonl
docker run --rm -v "$DIR:/examples:ro" --entrypoint /toolgate "$IMAGE" \
  policy test /examples/policy.json /examples/policy_cases.json
echo "OK"
