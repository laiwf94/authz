#!/usr/bin/env bash
# Builds the authz binary, starts `authz mcpfake` and `authz mcp` (formerly
# toolgate) with the files in this directory, and walks an agent through every
# control: filtered tool lists, an allowed call, argument constraints, output
# redaction, rate limits, human approval, tool-definition change detection,
# and a tamper-evident audit log.
#
# Needs go, curl and python3. Uses ports 18080, 18081 and 19100 on 127.0.0.1.
#
# The audit log the scenarios produce is compared with the recorded decisions
# in demo_decisions.jsonl (timestamps, latencies and per-run identifiers
# normalised; see scripts/recorded-decisions.go), and the demo fails on any
# difference. DEMO_RECORD=1 rewrites the recording instead.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
WORK="$(mktemp -d)"
GW=http://127.0.0.1:18080
ADMIN=http://127.0.0.1:18081
FAKE=http://127.0.0.1:19100
ALICE=tgk_demo_alice_0123456789abcdefghijklmnop
BOB=tgk_demo_bob_0123456789abcdefghijklmnopqr
ADMIN_TOKEN=demo-admin-token-0123456789abcdefghij
FAKE_ADMIN=demo-fake-admin-0123456789
export FAKE_UPSTREAM_TOKEN=demo-upstream-secret-0123456789

cleanup() {
  [[ -n "${TG_PID:-}" ]] && kill "$TG_PID" 2>/dev/null || true
  [[ -n "${FAKE_PID:-}" ]] && kill "$FAKE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() { # url
  for _ in $(seq 1 100); do curl -fsS "$1" >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "timed out waiting for $1" >&2; return 1
}

echo "== build"
(cd "$REPO" && go build -o "$WORK/authz" ./cmd/authz)
cp "$DIR/policy.json" "$WORK/policy.json"
mkdir -p "$WORK/state"

MCPFAKE_ADDR=127.0.0.1:19100 MCPFAKE_SANDBOX="$DIR/sandbox" MCPFAKE_TOKEN="$FAKE_UPSTREAM_TOKEN" \
  MCPFAKE_ADMIN_TOKEN="$FAKE_ADMIN" MCPFAKE_HTTP_ALLOW=example.com \
  "$WORK/authz" mcpfake >"$WORK/mcpfake.log" 2>&1 &
FAKE_PID=$!
TOOLGATE_ADDR=127.0.0.1:18080 TOOLGATE_ADMIN_ADDR=127.0.0.1:18081 TOOLGATE_ADMIN_TOKEN="$ADMIN_TOKEN" \
  TOOLGATE_CONFIG="$DIR/config.json" TOOLGATE_POLICY="$WORK/policy.json" \
  TOOLGATE_AUDIT_LOG="$WORK/audit.jsonl" TOOLGATE_AUDIT_KEY="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  TOOLGATE_STATE_DIR="$WORK/state" "$WORK/authz" mcp >"$WORK/mcp.log" 2>&1 &
TG_PID=$!
wait_for "$FAKE/healthz"
wait_for "$GW/healthz"

ID=0
# mcp KEY METHOD PARAMS_JSON [extra curl args]: one modern (2026-07-28) MCP
# request. Prints "HTTP <status>" and the JSON body.
mcp() {
  local key=$1 method=$2 params=$3; shift 3
  ID=$((ID + 1))
  local body name
  body=$(python3 -c '
import json, sys
p = json.loads(sys.argv[3])
p["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
              "io.modelcontextprotocol/clientCapabilities": {},
              "io.modelcontextprotocol/clientInfo": {"name": "demo-agent", "version": "1"}}
print(json.dumps({"jsonrpc": "2.0", "id": int(sys.argv[1]), "method": sys.argv[2], "params": p}))' "$ID" "$method" "$params")
  name=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1]).get("name", ""))' "$params")
  local args=(-sS -D "$WORK/headers" -o "$WORK/body" -w '%{http_code}' "$GW/mcp"
    -H "Authorization: Bearer $key" -H 'Content-Type: application/json'
    -H 'Accept: application/json, text/event-stream'
    -H 'MCP-Protocol-Version: 2026-07-28' -H "Mcp-Method: $method")
  [[ -n "$name" ]] && args+=(-H "Mcp-Name: $name")
  local status
  status=$(curl "${args[@]}" "$@" -d "$body")
  echo "HTTP $status $(cat "$WORK/body")"
}

# show: summarize a tools/call reply on one line.
show() {
  python3 -c '
import json, sys
status, body = sys.stdin.read().split(" ", 2)[1:]
r = json.loads(body)
if "error" in r:
    e = r["error"]; d = e.get("data", {})
    extra = " ".join("%s=%s" % (k, d[k]) for k in ("rule_id", "approval_id", "scope") if k in d)
    print(("   HTTP %s  error %s: %s  %s" % (status, e["code"], e["message"], extra)).rstrip())
else:
    text = "".join(c.get("text", "") for c in r["result"].get("content", []))
    print("   HTTP %s  ok: %s" % (status, text.strip()[:110]))'
}

tools() { # key
  mcp "$1" tools/list '{}' | python3 -c '
import json, sys
r = json.loads(sys.stdin.read().split(" ", 2)[2])
print("   " + ", ".join(t["name"] for t in r["result"]["tools"]))'
}

admin() { # method path [json]
  curl -fsS -X "$1" "$ADMIN$2" -H "Authorization: Bearer $ADMIN_TOKEN" ${3:+-H 'Content-Type: application/json' -d "$3"}
}

echo
echo "1. Each agent sees only the tools its policy allows"
echo "   alice-bot:"; tools "$ALICE"
echo "   bob-bot:"; tools "$BOB"

echo
echo "2. An allowed call (the gateway adds the upstream credential; the agent never sees it)"
mcp "$ALICE" tools/call '{"name":"fake.read_file","arguments":{"path":"reports/q1.txt"}}' | show

echo
echo "3. Argument constraints: path traversal, a .env file, and an SSRF attempt"
mcp "$ALICE" tools/call '{"name":"fake.read_file","arguments":{"path":"../../etc/passwd"}}' | show
mcp "$ALICE" tools/call '{"name":"fake.read_file","arguments":{"path":"secrets/.env"}}' | show
mcp "$ALICE" tools/call '{"name":"fake.http_get","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}' | show

echo
echo "4. Output guarding: a secret in a tool result is redacted"
mcp "$ALICE" tools/call '{"name":"fake.read_file","arguments":{"path":"reports/deploy-notes.txt"}}' | show

echo
echo "5. Rate limit: alice-bot may call one tool 3 times in a burst, then 1 per second"
for _ in 1 2 3 4; do mcp "$ALICE" tools/call '{"name":"fake.echo","arguments":{"text":"ping"}}' | show; done
echo "   Retry-After: $(grep -i '^retry-after' "$WORK/headers" | tr -d '\r' | cut -d' ' -f2)s"

echo
echo "6. Human approval: the first call is parked"
TRANSLATE='{"name":"fake.translate","arguments":{"text":"The release ships on Friday.","language":"de"}}'
reply=$(mcp "$ALICE" tools/call "$TRANSLATE" -H 'Mcp-Param-Language: de')
echo "$reply" | show
APPROVAL=$(echo "$reply" | python3 -c 'import json, sys; print(json.loads(sys.stdin.read().split(" ", 2)[2])["error"]["data"]["approval_id"])')
echo "   an administrator reviews it:"
admin GET "/admin/approvals/$APPROVAL" | python3 -c 'import json, sys; r = json.load(sys.stdin); print("   %s wants %s with %s" % (r["agent_id"], r["tool"], json.dumps(r["arguments"])))'
admin POST "/admin/approvals/$APPROVAL/approve" '{"ttl_seconds":120,"note":"fine to translate"}' >/dev/null
echo "   approved; the agent retries the same call:"
mcp "$ALICE" tools/call "$TRANSLATE" -H 'Mcp-Param-Language: de' | show
echo "   an approval is single use; calling again needs a new one:"
mcp "$ALICE" tools/call "$TRANSLATE" -H 'Mcp-Param-Language: de' | show

echo
echo "7. Rug pull: the upstream swaps the translate tool's description for one with injected instructions"
curl -fsS -X POST "$FAKE/admin/rugpull" -H "Authorization: Bearer $FAKE_ADMIN" >/dev/null
sleep 1.2 # the demo config refreshes tool lists every second
echo "   alice-bot's tool list no longer offers it:"; tools "$ALICE"
mcp "$ALICE" tools/call "$TRANSLATE" -H 'Mcp-Param-Language: de' | show
admin GET /admin/tools | python3 -c '
import json, sys
for t in json.load(sys.stdin)["tools"]:
    if t["status"] == "quarantined":
        print("   quarantined %s, new description: \"%s...\"" % (t["tool"], t["pending_definition"]["description"][:90]))'

echo
echo "8. The audit log is a hash chain"
"$WORK/authz" mcp audit verify "$WORK/audit.jsonl" | sed 's/^/   /'
echo "   and it holds exactly the decisions recorded for this demo:"
(cd "$REPO" && go run scripts/recorded-decisions.go ${DEMO_RECORD:+-update} \
  toolgate/examples/demo_decisions.jsonl "$WORK/audit.jsonl") | sed 's/^/   /'
LINE=$(python3 -c '
import sys
path = sys.argv[1]
lines = open(path).read().splitlines(True)
for i, l in enumerate(lines):
    if "\"decision\":\"deny\"" in l:
        lines[i] = l.replace("\"decision\":\"deny\"", "\"decision\":\"allow\"", 1)
        open(path, "w").writelines(lines)
        print(i + 1)
        break' "$WORK/audit.jsonl")
echo "   someone rewrites line $LINE to turn a denial into an allow..."
"$WORK/authz" mcp audit verify "$WORK/audit.jsonl" | sed 's/^/   /' || true

echo
echo "Done. Logs were in $WORK (removed on exit)."
