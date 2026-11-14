#!/usr/bin/env bash
# One audit chain, end to end. Builds the authz binary and starts authz
# serve, authz gateway and authz mcp as three processes writing one signed
# audit log that rotates every 16 KiB, then:
#
#   1. keeps them busy from several clients at once: permission checks,
#      sign-on denials and an agent's tool calls, some denied;
#   2. saves a signed checkpoint, as an auditor would, partway through;
#   3. verifies the rotated log, every segment as one chain, against the
#      newest checkpoint with only the public key;
#   4. queries it for the agent's denied calls, and hands the auditor a proof
#      of one of them, which auditor.sh checks holding only the public key,
#      and refuses when the claim about the record is not what was logged;
#   5. removes a middle segment from a copy and watches verify and query
#      name it.
#
# Needs go, curl and sha256sum. Uses ports 18280 to 18285 and 19200 on
# 127.0.0.1. CI runs it (the "Demo (audit)" step).
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
WORK="$(mktemp -d)"
LOG="$WORK/audit.jsonl"
SERVE=http://127.0.0.1:18280
GW=http://127.0.0.1:18281
MCP=http://127.0.0.1:18283
ADMIN=http://127.0.0.1:18284
FAKE=127.0.0.1:19200
API_KEY=audit-demo-api-key-0123456789
AGENT=tgk_audit_demo_0123456789abcdefghijklmn
ADMIN_TOKEN=audit-demo-admin-0123456789abcdefghijk
CLIENTS=4 ROUNDS=20

PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${DEMO_KEEP:-}" ]] || rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() { # url
  for _ in $(seq 1 100); do curl -fsS "$1" >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "timed out waiting for $1" >&2; return 1
}
indent() { sed 's/^/   /'; }
short() { awk '{ if (substr($0, 1, 1) == "{" && length($0) > 150) $0 = substr($0, 1, 150) "..."; print "   " $0 }'; }

echo "== build"
(cd "$REPO" && go build -o "$WORK/authz" ./cmd/authz)
AUTHZ="$WORK/authz"

echo
echo "0. A signing key for checkpoints; the auditor gets the public key"
PUB=$("$AUTHZ" audit keygen -out "$WORK/audit.key" audit.demo)
echo "$PUB" | indent

# Every subcommand signs checkpoints with the one key, every second, and
# cuts the shared file into 16 KiB segments.
export AUTHZ_AUDIT_SIGNING_KEY_FILE="$WORK/audit.key" AUTHZ_AUDIT_CHECKPOINT_INTERVAL=1s

GRANTD_ADDR=127.0.0.1:18280 GRANTD_API_KEYS="$API_KEY" GRANTD_DATA_DIR= \
  GRANTD_AUDIT_LOG="$LOG" GRANTD_AUDIT_CHECKS=true GRANTD_AUDIT_ROTATE_BYTES=16384 \
  "$AUTHZ" serve >"$WORK/serve.log" 2>&1 &
PIDS+=($!)

cat >"$WORK/gateway.json" <<JSON
{"public_url": "https://auth.example.com",
 "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "CORP_SECRET"}],
 "apps": [{"id": "wiki", "hosts": ["wiki.example.com"], "providers": ["corp"], "allow": {"any_user": true}}]}
JSON
CORP_SECRET=demo WICKET_CONFIG="$WORK/gateway.json" \
  WICKET_COOKIE_KEYS=0011223344556677889900112233445566778899001122334455667788990011 \
  WICKET_ADDR=127.0.0.1:18281 WICKET_ADMIN_ADDR=127.0.0.1:18282 \
  WICKET_AUDIT_LOG="$LOG" WICKET_AUDIT_ROTATE_BYTES=16384 \
  "$AUTHZ" gateway >"$WORK/gateway.log" 2>&1 &
PIDS+=($!)

MCPFAKE_ADDR=$FAKE MCPFAKE_SANDBOX="$REPO/toolgate/examples/sandbox" "$AUTHZ" mcpfake >"$WORK/mcpfake.log" 2>&1 &
PIDS+=($!)
cat >"$WORK/mcp.json" <<JSON
{"tokens": {"issuer": "authz", "audience": "audit-demo"},
 "agents": [{"id": "report-bot", "owner": "alice", "scopes": ["files:read"],
             "token_sha256": "$(printf %s "$AGENT" | sha256sum | cut -d' ' -f1)"}],
 "upstreams": [{"name": "fake", "url": "http://$FAKE/mcp"}],
 "limits": {"agent_rps": 1000, "agent_burst": 1000, "tool_rps": 1000, "tool_burst": 1000, "daily_quota": 100000}}
JSON
cat >"$WORK/policy.json" <<'JSON'
{"version": 1, "rules": [
  {"id": "read-reports", "effect": "allow", "scopes": ["files:read"], "upstreams": ["fake"], "tools": ["read_file"],
   "arguments": {"required": ["path"], "properties": {"path": {"type": "string", "x-path-prefix": ["reports"]}}}}]}
JSON
AUTHZ_MCP_ADDR=127.0.0.1:18283 AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:18284 AUTHZ_MCP_ADMIN_TOKEN="$ADMIN_TOKEN" \
  AUTHZ_MCP_CONFIG="$WORK/mcp.json" AUTHZ_MCP_POLICY="$WORK/policy.json" \
  AUTHZ_MCP_AUDIT_LOG="$LOG" AUTHZ_MCP_AUDIT_KEY=$(printf '%064d' 7) AUTHZ_MCP_AUDIT_ROTATE_BYTES=16384 \
  "$AUTHZ" mcp >"$WORK/mcp.log" 2>&1 &
PIDS+=($!)
wait_for "$SERVE/healthz"
wait_for "$GW/healthz"
wait_for "http://$FAKE/healthz"
wait_for "$MCP/healthz"

api() { # path json [method]
  curl -fsS -o /dev/null -X "${3:-POST}" "$SERVE$1" -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' -d "$2"
}
call() { # tool arguments_json: prints the HTTP status
  curl -sS -o /dev/null -w '%{http_code}\n' "$MCP/mcp" -H "Authorization: Bearer $AGENT" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H "Mcp-Name: fake.$1" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"fake.$1\",\"arguments\":$2,
        \"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}
admin() { # path [method]
  curl -fsS -X "${2:-GET}" "$ADMIN$1" -H "Authorization: Bearer $ADMIN_TOKEN"
}

api /v1/schema '{"schema":"definition user {}\ndefinition doc {\n  relation viewer: user\n  permission view = viewer\n}"}' PUT
api /v1/relationships/write '{"updates":[{"op":"touch","relationship":"doc:q1#viewer@user:alice"}]}'

client() { # n: one client's rounds of a check, a sign-on denial and two tool calls
  for i in $(seq 1 "$ROUNDS"); do
    api /v1/check "{\"resource\":\"doc:q1\",\"permission\":\"view\",\"subject\":\"user:u$1-$i\"}"
    curl -sS -o /dev/null "$GW/auth" -H 'X-Forwarded-Proto: https' -H "X-Forwarded-Host: unknown-$1-$i.example.com" -H 'X-Forwarded-Uri: /'
    call read_file '{"path":"reports/q1.txt"}' >/dev/null
    call http_get "{\"url\":\"https://example.com/$1/$i\"}" >/dev/null
  done
}

busy() { # first client number
  local jobs=()
  for c in $(seq "$1" $(($1 + CLIENTS - 1))); do client "$c" & jobs+=($!); done
  wait "${jobs[@]}"
}

echo
echo "1. $CLIENTS clients at once, $ROUNDS rounds each: a check, a sign-on denial and two tool calls"
busy 1
echo
echo "2. The auditor saves the newest signed checkpoint, then $CLIENTS more clients keep going"
admin /admin/audit/checkpoint >"$WORK/saved.checkpoint"
cp "$WORK/saved.checkpoint" "$WORK/first.checkpoint"
sed -n 2p "$WORK/saved.checkpoint" | sed 's/^/   it covers records 1 to /'
busy $((CLIENTS + 1))
segments=$(ls "$LOG".[0-9]* | grep -cv '\.idx$')
echo "   the three processes cut $segments segments between them"

echo
echo "3. Every segment is one chain, and the newest checkpoint covers it, checked with the public key"
"$AUTHZ" audit verify -key "$PUB" "$LOG" | indent

echo
echo "4. The operator looks up the agent's denied calls, and proves one to the auditor"
"$AUTHZ" audit query -count "$LOG" agent=report-bot tool=http_get decision=deny 2>/dev/null |
  sed 's/^/   denied http_get calls: /'
line=$("$AUTHZ" audit query -limit 1 "$LOG" agent=report-bot tool=http_get decision=deny 2>/dev/null)
record=$(echo "$line" | sed -E 's/^\{"seq":([0-9]+),.*/\1/')
mkdir "$WORK/evidence"
admin /admin/audit/checkpoint >"$WORK/evidence/checkpoint"
size=$(sed -n 2p "$WORK/evidence/checkpoint")
admin "/admin/audit/proof?record=$record&size=$size" >"$WORK/evidence/record.proof"
admin "/admin/audit/proof?from=$(sed -n 2p "$WORK/saved.checkpoint")&size=$size" >"$WORK/evidence/grew.proof"
echo "   record $record, against the checkpoint of $size records"

echo
echo "   The auditor, with the public key, the checkpoint saved in step 2 and the evidence:"
AUTHZ="$AUTHZ" "$DIR/auditor.sh" "$PUB" "$WORK/saved.checkpoint" "$WORK/evidence" \
  track=agents agent=report-bot tool=http_get decision=deny rule=default-deny | short
cmp -s "$WORK/saved.checkpoint" "$WORK/evidence/checkpoint" && echo "   (the auditor now keeps the newer checkpoint)"

echo
echo "   The same evidence does not back a claim that the call was allowed:"
if AUTHZ="$AUTHZ" "$DIR/auditor.sh" "$PUB" "$WORK/first.checkpoint" "$WORK/evidence" \
  agent=report-bot tool=http_get decision=allow | short; then
  echo "the auditor accepted a claim the log does not hold" >&2; exit 1
fi

for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
wait 2>/dev/null || true
PIDS=()

echo
echo "5. Someone removes a middle segment of a copy"
mkdir "$WORK/copy"
cp -p "$LOG"* "$WORK/copy/"
COPY="$WORK/copy/audit.jsonl"
middle=$(ls "$COPY".[0-9]* | grep -v '\.idx$' | sed -n "$((segments / 2))p")
rm "$middle"
echo "   removed $(basename "$middle")"
named="a segment ($(basename "$middle")) was removed"
if out=$("$AUTHZ" audit verify -key "$PUB" "$COPY"); then
  echo "verify passed without a segment" >&2; exit 1
fi
echo "   verify: $out"
grep -qF "$named" <<<"$out" || { echo "verify did not name the segment" >&2; exit 1; }
if out=$("$AUTHZ" audit query -count -full "$COPY" decision=deny 2>&1 >/dev/null); then
  echo "query passed without a segment" >&2; exit 1
fi
echo "   query:  $out"
grep -qF "$named" <<<"$out" || { echo "query did not name the segment" >&2; exit 1; }

echo
echo "Done. Logs were in $WORK (removed on exit)."
