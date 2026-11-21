#!/usr/bin/env bash
# Conditional access against a running `authz serve`: edit access that holds
# only from an allowed network (a caveat), and a viewer link that runs out
# (a relationship written with expires_at).
#   GRANTD_URL (default http://localhost:8080), GRANTD_API_KEY (default local-dev-key-0123456)
# Needs curl and python3. Takes about four seconds: it waits for the link to
# run out. CI runs it and compares its output with
# internal/authz/golden/testdata/caveats-demo.golden.
set -euo pipefail

URL="${GRANTD_URL:-http://localhost:8080}"
KEY="${GRANTD_API_KEY:-local-dev-key-0123456}"
DIR="$(cd "$(dirname "$0")" && pwd)"

call() { # method path json
  curl -fsS -X "$1" "$URL$2" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "$3"
}
field() { python3 -c "import sys, json; print(json.load(sys.stdin)['$1'])"; }
# answer prints a check response as allowed, denied or conditional on the
# parameters nobody supplied.
answer() {
  python3 -c '
import sys, json
r = json.load(sys.stdin)
if r.get("conditional"):
    print("conditional, missing " + ",".join(r["missing"]))
else:
    print("allowed" if r["allowed"] else "denied")'
}

echo "1. Write the schema: a caveat, ip_allowed, on group editors of a doc"
schema_json=$(python3 -c 'import json, sys; print(json.dumps({"schema": open(sys.argv[1]).read()}))' "$DIR/docs.schema")
call PUT /v1/schema "$schema_json" > /dev/null

# The link runs out three seconds from now.
expires=$(python3 -c 'import datetime as d; print((d.datetime.now(d.timezone.utc) + d.timedelta(seconds=3)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))')

echo "2. Engineering edits doc:design from the office network only; bob gets a viewer link for three seconds"
written=$(call POST /v1/relationships/write '{"updates":[
  {"op":"touch","relationship":"group:eng#member@user:alice"},
  {"op":"touch","relationship":"group:staff#member@group:eng#member"},
  {"op":"touch","relationship":"folder:root#viewer@group:staff#member"},
  {"op":"touch","relationship":"doc:design#parent@folder:root"},
  {"op":"touch","relationship":"doc:design#editor@group:eng#member",
   "caveat":{"name":"ip_allowed","context":{"allowed":"10.0.0.0/8"}}},
  {"op":"touch","relationship":"doc:design#viewer@user:bob","expires_at":"'"$expires"'"}
]}' | field written_at)

fresh() { echo "{\"mode\":\"at_least_as_fresh\",\"token\":\"$1\"}"; }
check() { # resource permission subject token [client_ip]
  local ctx="" from="(no context)"
  if [[ -n "${5:-}" ]]; then ctx=",\"context\":{\"client_ip\":\"$5\"}"; from="from $5"; fi
  result=$(call POST /v1/check "{\"resource\":\"$1\",\"permission\":\"$2\",\"subject\":\"$3\",
    \"consistency\":$(fresh "$4")$ctx}" | answer)
  printf '   %-10s %-4s %-10s %-16s -> %s\n' "$1" "$2" "$3" "$from" "$result"
}

echo "3. Alice's edit access depends on where the request comes from; her view access does not"
check doc:design edit user:alice "$written"
check doc:design edit user:alice "$written" 10.1.2.3
check doc:design edit user:alice "$written" 203.0.113.9
check doc:design view user:alice "$written" 203.0.113.9

echo "4. Which docs can alice edit, without and with her address?"
call POST /v1/lookup/resources '{"resource_type":"doc","permission":"edit","subject":"user:alice",
  "consistency":'"$(fresh "$written")"'}' | python3 -c 'import sys, json; r = json.load(sys.stdin); print("  ", json.dumps({k: r.get(k) for k in ("resource_ids", "conditional")}))'
call POST /v1/lookup/resources '{"resource_type":"doc","permission":"edit","subject":"user:alice",
  "consistency":'"$(fresh "$written")"',"context":{"client_ip":"10.1.2.3"}}' | python3 -c 'import sys, json; r = json.load(sys.stdin); print("  ", json.dumps({k: r.get(k) for k in ("resource_ids", "conditional")}))'

echo "5. Who can edit doc:design?"
call POST /v1/lookup/subjects '{"resource":"doc:design","permission":"edit","subject_type":"user",
  "consistency":'"$(fresh "$written")"'}' | python3 -c 'import sys, json; print("  ", json.dumps(json.load(sys.stdin)["subjects"]))'

echo "6. Read doc:design's relationships: the caveat with its stored context, and which ones expire"
call POST /v1/relationships/read '{"filter":{"resource_type":"doc","resource_id":"design"},
  "consistency":'"$(fresh "$written")"'}' | python3 -c '
import sys, json
r = json.load(sys.stdin)
for rel in r["relationships"]:
    extra = ""
    if rel in r.get("caveats", {}):
        extra += " with " + json.dumps(r["caveats"][rel])
    if rel in r.get("expires_at", {}):
        extra += " (expires)"
    print("   " + rel + extra)'

echo "7. Bob's link, before and after it runs out"
check doc:design view user:bob "$written"
python3 -c 'import datetime as d, sys, time
t = d.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
time.sleep(max(0, (t - d.datetime.now(d.timezone.utc)).total_seconds()) + 0.2)' "$expires"
echo "   the link has run out, but the newest revision was committed before that: a snapshot never changes"
check doc:design view user:bob "$written"
echo "   the next write commits a revision after the expiry, and from there on bob is denied"
later=$(call POST /v1/relationships/write '{"updates":[{"op":"touch","relationship":"doc:notes#owner@user:alice"}]}' | field written_at)
check doc:design view user:bob "$later"
call POST /v1/relationships/read '{"filter":{"resource_type":"doc","resource_id":"design","relation":"viewer"},
  "consistency":'"$(fresh "$later")"'}' | python3 -c 'import sys, json; print("   viewers of doc:design:", json.load(sys.stdin)["relationships"])'
