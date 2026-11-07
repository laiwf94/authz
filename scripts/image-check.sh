#!/usr/bin/env bash
# image-check.sh builds the two images and checks that a deployment written
# for the old wicket image still works against them:
#
#   - /wicket is a symlink to /authz in both images (not a second binary);
#   - "wicket -h", "wicket genkey", "wicket check" and an unknown subcommand
#     behave as "authz gateway" does, with "wicket" in the messages;
#   - the gateway serves the same wicket config and WICKET_* environment
#     whether it is started as /wicket (the old entrypoint), as the gateway
#     image's default "authz gateway", or as "authz gateway" in the main
#     image, and the forward-auth answers are byte-identical apart from Date
#     and the per-request ID.
#
#   scripts/image-check.sh
#
# AUTHZ_IMAGE and GATEWAY_IMAGE name images that are already built; without
# them the script builds Dockerfile and wicket/Dockerfile from the repository
# root. Needs docker and curl. Uses ports 4190-4192 on 127.0.0.1.
# Exit status: 0 when every check passes, 1 otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."
WORK="$(mktemp -d)"
CONTAINERS=()
cleanup() {
	for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT

ok() { printf '   ok: %s\n' "$*"; }
fail() {
	printf '   FAILED: %s\n' "$*"
	exit 1
}

if [[ -z "${AUTHZ_IMAGE:-}" ]]; then
	AUTHZ_IMAGE=authz-image-check
	docker build -q -t "$AUTHZ_IMAGE" . >/dev/null
fi
if [[ -z "${GATEWAY_IMAGE:-}" ]]; then
	GATEWAY_IMAGE=authz-gateway-image-check
	docker build -q -f wicket/Dockerfile -t "$GATEWAY_IMAGE" . >/dev/null
fi

printf '== /wicket in both images\n'
for img in "$AUTHZ_IMAGE" "$GATEWAY_IMAGE"; do
	# distroless has no shell, so inspect the files from an exported copy.
	id=$(docker create "$img")
	docker export "$id" | tar -C "$WORK" -xf - authz wicket
	docker rm "$id" >/dev/null
	[[ -L "$WORK/wicket" && "$(readlink "$WORK/wicket")" == authz ]] || fail "$img: /wicket is not a symlink to authz"
	[[ -f "$WORK/authz" && ! -L "$WORK/authz" && -x "$WORK/authz" ]] || fail "$img: /authz is not an executable file"
	rm -f "$WORK/authz" "$WORK/wicket"
	ok "$img: /wicket -> authz"
done

printf '== the wicket name behaves as authz gateway\n'
run() { docker run --rm "$@"; }
hex='^[0-9a-f]{64}$'
[[ "$(run --entrypoint /wicket "$AUTHZ_IMAGE" genkey)" =~ $hex ]] || fail "wicket genkey"
[[ "$(run "$AUTHZ_IMAGE" gateway genkey)" =~ $hex ]] || fail "authz gateway genkey"
[[ "$(run "$GATEWAY_IMAGE" genkey)" =~ $hex ]] || fail "gateway image genkey"
ok "genkey prints a 256-bit key as wicket, authz gateway and the gateway image"
# The whole output first: grep -q stops reading at the first match, and the
# key's remaining lines would then hit a closed pipe (#233).
pem=$(run --entrypoint /wicket "$AUTHZ_IMAGE" gensigningkey) || fail "wicket gensigningkey exited non-zero"
[[ "$pem" == *'-----BEGIN '* ]] || fail "wicket gensigningkey"
ok "wicket gensigningkey prints a PEM key"
help=$(run --entrypoint /wicket "$AUTHZ_IMAGE" -h 2>&1) || fail "wicket -h exited non-zero"
[[ "$(head -1 <<<"$help")" == "usage: wicket" ]] || fail "wicket -h: $(head -1 <<<"$help")"
ok "wicket -h exits 0 with usage: wicket"
set +e
msg=$(run --entrypoint /wicket "$AUTHZ_IMAGE" bogus 2>&1)
code=$?
set -e
[[ $code == 2 && "$msg" == 'wicket: unknown command "bogus"'* ]] || fail "wicket bogus: exit $code: $msg"
ok "an unknown wicket subcommand exits 2"

# A config file as the old image's users mount it, with only offline-checkable
# references, so nothing needs the network.
cat >"$WORK/wicket.json" <<'EOF'
{
  "public_url": "https://app.example.com/_wicket",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://login.example.com",
     "client_id": "wicket", "client_secret_env": "CORP_SECRET"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["app.example.com"], "providers": ["corp"],
     "allow": {"groups": ["eng"]}}
  ]
}
EOF
chmod 644 "$WORK/wicket.json"
mount=(-v "$WORK/wicket.json:/etc/wicket/wicket.json:ro")
out=$(run "${mount[@]}" -e CORP_SECRET=s --entrypoint /wicket "$AUTHZ_IMAGE" check /etc/wicket/wicket.json)
[[ "$out" == "/etc/wicket/wicket.json: ok, 1 provider and 1 app, 0 warnings (offline checks)" ]] || fail "wicket check: $out"
ok "wicket check accepts the config"
set +e
run "${mount[@]}" --entrypoint /wicket "$AUTHZ_IMAGE" check /etc/wicket/wicket.json >/dev/null 2>&1
code=$?
set -e
[[ $code == 1 ]] || fail "wicket check with CORP_SECRET unset exited $code, want 1"
ok "wicket check exits 1 when the client secret is missing"

printf '== the same config served three ways\n'
cookie_key=$(run "$GATEWAY_IMAGE" genkey)
serve() { # name port image [args...]
	local name=$1 port=$2
	shift 2
	docker run -d --name "$name" -p "127.0.0.1:$port:4180" "${mount[@]}" \
		-e CORP_SECRET=s -e WICKET_CONFIG=/etc/wicket/wicket.json \
		-e WICKET_COOKIE_KEYS="$cookie_key" -e WICKET_ADDR=0.0.0.0:4180 \
		"$@" >/dev/null
	CONTAINERS+=("$name")
}
serve image-check-wicket 4190 --entrypoint /wicket "$AUTHZ_IMAGE"
serve image-check-gateway 4191 "$GATEWAY_IMAGE"
serve image-check-authz 4192 "$AUTHZ_IMAGE" gateway
for port in 4190 4191 4192; do
	for _ in $(seq 1 50); do
		curl -sf -o /dev/null "http://127.0.0.1:$port/healthz" && break
		sleep 0.2
	done
	curl -sf -o /dev/null "http://127.0.0.1:$port/healthz" || {
		docker logs "${CONTAINERS[$((port - 4190))]}" 2>&1 | tail -5
		fail "nothing healthy on :$port"
	}
done
ok "all three are healthy"

# capture PORT NAME CURL-ARGS...: the full response without the Date header,
# with the per-request ID replaced by <request-id> wherever it appears.
capture() {
	local port=$1 name=$2 raw id
	shift 2
	raw=$(curl -sS -i "$@" "http://127.0.0.1:$port/auth" | tr -d '\r' | grep -v -i '^date:')
	id=$(sed -n 's/^X-Request-Id: \([0-9a-f]*\)$/\1/Ip' <<<"$raw")
	[[ -n "$id" ]] || fail "$name: no X-Request-Id on :$port"
	printf '%s\n' "${raw//$id/<request-id>}" >"$WORK/$name.$port"
}
requests=(
	"api:-H X-Forwarded-Host:app.example.com"
	"browser:-H X-Forwarded-Host:app.example.com -H Accept:text/html"
	"redirect:-H X-Forwarded-Host:app.example.com -H Accept:text/html -G -d redirect=1"
	"unknown-host:-H X-Forwarded-Host:other.example.com"
	"forged-cookie:-H X-Forwarded-Host:app.example.com -b __Host-wicket=forged"
)
for r in "${requests[@]}"; do
	name=${r%%:*}
	read -r -a args <<<"${r#*:}"
	for port in 4190 4191 4192; do capture "$port" "$name" "${args[@]}"; done
	[[ -s "$WORK/$name.4190" ]] || fail "$name: empty response"
	diff -u "$WORK/$name.4190" "$WORK/$name.4191" || fail "$name: the gateway image answers differently from /wicket"
	diff -u "$WORK/$name.4190" "$WORK/$name.4192" || fail "$name: authz gateway answers differently from /wicket"
	ok "$name: $(head -1 "$WORK/$name.4190"), identical from all three"
done
grep -q '^X-Auth-Redirect: https://app.example.com/_wicket/login?app=wiki' "$WORK/api.4190" ||
	fail "the API request did not get the login redirect"
ok "a signed-out request is sent to the configured login page"

printf '\nimage checks passed\n'
