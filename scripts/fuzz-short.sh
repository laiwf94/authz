#!/usr/bin/env bash
# The CI fuzz targets, each run for its time budget. With SHARD/COUNT (such
# as 2/3) only every COUNT-th target from the SHARD-th runs, so CI spreads
# them over parallel jobs; with no argument every target runs, one after
# another, as a local gate run does. The list and the times are the gate:
# change them here, not in ci.yml.
set -euo pipefail

TARGETS=(
  "./internal/authz/schema FuzzParse 30s"
  "./internal/authz/store FuzzParseRelationship 30s"
  "./internal/platform/storage/wal FuzzScan 20s"
  "./internal/platform/jose FuzzParse$ 20s"
  "./internal/platform/jose FuzzParseKeySet 20s"
  "./internal/platform/jose FuzzVerifyHMAC 20s"
  "./internal/platform/seal FuzzOpen 20s"
  "./internal/authn/redirect FuzzValidate 20s"
  "./internal/authn/saml FuzzParseResponse 30s"
  "./internal/authn/saml FuzzParseMetadata 20s"
  "./internal/authn/config FuzzCheck 20s"
  "./internal/platform/config FuzzCheck 20s"
  "./internal/agents/jsonrpc FuzzDecode 20s"
  "./internal/agents/schema FuzzCompileValidate 20s"
  "./internal/agents/policy FuzzParse 20s"
  "./internal/agents/policy FuzzCases 20s"
  "./internal/agents/identity FuzzAuthenticate 20s"
  "./internal/platform/audit FuzzVerify 20s"
  "./internal/platform/audit FuzzParseFilter 20s"
  "./internal/platform/audit FuzzParseIndex 20s"
  "./internal/platform/logging FuzzParseTraceparent 20s"
  "./internal/platform/logging FuzzScan 20s"
  "./internal/platform/merkle FuzzUnmarshal 20s"
)

shard=1 count=1
if (($# > 0)); then
  if [[ ! $1 =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] || ((BASH_REMATCH[1] > BASH_REMATCH[2])); then
    echo "usage: $0 [SHARD/COUNT]" >&2
    exit 2
  fi
  shard=${BASH_REMATCH[1]} count=${BASH_REMATCH[2]}
fi

for i in "${!TARGETS[@]}"; do
  ((i % count == shard - 1)) || continue
  read -r pkg fuzz time <<<"${TARGETS[$i]}"
  echo "== $pkg $fuzz $time"
  go test "$pkg" -run='^$' -fuzz="$fuzz" -fuzztime="$time"
done
