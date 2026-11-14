#!/usr/bin/env bash
# The auditor's side of the audit log: proves, holding only the log's public
# key, that a record matching TERMs was logged, and that the log the
# operator shows now extends the one the auditor saw last time. Nothing the
# operator says is taken on trust; the log itself is never needed.
#
# usage: auditor.sh PUBLIC_KEY SAVED_CHECKPOINT EVIDENCE_DIR TERM...
#
#   PUBLIC_KEY        what `authz audit keygen` printed (NAME+HASH+KEY), or a file holding it
#   SAVED_CHECKPOINT  the signed checkpoint the auditor kept from last time
#   EVIDENCE_DIR      what the operator handed over:
#                       checkpoint    a signed checkpoint, newer than the saved one
#                       record.proof  an inclusion proof of one record against it
#                       grew.proof    a consistency proof from the saved checkpoint to it
#   TERM...           what the record must be, in `authz audit query` terms,
#                     such as track=agents tool=http_get decision=deny
#
# Exits 0 when both proofs hold and the record matches, then keeps the
# operator's checkpoint as SAVED_CHECKPOINT for next time; exits 1 otherwise
# and keeps the old one. AUTHZ names the binary (default: authz on PATH).
set -euo pipefail

if (($# < 4)); then
  sed -n '7,17p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
AUTHZ="${AUTHZ:-authz}"
KEY=$1 SAVED=$2 EVIDENCE=$3
shift 3

# 1. The operator's log extends the one the auditor saw: nothing the saved
#    checkpoint covers was removed, changed or reordered since, and the
#    operator is not showing a second, forked log.
"$AUTHZ" audit prove -check "$EVIDENCE/grew.proof" -key "$KEY" \
  -checkpoint "$EVIDENCE/checkpoint" -old "$SAVED"

# 2. The record is one of the records that checkpoint covers, byte for byte
#    as logged, and it is the record the claim is about.
"$AUTHZ" audit prove -check "$EVIDENCE/record.proof" -key "$KEY" \
  -checkpoint "$EVIDENCE/checkpoint" "$@"

# 3. Both held, so the operator's checkpoint is the auditor's view from now
#    on: next time, the log must extend this one.
cp "$EVIDENCE/checkpoint" "$SAVED.new"
mv "$SAVED.new" "$SAVED"
