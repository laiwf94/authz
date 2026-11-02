#!/bin/sh
# staticcheck.sh runs staticcheck over the whole module with the Go
# toolchain go.mod asks for, and fails on any finding that
# scripts/staticcheck-allow.txt does not list. The list may only name lines in
# test files the week 1 moves froze (see scripts/testbody-diff.sh); everything
# else is fixed. See scripts/staticcheck.go and internal/gate.
#
#   scripts/staticcheck.sh [PACKAGES...]    (default ./...)
#
# Exit status: 0 clean, 1 findings or stale allow entries, 2 usage or run
# error.
set -eu

cd "$(dirname "$0")/.."
# staticcheck must be built with the toolchain the module needs: built with
# an older one it cannot type-check the standard library of the newer one.
toolchain=$(go env GOVERSION)
[ $# -gt 0 ] || set -- ./...
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
GOTOOLCHAIN=$toolchain GOBIN=$bin go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOTOOLCHAIN=$toolchain go run scripts/staticcheck.go -allow scripts/staticcheck-allow.txt -- \
	"$bin/staticcheck" "$@"
