#!/bin/sh
# testbody-diff.sh proves that the week 1 moves changed nothing in any test
# file outside its import block and package clause, and that every package
# kept its tests.
#
#   scripts/testbody-diff.sh [-v] [BASE [HEAD]]
#
# BASE defaults to 41d9bf0, the last commit before the first move: grantd at
# the root, wicket under wicket/ and toolgate under toolgate/, each with its
# own go.mod. HEAD defaults to HEAD. Every _test.go file of BASE is paired
# with its new path and the package clause and import declarations are
# removed from both. Every old top-level declaration must still be there with
# the same lines, and so must the comments outside declarations; any other
# changed line is printed and fails the run, unless scripts/testbody-allow.txt
# lists it (relative fixture paths that gained a directory level). Packages
# that later collapsed into one pair their old test files with the new one
# through scripts/testbody-merge.txt, and each must still be clean. Tests and
# helpers added after the move are reported, not failed, except init and
# TestMain. A per-package table of test functions before and after follows.
# Exit status: 0 clean, 1 changed or missing, 2 usage or git error.
# See internal/testbody and scripts/testbody-diff.go.
set -eu

verbose=
if [ "${1:-}" = "-v" ]; then
	verbose=-v
	shift
fi
base=${1:-41d9bf0af08b3f40e8292635831a76ce8714d27c}
head=${2:-HEAD}

cd "$(dirname "$0")/.."
exec go run scripts/testbody-diff.go $verbose -allow scripts/testbody-allow.txt -merge scripts/testbody-merge.txt "$base" "$head"
