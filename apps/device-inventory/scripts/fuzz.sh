#!/bin/sh
# Runs every fuzz target in this module for FUZZTIME each (default 10s).
# CI: `apps/device-inventory/scripts/fuzz.sh` (optionally FUZZTIME=30s).
# The seed corpora also run as ordinary tests under `go test ./...`.
set -eu
cd "$(dirname "$0")/.."
FUZZTIME="${FUZZTIME:-10s}"
status=0
for pkg in $(go list ./...); do
	dir=$(go list -f '{{.Dir}}' "$pkg")
	for target in $(grep -ho '^func Fuzz[A-Za-z0-9_]*' "$dir"/*_test.go 2>/dev/null | sed 's/^func //' | sort -u); do
		echo "== $pkg $target ($FUZZTIME)"
		if ! go test -run='^$' -fuzz="^${target}\$" -fuzztime="$FUZZTIME" "$pkg"; then
			status=1
		fi
	done
done
exit "$status"
