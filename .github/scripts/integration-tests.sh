#!/usr/bin/env bash
# Runs the PostgreSQL integration suite (//go:build integration) the way CI
# does, and prints a short summary that names every failing package and test
# — including a package killed by -timeout, whose "panic: test timed out" and
# list of running tests would otherwise sit at the end of megabytes of GORM log
# output, past what the GitHub log view keeps.
#
#   TEST_PG_DSN=postgres://...test... .github/scripts/integration-tests.sh [packages...]
#
# -p 1: every package's NewIntegrationDB resets the SAME TEST_PG_DSN schema
# (DROP SCHEMA public CASCADE), so the package binaries must run one at a time.
# The full `go test -json` stream is written to $INTEGRATION_JSON (default
# integration.json; CI uploads it as an artifact). The exit status is go
# test's.
set -uo pipefail

out=${INTEGRATION_JSON:-integration.json}
timeout=${INTEGRATION_TIMEOUT:-15m}
if [ "$#" -eq 0 ]; then
	set -- ./internal/database/... ./internal/api/handlers/... ./cmd/poller/... ./internal/archive/...
fi

go test -tags=integration -p 1 -count=1 -timeout="$timeout" -json "$@" >"$out"
status=$?

summary() {
	echo "== packages"
	jq -r 'select(.Test == null and (.Action == "pass" or .Action == "fail" or .Action == "skip"))
		| "\(.Action | ascii_upcase)\t\(.Package)\t\(.Elapsed // 0)s"' "$out"
	echo "== failed tests"
	jq -r 'select(.Test != null and .Action == "fail") | "--- FAIL: \(.Test) (\(.Package), \(.Elapsed // 0)s)"' "$out"
	echo "== failure lines (assertions of failed tests, panics, timeouts and the tests running then)"
	jq -r -s '
		(map(select(.Test != null and .Action == "fail") | "\(.Package) \(.Test)") | unique) as $failed
		| .[] | select(.Action == "output")
		| select(
			(.Output | test("^panic: |test timed out|running tests:|^\\t\\tTest[^ ]* \\([0-9]|^FAIL\\s"))
			or (.Test != null and ("\(.Package) \(.Test)" | IN($failed[])) and (.Output | test("_test\\.go:[0-9]+:|^\\s*--- FAIL"))))
		| "\(.Package | sub("^firewall-mon/"; "")): \(.Output | rtrimstr("\n"))"' "$out" | head -n 300
}

if command -v jq >/dev/null 2>&1; then
	text=$(summary)
	printf '%s\n' "$text"
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		printf '### Integration (PostgreSQL)\n```\n%s\n```\n' "$text" >>"$GITHUB_STEP_SUMMARY"
	fi
else
	echo "jq not found: no summary; see $out" >&2
fi
if [ "$status" -ne 0 ]; then
	echo "integration tests FAILED (go test exit $status); full output: $out" >&2
fi
exit "$status"
