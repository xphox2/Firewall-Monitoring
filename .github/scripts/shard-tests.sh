#!/usr/bin/env bash
# Prints the package list for one shard of the `-race` suite so the shards
# finish together. The wall clock of an unsharded `go test -race ./...` is
# dominated by two packages — `internal/database` (~270 s) and
# `internal/api/handlers` (~225 s) locally, ~9 min each on a CI runner — so a
# plain split would leave one shard carrying everything.
#
# The weights below are local `go test -race -json ./...` Elapsed seconds
# (2026-10); a package with no entry counts as 4. Longest-processing-time-first
# packs them into `total` bins, so the two heavy packages land in different
# shards and each shard gets a similar total. Re-tune the numbers when a
# package's cost changes; the exact values matter less than their ranking.
#
# Usage (from the repo root): .github/scripts/shard-tests.sh <shard> <total>
# The union over shard=1..total is exactly `go list ./...`, so nothing is
# dropped by sharding.
set -euo pipefail

shard=${1:?usage: shard-tests.sh <shard 1..N> <N>}
total=${2:?usage: shard-tests.sh <shard 1..N> <N>}

weight() {
	case "$1" in
	firewall-mon/internal/database)       echo 270 ;;
	firewall-mon/internal/api/handlers)   echo 226 ;;
	firewall-mon/internal/alerts)         echo 100 ;;
	firewall-mon/internal/archive/worker) echo 88 ;;
	firewall-mon/test/guardrails)         echo 54 ;;
	firewall-mon/cmd/poller)              echo 43 ;;
	firewall-mon/internal/report)         echo 35 ;;
	firewall-mon/internal/detect)         echo 31 ;;
	*) echo 4 ;;
	esac
}

go list ./... | while read -r pkg; do
	printf '%s %s\n' "$(weight "$pkg")" "$pkg"
done |
	sort -k1,1nr -k2,2 |
	awk -v n="$total" -v want="$shard" '
		BEGIN { for (i = 1; i <= n; i++) load[i] = 0 }
		{
			b = 1
			for (i = 2; i <= n; i++) if (load[i] < load[b]) b = i
			load[b] += $1
			if (b == want) printf "%s ", $2
		}
		END { print "" }
	'
