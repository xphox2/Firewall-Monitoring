#!/usr/bin/env bash
# Prints the `go test` ARGUMENTS for one shard of the `-race` suite, ONE
# ARGUMENT PER LINE, so the caller can read them into an array safely:
#
#   mapfile -t args < <(.github/scripts/shard-tests.sh 3 10)
#   go test -race -count=1 -timeout=20m "${args[@]}"
#
# The suite's wall clock is two packages, not many: `internal/database` (691
# tests) and `internal/api/handlers` (444), run sequentially by `go test` and
# ~11.5 and ~9 min on a runner. Splitting by package only moves them to their
# own runner, so those two are split by TEST NAME instead — round-robin over
# the sorted names, so every bucket holds a similar number and every test runs
# exactly once across the shards. Every other package is grouped by a rough
# cost (longest-processing-time-first) so those groups also finish together.
#
# Usage: .github/scripts/shard-tests.sh <shard> <total>
#   <total> must be N_DB + N_HANDLERS + N_LIGHT (the plan below). Bump a
#   bucket count to spread the heavy packages further if a shard is still the
#   wall clock.
set -euo pipefail

shard=${1:?usage: shard-tests.sh <shard> <total>}
total=${2:?usage: shard-tests.sh <shard> <total>}

N_DB=4       # buckets of internal/database's tests
N_HANDLERS=3 # buckets of internal/api/handlers' tests
N_LIGHT=3    # groups of every other package
N_TOTAL=$((N_DB + N_HANDLERS + N_LIGHT))

if [ "$total" -ne "$N_TOTAL" ]; then
	echo "shard-tests.sh: total must be $N_TOTAL (N_DB + N_HANDLERS + N_LIGHT)" >&2
	exit 2
fi
if [ "$shard" -lt 1 ] || [ "$shard" -gt "$N_TOTAL" ]; then
	echo "shard-tests.sh: shard must be 1..$N_TOTAL" >&2
	exit 2
fi

# bucket_args <pkg> <bucket 0-based> <buckets>: prints `-run`, the regex and
# the package. `-list` compiles with the same -race flag the run uses, so the
# run reuses the build cache; round-robin over the sorted names keeps the
# buckets even.
bucket_args() {
	local pkg=$1 b=$2 n=$3 names regex
	names=$(go test -race -list '^Test' "$pkg" 2>/dev/null |
		grep -E '^Test' | LC_ALL=C sort || true)
	if [ -z "$names" ]; then
		return 0
	fi
	regex=$(printf '%s\n' "$names" | awk -v n="$n" -v b="$b" 'NR % n == b' | paste -sd'|' -)
	if [ -z "$regex" ]; then
		return 0
	fi
	printf -- '-run\n^(%s)$\n%s\n' "$regex" "$pkg"
}

if [ "$shard" -le "$N_DB" ]; then
	bucket_args ./internal/database "$((shard - 1))" "$N_DB"
elif [ "$shard" -le "$((N_DB + N_HANDLERS))" ]; then
	bucket_args ./internal/api/handlers "$((shard - N_DB - 1))" "$N_HANDLERS"
else
	# A group of every package except the two heavy ones, balanced by weight.
	group=$((shard - N_DB - N_HANDLERS)) # 1..N_LIGHT
	weight() {
		case "$1" in
		firewall-mon/internal/alerts)         echo 100 ;;
		firewall-mon/internal/archive/worker) echo 88 ;;
		firewall-mon/test/guardrails)         echo 54 ;;
		firewall-mon/cmd/poller)              echo 43 ;;
		firewall-mon/internal/report)         echo 35 ;;
		firewall-mon/internal/detect)         echo 31 ;;
		*) echo 4 ;;
		esac
	}
	go list ./... |
		grep -v -e '^firewall-mon/internal/database$' -e '^firewall-mon/internal/api/handlers$' |
		while read -r pkg; do printf '%s %s\n' "$(weight "$pkg")" "$pkg"; done |
		sort -k1,1nr -k2,2 |
		awk -v n="$N_LIGHT" -v want="$group" '
			BEGIN { for (i = 1; i <= n; i++) load[i] = 0 }
			{
				b = 1
				for (i = 2; i <= n; i++) if (load[i] < load[b]) b = i
				load[b] += $1
				if (b == want) print $2
			}
		'
fi
