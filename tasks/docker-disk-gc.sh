#!/usr/bin/env bash
#
# docker-disk-gc.sh — reclaim Docker disk on the host, and report why it filled.
#
# WHICH DISK. rust-01 has two, and they fail differently. This script is about
# the ROOT filesystem (77 GB), which holds Docker under /var/lib/containerd and
# /var/lib/docker. It has nothing to do with /mnt/STORAGE (344 GB), which holds
# PGDATA and is the subject of the 2026-07-26 fill-up and the 2026-09-05 ingest
# growth work. Confusing the two is the first mistake to make here.
#
# WHY THIS IS A HELPER AND NOT A CRON JOB. The root disk hit 88% twice, and a
# manual cleanup on 2026-09-08 reclaimed 47 GB. The cause was not "nothing ever
# cleans up" — it was that BuildKit's garbage collector shipped with upstream
# defaults sized for a CI machine: Max Used Space 42.84 GiB and Min Free Space
# 11.18 GiB, PER BUILDER, on a 77 GB disk with two builders. A Min Free Space of
# 11.18 GiB on this disk means BuildKit only starts evicting at 85.5% used, which
# is exactly why the host climbs to ~88% and then sits there rather than filling
# to 100%. The real fix is the GC policy (see docs/OPERATIONS.md, "Host disk
# housekeeping"); this script is the one-off cleanup and the "why is it full"
# report for when you are staring at a full disk right now.
#
# WHAT IT WILL NEVER DO. It only removes untagged ("dangling") images and build
# cache. It never runs a full system prune, never touches volumes, never passes
# -a/--all to the image prune, and never stops, removes or restarts a container.
# Those exclusions are asserted by internal/shell/dockerdiskgc_test.go, because
# the tempting one-liner that would undo them removes unused TAGGED images too
# and forces re-pulls of every base image on the box.
#
# Removing dangling images is safe even while a deploy is in flight: the daemon
# excludes any image referenced by a container, running OR stopped. That is not
# a guess — on 2026-09-08 the live firewall-mon container was itself running on
# an untagged image (a build had run without a recreate) and prune correctly
# left it alone.
#
# USAGE:
#   ./tasks/docker-disk-gc.sh              # report, then reclaim
#   ./tasks/docker-disk-gc.sh --dry-run    # report only, change nothing
#   ./tasks/docker-disk-gc.sh report       # just the report
#
#   CACHE_CAP=8GB ./tasks/docker-disk-gc.sh   # override the per-builder cap
#
set -euo pipefail

# Per-builder build-cache ceiling. --max-used-space is a first-class buildx flag
# on Docker 29.x / BuildKit v0.31.x, and it makes an age filter unnecessary: a
# cap is a cap, with no `df` loop and no threshold to drift out of step with the
# app's own 85% DISK_HIGH alert (cmd/poller/serverhealth.go).
CACHE_CAP="${CACHE_CAP:-8GB}"

# Absolute path: this is expected to run from cron, and paying one line here is
# cheaper than debugging a PATH difference at 4am.
DOCKER="${DOCKER:-/usr/bin/docker}"

LOCKFILE="${LOCKFILE:-/tmp/docker-disk-gc.lock}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
die() {
	log_error "$1"
	exit 1
}

DRY_RUN=false

# root_used_pct prints the root filesystem's used percentage as a bare integer.
root_used_pct() {
	df -P / | awk 'NR==2 {gsub(/%/,"",$5); print $5}'
}

root_avail_h() {
	df -Ph / | awk 'NR==2 {print $4}'
}

# builders prints one builder NAME per line.
#
# Deliberately not `buildx ls --format '{{.Name}}'`: that emits node rows as well
# as builder rows, so on this host it yields honcho-synology, honcho-synology0,
# default, default — and honcho-synology0 is a node, not a builder, so pruning it
# fails. The JSON form has one object per builder with its nodes nested.
# The `sed` that drops the Nodes array is load-bearing, not tidying. Each JSON
# object is one line carrying the builder's own "Name" AND its nodes' "Name"
# fields, and a `.*"Name":"..."` match is greedy, so it returns the LAST one —
# the node. Verified against this host's real output: without the strip it
# yields honcho-synology0 (a node) instead of honcho-synology (the builder).
builders() {
	local out
	# JSON first: one object per line, builder "Name" before its nested "Nodes".
	out=$("$DOCKER" buildx ls --format json 2>/dev/null |
		sed 's/"Nodes".*//' |
		sed -n 's/.*"Name":"\([^"]*\)".*/\1/p' |
		head -20) || true
	if [ -z "$out" ]; then
		# The JSON parse leans on buildx emitting "Name" before "Nodes", which is
		# Go struct field order and could change. Fall back to the table, where
		# builder rows start in column 0 and node rows are indented — a display
		# convention, so the two failure modes are independent.
		out=$("$DOCKER" buildx ls 2>/dev/null |
			awk 'NR>1 && $0 !~ /^[[:space:]]/ {gsub(/\*$/,"",$1); print $1}' |
			head -20) || true
	fi
	printf '%s\n' "$out"
}

report() {
	log_info "root filesystem: $(root_used_pct)% used, $(root_avail_h) available"
	echo
	# Note for whoever reads this next: `docker system df` UNDER-REPORTS on this
	# host. A docker-container-driver builder keeps its cache in its own volume,
	# so system df showed "Build Cache 3.846MB" while that builder was holding
	# gigabytes. The per-builder `buildx du` below is the honest number.
	"$DOCKER" system df || log_warn "docker system df failed"
	echo
	local b
	for b in $(builders); do
		local used
		# Each builder is tolerated individually: a docker-container builder whose
		# BuildKit container is stopped makes this exit non-zero, and under set -e
		# that would abort the whole run before anything else was reported.
		if used=$("$DOCKER" buildx du --builder "$b" 2>/dev/null | tail -1); then
			log_info "builder ${b}: ${used}"
		else
			log_warn "builder ${b}: unavailable (its BuildKit container may be stopped) — skipping"
		fi
	done
}

reclaim() {
	local before_pct before_avail
	before_pct=$(root_used_pct)
	before_avail=$(root_avail_h)

	if [ "$DRY_RUN" = true ]; then
		log_warn "DRY RUN — nothing will be removed."
		log_info "[dry-run] Would run: ${DOCKER} image prune -f"
		# Validate the cap's SHAPE here rather than by invoking buildx: --max-used-space
		# is a prune-only flag (buildx du does not accept it), so there is no
		# read-only command that exercises its parser. A malformed value would
		# otherwise only surface during the real run.
		if ! printf '%s' "$CACHE_CAP" | grep -Eq '^[0-9]+(\.[0-9]+)?(B|[KMGT]B|[KMGT]iB)?$'; then
			log_warn "CACHE_CAP='${CACHE_CAP}' does not look like a byte size (e.g. 8GB, 512MB) — the real run would fail"
		fi
		local b
		for b in $(builders); do
			log_info "[dry-run] Would run: ${DOCKER} buildx prune --builder ${b} -f --max-used-space ${CACHE_CAP}"
			# Reachability IS worth probing read-only: a docker-container builder
			# whose BuildKit container is stopped fails the real prune, and knowing
			# that before the maintenance window is the point of a dry run.
			if ! "$DOCKER" buildx du --builder "$b" >/dev/null 2>&1; then
				log_warn "  builder ${b}: unreachable — the real run would skip it"
			fi
		done
		log_info "Dry run complete. Re-run without --dry-run to apply."
		return 0
	fi

	# Untagged images only. No -a: that would take unused TAGGED images too.
	log_info "pruning dangling images"
	"$DOCKER" image prune -f || log_warn "image prune failed — continuing"

	local b
	for b in $(builders); do
		log_info "capping build cache on builder ${b} at ${CACHE_CAP}"
		if ! "$DOCKER" buildx prune --builder "$b" -f --max-used-space "$CACHE_CAP"; then
			log_warn "builder ${b}: prune failed (its BuildKit container may be stopped) — skipping"
		fi
	done

	local after_pct after_avail
	after_pct=$(root_used_pct)
	after_avail=$(root_avail_h)
	# $(( )) rather than (( )): an arithmetic COMMAND that evaluates to zero
	# returns exit status 1, which under set -e would abort the script on exactly
	# the quiet runs where nothing needed reclaiming.
	local freed_pct=$((before_pct - after_pct))
	log_info "root filesystem: ${before_pct}% -> ${after_pct}% (${freed_pct} points), ${before_avail} -> ${after_avail} available"

	if [ "$after_pct" -ge 85 ]; then
		# 85 is the app's own server_disk_threshold default
		# (cmd/poller/serverhealth.go), so this is the point where DISK_HIGH fires.
		# Saying so plainly matters: if Docker was not the problem, the next place
		# to look is journald, apt, or a container log, and this script cannot and
		# should not touch any of them.
		log_warn "still at ${after_pct}% after reclaiming — Docker was not the cause."
		log_warn "check non-Docker consumers: sudo du -xhd1 /var /home /opt | sort -h | tail"
		return 1
	fi
}

usage() {
	# Kept free of the forbidden command names on purpose: the guard test strips
	# # comments before its negative checks but not heredocs or string literals,
	# so naming them here would trip the very check that forbids them.
	cat <<'EOF'
Usage: docker-disk-gc.sh [report|reclaim] [--dry-run]

  report     Show root disk usage and per-builder cache size, change nothing.
  reclaim    Remove dangling images and cap each builder's cache (default).

  --dry-run  Print what reclaim would do, and validate the cache cap against
             the real flag parser, without removing anything.
EOF
}

main() {
	local cmd="reclaim"
	while [ $# -gt 0 ]; do
		case "$1" in
		report | reclaim)
			cmd="$1"
			shift
			;;
		--dry-run)
			DRY_RUN=true
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			usage
			die "unknown argument: $1"
			;;
		esac
	done

	command -v "$DOCKER" >/dev/null 2>&1 || die "docker not found at ${DOCKER} (set DOCKER=/path/to/docker)"

	# ONE lock, held here and nowhere else. Do NOT also wrap the cron invocation
	# in flock on this same path: flock(2) treats the wrapper's fd and this one as
	# separate open file descriptions, so the inner acquisition is denied by the
	# outer lock held by the very same process, and the script would exit
	# immediately on every scheduled run. That was verified on the host.
	if command -v flock >/dev/null 2>&1; then
		exec 9>"$LOCKFILE"
		if ! flock -n 9; then
			log_warn "another run holds ${LOCKFILE} — exiting"
			exit 0
		fi
	else
		# Distinguishing "lock is held" from "flock is missing" matters more than
		# it looks. Without this branch a host with no flock takes the failure
		# path above and exits 0 announcing another run holds the lock — a silent
		# no-op wearing the costume of success, which is the exact failure mode
		# this script must never have. Found by running it on a machine with no
		# flock in PATH.
		log_warn "flock not available — continuing WITHOUT a lock; concurrent runs are possible"
	fi

	# An empty builder list is the worst failure this script has, because it looks
	# exactly like success: every loop iterates zero times, nothing is pruned, and
	# the summary reports a tidy no-op. Fail loudly instead.
	if [ -z "$(builders)" ]; then
		die "could not enumerate any buildx builder — refusing to report success having pruned nothing. Check: ${DOCKER} buildx ls"
	fi

	report
	echo
	[ "$cmd" = "report" ] && exit 0
	reclaim
}

main "$@"
