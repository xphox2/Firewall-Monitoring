package shell

import (
	"os"
	"strings"
	"testing"
)

// tasks/docker-disk-gc.sh reclaims Docker disk on the host. rust-01's ROOT
// filesystem hit 88% twice, and a manual cleanup on 2026-09-08 reclaimed 47 GB.
//
// The script is deliberately narrow: it removes untagged images and caps build
// cache, and nothing else. The tempting "simplification" is to replace the whole
// thing with `docker system prune -a --volumes`, which is a very different
// operation — it removes unused TAGGED images (forcing a re-pull of every base
// image on the box), removes networks, and with --volumes can destroy data. The
// host runs ten containers across four unrelated projects, so that would be an
// outage in several of them at once.
//
// These assertions are the only mechanised gate on this file: the repo has no
// shellcheck and no shfmt, in CI or anywhere else, so `go test ./...` running
// this package is the whole story for shell.
//
// Be honest about what this is. It is a TRIPWIRE for the specific one-liner
// somebody is most likely to reach for, not a sandbox. Substring matching does
// not catch `docker container prune`, `docker volume rm`, `docker image rm`,
// `docker compose down -v`, a doubled space, or any indirection through a
// variable. Making it exhaustive would mean parsing bash, which is a worse use
// of the effort than the review that catches those in a diff. What it does buy
// is that the obvious regression fails loudly and immediately.

func TestDockerDiskGC_NeverUsesDestructiveFlags(t *testing.T) {
	const path = "../../tasks/docker-disk-gc.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		// Fatalf, not Skipf. `go test` always runs with cwd at the package
		// directory, so this read fails for exactly one reason: the script is
		// gone. That is precisely when the guard must fire rather than let CI go
		// green on a deleted safety-critical file.
		t.Fatalf("tasks/docker-disk-gc.sh not found at %s: %v", path, err)
	}

	// Strip comments before the negative checks, so the header block explaining
	// WHY these commands are forbidden does not trip the check that forbids
	// them. Note the helper strips `#` comments only — not heredocs or string
	// literals — which is why the script's usage() heredoc is written without
	// naming these commands.
	body := stripBashComments(string(data))

	forbidden := []struct {
		needle string
		why    string
	}{
		{"system prune", "a full system prune removes unused TAGGED images, networks and (with --volumes) volumes. " +
			"This host runs ten containers across four projects; that is an outage, not a cleanup. " +
			"The script must only prune dangling images and build cache."},
		{"--volumes", "volumes hold real data — Honcho's Postgres among them. Nothing in a disk-reclaim script " +
			"should be able to remove one."},
		{"image prune -a", "-a on an image prune removes unused TAGGED images, forcing a re-pull of Alpine, " +
			"BuildKit, nginx-proxy-manager and the marketing site. Only dangling images are safe to remove " +
			"unattended, because the daemon guarantees it will not touch an image any container references."},
		{"image prune --all", "same as -a: it takes unused tagged images, not just dangling ones."},
		{"docker rm", "the script must never remove a container."},
		{"docker stop", "the script must never stop a container. On 2026-09-08 the cleanup was verified " +
			"specifically by confirming all ten containers stayed up with unchanged uptimes."},
	}
	for _, f := range forbidden {
		if strings.Contains(body, f.needle) {
			t.Errorf("tasks/docker-disk-gc.sh contains %q — %s", f.needle, f.why)
		}
	}
}

func TestDockerDiskGC_KeepsItsSafetyRails(t *testing.T) {
	const path = "../../tasks/docker-disk-gc.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("tasks/docker-disk-gc.sh not found at %s: %v", path, err)
	}
	// Positive checks run on stripped text too, so a commented-out line cannot
	// satisfy them.
	body := stripBashComments(string(data))

	required := []struct {
		needle string
		why    string
	}{
		{"set -euo pipefail", "house style for operational scripts (tasks/replica-setup.sh), and the script " +
			"reads command output into variables where a silent failure would produce a wrong report."},
		{"flock -n 9", "the script must actually TAKE a lock, not merely mention one — an earlier version of " +
			"this assertion matched the bare word `flock`, which a log line saying \"flock not available\" " +
			"satisfied even if the call had been deleted. It must also be the ONLY lock: wrapping the " +
			"invocation in flock on the same path as well would deadlock, because the inner acquisition is a " +
			"separate open file description and is denied by the outer lock held by the same process."},
		{"--max-used-space", "the build-cache bound. This replaced an age filter deliberately: buildx parses " +
			"durations with Go's time.ParseDuration, which has no 'd' unit, so `until=7d` is rejected outright " +
			"while `until=168h` is accepted — a cap has no such trap."},
		{"--dry-run", "the script must be exercisable against the real host without removing anything; that is " +
			"how it gets validated before it is ever run for real."},
	}
	for _, r := range required {
		if !strings.Contains(body, r.needle) {
			t.Errorf("tasks/docker-disk-gc.sh no longer contains %q — %s", r.needle, r.why)
		}
	}

	// The builder list must not be taken from the Go-template form. That emits
	// node rows as well as builder rows (honcho-synology, honcho-synology0,
	// default, default), and a node name is not a builder name, so pruning it
	// fails. Verified against this host's real output.
	if strings.Contains(body, `buildx ls --format '{{.Name}}'`) || strings.Contains(body, `buildx ls --format "{{.Name}}"`) {
		t.Error("tasks/docker-disk-gc.sh enumerates builders with --format '{{.Name}}', which also emits NODE " +
			"names; pruning a node name fails. Use the JSON form and drop the nested Nodes array first.")
	}
}

// The script is invoked directly by an operator and potentially by cron, so the
// execute bit is part of its contract — git preserves it, and without it the
// invocation fails with "Permission denied".
func TestDockerDiskGC_IsExecutable(t *testing.T) {
	const path = "../../tasks/docker-disk-gc.sh"
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("tasks/docker-disk-gc.sh not found at %s: %v", path, err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("tasks/docker-disk-gc.sh is mode %v — commit it with the execute bit set, or every invocation "+
			"fails with 'Permission denied'.", fi.Mode().Perm())
	}
}
