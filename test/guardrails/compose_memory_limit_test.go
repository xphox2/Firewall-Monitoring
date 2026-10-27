package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestComposeMemoryLimitIsOverridable pins that the container's memory
// limit is part of the DEPLOYMENT's configuration, not of the tracked file.
//
// The default is 2g, which suits a small install. It does not suit a large
// one: PostgreSQL's buffer manager fills whatever it is allowed, so with a
// 2g cgroup and a PostgreSQL tuned with ALTER SYSTEM to shared_buffers =
// 8GB, the OOM killer takes out the WHOLE container - the API, the poller
// and PostgreSQL die together (status 137). It happened on 2026-10-27
// twice: once during the daily pg_dump (which reads ~3.6 GB) and once when
// the limit was lowered again while the buffer pool was still full. Docker's
// `restart: unless-stopped` policy then brings back a fresh stack.
//
// A deployment with a large database therefore raises the limit in its .env,
// exactly the way it overrides the image. If the limit is hard-coded again,
// a large deployment cannot raise it without editing a tracked file - which
// is what produced the untracked working-tree drift that blocked `git pull`
// on the deployment host (v0.11.179).
func TestComposeMemoryLimitIsOverridable(t *testing.T) {
	compose, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Skipf("docker-compose.yml not found: %v", err)
	}
	body := string(compose)

	// The KEY is matched on a line that is not a comment: a stray
	// "# mem_limit: ${FIREWALL_MON_MEM_LIMIT:-2g}" in a comment must not
	// satisfy the check, or the real limit could be hard-coded again with
	// the comment left behind.
	values := composeValues(body)
	if got := values["mem_limit"]; got != "${FIREWALL_MON_MEM_LIMIT:-2g}" {
		t.Errorf("the compose file's mem_limit is %q, want ${FIREWALL_MON_MEM_LIMIT:-2g} - a deployment with a large database cannot raise it without editing a tracked file, and the OOM killer takes the whole container down when PostgreSQL's buffer pool outgrows the cgroup", got)
	}
	// The swap limit travels with it, and it must be raised TOO: Docker
	// refuses to create a container whose memswap_limit is below its
	// mem_limit, so a raised memory limit with the default swap limit does
	// not start.
	if got := values["memswap_limit"]; got != "${FIREWALL_MON_MEMSWAP_LIMIT:-4g}" {
		t.Errorf("the compose file's memswap_limit is %q, want ${FIREWALL_MON_MEMSWAP_LIMIT:-4g} - it must travel with the memory limit, and a raised memory limit with the default swap limit makes Docker refuse to create the container", got)
	}
	// The CPU count travels with them: it is the other bound on the same
	// cgroup, and a deployment that raises one raises the others.
	if got := values["cpus"]; got != "${FIREWALL_MON_CPUS:-2.0}" {
		t.Errorf("the compose file's cpus is %q, want ${FIREWALL_MON_CPUS:-2.0}", got)
	}
}

// composeValues reads the service KEYS out of a compose file, skipping the
// comment lines.
//
// A plain strings.Contains would be satisfied by a COMMENT that names the
// setting, which is how a guardrail ends up measuring the documentation
// instead of the configuration. This is the same line-loop the shm_size
// guardrail uses.
func composeValues(body string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "mem_limit" && key != "memswap_limit" && key != "cpus" {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values
}
