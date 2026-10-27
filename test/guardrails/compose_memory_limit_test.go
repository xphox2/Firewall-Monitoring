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
// and PostgreSQL die together (status 137) and the entrypoint restarts the
// stack. It happened on 2026-10-27 twice: once during the daily pg_dump
// (which reads ~3.6 GB) and once when the limit was lowered again while the
// buffer pool was still full.
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

	if !strings.Contains(body, "${FIREWALL_MON_MEM_LIMIT:-2g}") {
		t.Error("the compose file hard-codes the memory limit — a deployment with a large database cannot raise it without editing a tracked file, and the OOM killer takes the whole container down when PostgreSQL's buffer pool outgrows the cgroup")
	}
	// The swap limit travels with it: a memory limit above the host's RAM is
	// a promise the host cannot keep.
	if !strings.Contains(body, "${FIREWALL_MON_MEMSWAP_LIMIT:-4g}") {
		t.Error("the compose file hard-codes the swap limit — it must travel with the memory limit, or a raised limit becomes a promise the host cannot keep")
	}
	// And the default must still be the small one, so a fresh install is
	// bounded the way it always was.
	if !strings.Contains(body, "mem_limit: ${FIREWALL_MON_MEM_LIMIT:-2g}") {
		t.Error("the default memory limit is not 2g — a fresh install must stay bounded as it always was")
	}
}
