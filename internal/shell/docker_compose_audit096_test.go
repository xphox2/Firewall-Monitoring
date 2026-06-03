package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDockerCompose_HasHealthcheck_AUDIT096 is a static regression for
// the audit: docker-compose.yml ships the firewall-mon service without
// a `healthcheck:` block. Without one:
//   - `docker compose ps` shows "Up" without a health qualifier, so
//     operators have to read JSON to figure out whether the API is
//     actually serving (vs the process being wedged on a wedged DB).
//   - The `depends_on: condition: service_healthy` form on any
//     future split-out compose (e.g. a reverse proxy in front) is
//     not available, since the prerequisite is an explicit
//     `healthcheck:` block in the dependent's service definition.
//
// The Dockerfile has its own HEALTHCHECK (v0.10.264); this test
// pins the compose-level block independently so a future agent
// who edits the compose file and removes the block fails CI here
// even if the image is still healthy.
func TestDockerCompose_HasHealthcheck_AUDIT096(t *testing.T) {
	const path = "../../docker-compose.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("docker-compose.yml not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// Strip bash-style `#` comments (YAML allows them, and we don't
	// want a comment that says "TODO add healthcheck" to satisfy
	// the check).
	var nonComment []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		nonComment = append(nonComment, line)
	}
	effective := strings.Join(nonComment, "\n")

	if !strings.Contains(effective, "healthcheck:") {
		t.Fatalf("docker-compose.yml has no `healthcheck:` block for the firewall-mon service. AUDIT-096: declare an explicit healthcheck in compose (not only in the Dockerfile) so `docker compose ps` shows the health status and `depends_on: condition: service_healthy` is available to dependent services. See CHANGELOG v0.10.266 for the recommended shape.")
	}
	// The healthcheck must actually probe a real endpoint, not just
	// exist as a placeholder. wget -qO- http://localhost:8080/api/health
	// is the convention (matches the Dockerfile's HEALTHCHECK).
	if !strings.Contains(effective, "api/health") {
		t.Errorf("docker-compose.yml has a `healthcheck:` block but it does not probe /api/health. The endpoint must match the one used in the Dockerfile's HEALTHCHECK directive (v0.10.264) so a wedged DB returns 503 → compose reports unhealthy → restart loop kicks in.")
	}
}
