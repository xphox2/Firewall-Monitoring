package shell

import (
	"os"
	"strings"
	"testing"
)

// TestPostgresIntegrationWired_AUDIT118 pins that the Postgres integration lane
// stays in place: a build-tagged integration suite exists, the CI workflow has a
// Postgres-service job that runs it with TEST_PG_DSN, and the Makefile exposes a
// test-integration target. Production is Postgres-only, so losing this lane
// would silently drop all real-Postgres coverage (dialect drift like the
// v0.10.238 minute-bucket bug).
func TestPostgresIntegrationWired_AUDIT118(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}

	// The build-tagged integration suite exists and is gated on TEST_PG_DSN.
	suite := read("../../internal/database/integration_pg_test.go")
	for _, kw := range []string{"//go:build integration", "TEST_PG_DSN", "func TestPostgresIntegration(", "TimeBucket"} {
		if !strings.Contains(suite, kw) {
			t.Errorf("integration_pg_test.go missing %q (AUDIT-118).", kw)
		}
	}

	// The CI workflow runs it against a Postgres service with the tag.
	ci := read("../../.github/workflows/ci.yml")
	for _, kw := range []string{"integration-postgres", "image: postgres:16", "TEST_PG_DSN", "-tags=integration"} {
		if !strings.Contains(ci, kw) {
			t.Errorf("ci.yml missing %q (AUDIT-118): the Postgres integration job must run the tagged suite.", kw)
		}
	}

	// The Makefile exposes the target.
	mk := read("../../Makefile")
	if !strings.Contains(mk, "test-integration:") || !strings.Contains(mk, "-tags=integration") {
		t.Error("Makefile missing the test-integration target (AUDIT-118).")
	}
}
