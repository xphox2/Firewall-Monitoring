package shell

import (
	"os"
	"strings"
	"testing"
)

// TestEndToEndIntegrationWired_AUDIT123 pins the cross-package, end-to-end
// integration test that AUDIT-123 asked for (a real repo-level integration test,
// not just the DB-package PG-path checks of AUDIT-118): a build-tagged handler →
// real-Postgres ingestion suite exists, and the CI job + Makefile target run the
// handlers package under -tags=integration (so the suite actually executes, not
// just the database package).
func TestEndToEndIntegrationWired_AUDIT123(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}

	// The build-tagged end-to-end handler→Postgres suite exists.
	e2e := read("../../internal/api/handlers/integration_pg_test.go")
	for _, kw := range []string{
		"//go:build integration",
		"func TestEndToEndIngestion_Postgres_AUDIT123(",
		"database.NewIntegrationDB",
		"ReceiveSystemStatuses",
	} {
		if !strings.Contains(e2e, kw) {
			t.Errorf("handlers/integration_pg_test.go missing %q (AUDIT-123).", kw)
		}
	}

	// The shared, exported harness both suites use (DRY connect/reset/migrate).
	kit := read("../../internal/database/integration_testkit.go")
	for _, kw := range []string{"//go:build integration", "func NewIntegrationDB("} {
		if !strings.Contains(kit, kw) {
			t.Errorf("database/integration_testkit.go missing %q (AUDIT-123).", kw)
		}
	}

	// CI and Makefile must run the handlers package too, or the e2e suite never executes.
	ci := read("../../.github/workflows/ci.yml")
	if !strings.Contains(ci, "./internal/api/handlers/...") {
		t.Error("ci.yml integration job does not run ./internal/api/handlers/... (AUDIT-123): the e2e suite would be skipped in CI.")
	}
	mk := read("../../Makefile")
	if !strings.Contains(mk, "./internal/api/handlers/...") {
		t.Error("Makefile test-integration target does not run ./internal/api/handlers/... (AUDIT-123).")
	}
}
