package shell

import (
	"os"
	"strings"
	"testing"
)

// TestAuditWiring_AUDIT078 pins that cmd/api/main.go wires the admin-action
// audit trail: the middleware must be registered on the /admin group (so
// mutations are recorded) and the read endpoint must be served. A future edit
// that drops either silently blinds the audit trail.
func TestAuditWiring_AUDIT078(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cmd/api/main.go not found at %s (AUDIT-078): %v", path, err)
	}
	body := string(data)

	required := []struct{ needle, why string }{
		{`"firewall-mon/internal/audit"`, "main must import the audit package (AUDIT-078)"},
		{"audit.Middleware(db)", "the audit middleware must be registered on the admin group (AUDIT-078)"},
		{`admin.GET("/api/audit"`, "the audit read endpoint must be served (AUDIT-078)"},
	}
	for _, r := range required {
		if !strings.Contains(body, r.needle) {
			t.Errorf("main.go missing %q: %s", r.needle, r.why)
		}
	}

	// The middleware must come AFTER auth — otherwise the actor isn't on the
	// context. Assert the registration order in the source.
	// (P0-2 widened AdminAuth's signature to take the token store, so match
	// the call prefix rather than the full literal.)
	authIdx := strings.Index(body, "middleware.AdminAuth(authManager")
	auditIdx := strings.Index(body, "audit.Middleware(db)")
	if authIdx < 0 || auditIdx < 0 || auditIdx < authIdx {
		t.Error("audit.Middleware must be registered AFTER middleware.AdminAuth so the actor is on the context (AUDIT-078).")
	}
}
