package shell

import (
	"os"
	"strings"
	"testing"
)

// TestClientErrorReporting_AUDIT129 pins both halves of the client-error
// feature: the server route is registered, and the admin JS installs a global
// error/unhandledrejection reporter that beacons to it. Either half alone is
// useless, so a future edit that drops one should fail here.
func TestClientErrorReporting_AUDIT129(t *testing.T) {
	main, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatalf("main.go not found (AUDIT-129): %v", err)
	}
	if !strings.Contains(string(main), `api.POST("/client-error"`) {
		t.Error("main.go does not register POST /api/client-error (AUDIT-129).")
	}

	js, err := os.ReadFile("../../cmd/api/static/js/admin-common.js")
	if err != nil {
		t.Fatalf("admin-common.js not found (AUDIT-129): %v", err)
	}
	body := string(js)
	for _, kw := range []string{"/api/client-error", "addEventListener('error'", "unhandledrejection"} {
		if !strings.Contains(body, kw) {
			t.Errorf("admin-common.js client-error reporter missing %q (AUDIT-129).", kw)
		}
	}
}
