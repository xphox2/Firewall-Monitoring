package shell

import (
	"os"
	"strings"
	"testing"
)

// TestSecurityTxtRoute_AUDIT112 pins that the API serves an RFC 9116
// security.txt at the canonical well-known path, with the required fields.
// Many vulnerability-disclosure programs and scanners look for this file.
func TestSecurityTxtRoute_AUDIT112(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/api/main.go not found at %s; err: %v", path, err)
	}
	body := string(data)

	if !strings.Contains(body, `"/.well-known/security.txt"`) {
		t.Error("cmd/api/main.go does not register the /.well-known/security.txt route (AUDIT-112).")
	}
	// RFC 9116 requires Contact and Expires; Policy is strongly recommended.
	for _, field := range []string{"Contact:", "Expires:", "Policy:"} {
		if !strings.Contains(body, field) {
			t.Errorf("security.txt body is missing the %q field (AUDIT-112: RFC 9116 requires Contact + Expires).", field)
		}
	}
}
