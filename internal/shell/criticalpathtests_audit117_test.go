package shell

import (
	"os"
	"strings"
	"testing"
)

// TestCriticalPathTestsExist_AUDIT117 pins that the security-boundary and other
// critical-path packages the audit flagged with 0% coverage now carry tests —
// and that the auth suite keeps exercising the high-risk paths (the lockout
// state machine and the two JWT bypasses). It fails if any of these test files
// is deleted or quietly downgraded to a stub that no longer asserts the bypass.
func TestCriticalPathTestsExist_AUDIT117(t *testing.T) {
	checks := []struct {
		path  string
		needs []string
	}{
		// Security boundary: must keep covering lockout + alg-confusion + wrong-secret.
		{"../auth/auth_test.go", []string{
			"ValidateCredentials", "ErrAccountLocked",
			"ValidateToken", "SigningMethodNone", "ErrInvalidToken",
			"GenerateSecureToken",
		}},
		{"../alerts/policy_test.go", []string{"defaultSeverityForType"}},
		{"../models/models_test.go", []string{"TableName", "ToJSON"}},
	}
	for _, c := range checks {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Errorf("%s is missing (AUDIT-117): this critical-path package must keep its tests; err: %v", c.path, err)
			continue
		}
		body := string(data)
		for _, needle := range c.needs {
			if !strings.Contains(body, needle) {
				t.Errorf("%s no longer references %q (AUDIT-117): the critical-path test must keep covering this.", c.path, needle)
			}
		}
	}
}
