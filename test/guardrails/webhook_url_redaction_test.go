package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestWebhookTestURLRedaction pins D-22: the "Test connection" webhook handler
// must not echo the raw webhook URL (whose path/query can carry a secret token)
// back in an error response — it redacts to the host and unwraps the *url.Error.
func TestWebhookTestURLRedaction(t *testing.T) {
	data, err := os.ReadFile("../../internal/api/handlers/handlers_settings.go")
	if err != nil {
		t.Skipf("handlers_settings.go not found: %v", err)
	}
	body := string(data)
	if strings.Contains(body, `fmt.Sprintf("Failed to reach webhook: %v", err)`) {
		t.Error("Test-webhook handler still echoes the raw webhook URL in its error — redact to the host (D-22).")
	}
	if !strings.Contains(body, "errors.As(err, &uerr)") {
		t.Error("Test-webhook handler no longer unwraps the *url.Error before formatting — a redacted host must surface only the underlying cause (D-22).")
	}
}
