package report

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestBuildCriticalAlertEmail_SubjectSanitizesCRLF locks in AUDIT-014:
// the subject line built from Device.Name / Device.IPAddress / Alert.AlertType
// must never contain CR or LF, otherwise an attacker who can register a device
// with a malicious name folds extra headers (e.g. Bcc:) into the outbound mail.
func TestBuildCriticalAlertEmail_SubjectSanitizesCRLF(t *testing.T) {
	t.Parallel()
	device := &models.Device{
		Name:      "router-1\r\nBcc: attacker@evil.example",
		IPAddress: "10.0.0.1\nX-Mailer: pwn",
		Status:    "down",
	}
	alert := &models.Alert{
		AlertType:    "CPU_HIGH\r\nReply-To: attacker@evil.example",
		Severity:     "critical",
		Message:      "cpu over threshold",
		MetricName:   "cpu",
		CurrentValue: 99,
		Threshold:    80,
		Timestamp:    time.Now(),
	}

	subject, _, _, err := BuildCriticalAlertEmail(alert, device, nil, ThemeByName(""))
	if err != nil {
		t.Fatalf("BuildCriticalAlertEmail: %v", err)
	}
	if strings.ContainsAny(subject, "\r\n") {
		t.Fatalf("subject %q contains CR or LF — header injection possible", subject)
	}
	// The sanitized output should still preserve the visible characters
	// so the operator can read the alert type / device name.
	for _, must := range []string{"CPU_HIGH", "router-1", "10.0.0.1"} {
		if !strings.Contains(subject, must) {
			t.Errorf("subject %q missing expected substring %q (sanitizer stripped too much)", subject, must)
		}
	}
	// And the injected headers must NOT survive verbatim (no CR/LF separator
	// means the smtp server cannot fold them into separate headers).
	if strings.Contains(subject, "\n") || strings.Contains(subject, "\r") {
		t.Errorf("subject %q still contains line terminators", subject)
	}
}
