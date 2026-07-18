package report

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestCriticalAlertTemplate_ThemedAndEmailSafe runs the critical-alert email
// through the same email-safety assertions as the fleet report, in both
// themes: MSO ghost tables survive html/template's comment stripping, both
// dark-mode metas render, no pure white/black hex anywhere, and no banned
// visual devices. (The fleet report's matrix lives in render_validate_test —
// this template is a separate parse and needs its own pins.)
func TestCriticalAlertTemplate_ThemedAndEmailSafe(t *testing.T) {
	alert := &models.Alert{
		Timestamp: time.Now(), AlertType: "CPU_HIGH", Severity: "critical",
		Message: "CPU usage 97.6% exceeds threshold", MetricName: "cpu_usage",
		CurrentValue: 97.6, Threshold: 90,
	}
	device := &models.Device{Name: "fw-edge-01", IPAddress: "10.0.0.1", Status: "online"}
	history := []models.SystemStatus{
		{Timestamp: time.Now().Add(-10 * time.Minute), CPUUsage: 80, MemoryUsage: 60},
		{Timestamp: time.Now(), CPUUsage: 97.6, MemoryUsage: 62},
	}

	for _, themeName := range []string{"light", "dark"} {
		theme := ThemeByName(themeName)
		subject, html, atts, err := BuildCriticalAlertEmail(alert, device, history, theme)
		if err != nil {
			t.Fatalf("theme=%s: %v", themeName, err)
		}
		if !strings.Contains(subject, "[CRITICAL]") {
			t.Errorf("theme=%s: subject lost its CRITICAL tag: %q", themeName, subject)
		}
		for _, bad := range []string{"<no value>", "ZgotmplZ", "%!", "<nil>"} {
			if strings.Contains(html, bad) {
				t.Errorf("theme=%s: template artifact %q", themeName, bad)
			}
		}
		if !strings.Contains(html, "<!--[if mso") || !strings.Contains(html, "<![endif]-->") {
			t.Errorf("theme=%s: MSO ghost tables missing (html/template comment-stripping regression)", themeName)
		}
		for _, meta := range []string{`name="color-scheme"`, `name="supported-color-schemes"`} {
			if !strings.Contains(html, meta) {
				t.Errorf("theme=%s: missing %s meta", themeName, meta)
			}
		}
		if loc := pureHexRe.FindString(html); loc != "" {
			t.Errorf("theme=%s: pure white/black hex %q in output", themeName, loc)
		}
		for _, banned := range []string{"box-shadow", "linear-gradient", "feDropShadow", "fonts.googleapis.com"} {
			if strings.Contains(html, banned) {
				t.Errorf("theme=%s: banned visual device %q", themeName, banned)
			}
		}
		// Interim contract: the legacy light-styled PNG rides only in LIGHT
		// emails; a dark email carries no chart until the themed renderers
		// land (the numbers live in the detail table either way).
		if themeName == "dark" {
			if len(atts) != 0 || strings.Contains(html, "cid:") {
				t.Errorf("dark critical email must not embed the legacy white chart (got %d attachments)", len(atts))
			}
		} else {
			if len(atts) != 1 || !strings.Contains(html, "cid:cpumem_critical") {
				t.Errorf("light critical email should embed the CPU/Mem chart (got %d attachments)", len(atts))
			}
		}
	}
}
