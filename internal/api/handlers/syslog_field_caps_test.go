package handlers

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// TestTruncateSyslogFields pins D-27: oversized free-form syslog fields are
// truncated to maxSyslogFieldLen, while short fields are untouched.
func TestTruncateSyslogFields(t *testing.T) {
	long := strings.Repeat("x", maxSyslogFieldLen+100)
	m := &models.SyslogMessage{Message: long, Hostname: long, SourceIP: "1.2.3.4", AppName: "app"}
	truncateSyslogFields(m)

	if len(m.Message) != maxSyslogFieldLen {
		t.Errorf("Message len = %d, want %d", len(m.Message), maxSyslogFieldLen)
	}
	if len(m.Hostname) != maxSyslogFieldLen {
		t.Errorf("Hostname len = %d, want %d", len(m.Hostname), maxSyslogFieldLen)
	}
	if m.SourceIP != "1.2.3.4" {
		t.Errorf("SourceIP should be untouched, got %q", m.SourceIP)
	}
	if m.AppName != "app" {
		t.Errorf("AppName should be untouched, got %q", m.AppName)
	}
}
