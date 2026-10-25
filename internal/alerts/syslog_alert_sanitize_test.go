package alerts

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// D-38: a syslog event-rule alert carries the device's message text into the
// alert row and every notification channel. CR/LF/ESC in it must not survive
// into Alert.Message; the stored syslog row itself is left untouched.
func TestFireEventAlert_SyslogControlCharsNeutralised(t *testing.T) {
	am, db := newTestManager(t)
	installChainRulesDB(t, am, db) // device 1 → "dev-alert" fires on any message

	msg := &models.SyslogMessage{
		DeviceID:  1,
		Hostname:  "fw1\r\nPRIVMSG #ops :pwned",
		Message:   "link down\r\n[CRITICAL] forged line\x1b[2J\u009b\x00 end",
		Timestamp: time.Now(),
	}
	raw := msg.Message
	if err := am.EvaluateSyslog(msg, nil); err != nil {
		t.Fatalf("EvaluateSyslog: %v", err)
	}
	var a models.Alert
	if err := db.Gorm().Where("device_id = ?", 1).First(&a).Error; err != nil {
		t.Fatalf("expected the rule to fire: %v", err)
	}
	want := "[dev-alert] fw1  PRIVMSG #ops :pwned: link down  [CRITICAL] forged line [2J   end"
	if a.Message != want {
		t.Fatalf("Alert.Message = %q\nwant            %q", a.Message, want)
	}
	if msg.Message != raw {
		t.Fatalf("the syslog message itself must not be rewritten: got %q", msg.Message)
	}
}

func TestSingleLine(t *testing.T) {
	cases := map[string]string{
		"plain text":          "plain text",
		"a\tb\nc\rd\x7fe":     "a b c d e",
		"Zürich ✓":            "Zürich ✓",
		"bad \xff utf8":       "bad � utf8",
		"c1 \u0085 next-line": "c1   next-line",
	}
	for in, want := range cases {
		if got := singleLine(in); got != want {
			t.Errorf("singleLine(%q) = %q, want %q", in, got, want)
		}
	}
}
