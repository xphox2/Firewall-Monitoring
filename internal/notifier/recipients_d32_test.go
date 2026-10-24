package notifier

import (
	"testing"
)

// TestSendEmail_RejectsHeaderInjectionInRecipients_D32 pins D-32: a recipient
// string carrying a line break must be refused before any SMTP traffic. Pre-fix
// "a@example.com,\r\nBcc: x@example.org" split into two envelope recipients
// (TrimSpace ate the CRLF) and was written verbatim into the To: header,
// injecting a Bcc line that a lenient relay delivered.
func TestSendEmail_RejectsHeaderInjectionInRecipients_D32(t *testing.T) {
	port, rcpts := startFakeSMTP(t)
	n := &Notifier{}
	nc := NotifyConfig{
		SMTPHost: "127.0.0.1", SMTPPort: port,
		SMTPFrom: "fwmon@example.com", SMTPTo: "a@example.com,\r\nBcc: x@example.org",
	}
	if err := n.sendEmail(fireAlert("warning"), nc); err == nil {
		t.Fatal("sendEmail accepted a recipient list with an embedded line break")
	}
	if got := rcpts(); len(got) != 0 {
		t.Fatalf("RCPT TO sent despite invalid recipients: %q", got)
	}
}

// TestParseRecipients_D32 pins the address validation: display-name forms are
// reduced to the bare addr-spec the SMTP envelope needs, and a non-address is
// rejected rather than handed to RCPT TO.
func TestParseRecipients_D32(t *testing.T) {
	got, err := parseRecipients("Ops <ops@example.com>, b@example.org")
	if err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	if len(got) != 2 || got[0] != "ops@example.com" || got[1] != "b@example.org" {
		t.Fatalf("parseRecipients = %q", got)
	}
	for _, bad := range []string{"not-an-address", "a@example.com, Bcc: x@example.org", "a@example.com\nb@example.org"} {
		if _, err := parseRecipients(bad); err == nil {
			t.Errorf("parseRecipients(%q) accepted an invalid recipient", bad)
		}
	}
}
