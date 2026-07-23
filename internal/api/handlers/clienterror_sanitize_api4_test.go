package handlers

import "testing"

// TestSanitizeLogField_StripsControlChars is the AUDIT API4 regression: the
// unauthenticated client-error beacon logs attacker-controlled fields, so
// control characters (esp. CR/LF) must be neutralized or a crafted `message`
// could forge fake log lines.
func TestSanitizeLogField_StripsControlChars(t *testing.T) {
	in := "ok\n2026-07-23 client-error ADMIN LOGIN SUCCESS\r\tmore\x00end"
	got := sanitizeLogField(in)

	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control char survived sanitization: %q -> %q", in, got)
		}
	}
	if want := "ok 2026-07-23 client-error ADMIN LOGIN SUCCESS  more end"; got != want {
		t.Fatalf("unexpected output:\n got: %q\nwant: %q", got, want)
	}

	// Plain text is untouched.
	if s := "no control chars here"; sanitizeLogField(s) != s {
		t.Errorf("plain text should pass through unchanged, got %q", sanitizeLogField(s))
	}
}
