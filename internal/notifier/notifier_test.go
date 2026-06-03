package notifier

import (
	"strings"
	"testing"
)

// TestSanitizeHeader_StripsCRLF locks in AUDIT-014: a header value built from
// device-controlled input must never contain CR or LF, otherwise an attacker
// who can set Device.Name to "X\r\nBcc: evil@example.com" causes header
// injection into the SMTP Subject line.
func TestSanitizeHeader_StripsCRLF(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "hello", "hello"},
		{"single LF", "a\nb", "ab"},
		{"single CR", "a\rb", "ab"},
		{"CRLF", "a\r\nb", "ab"},
		{"multiple CRLF", "a\r\nb\r\nc", "abc"},
		{"trailing CRLF", "abc\r\n", "abc"},
		{"leading CRLF", "\r\nabc", "abc"},
		{"injection attempt", "Critical Alert\r\nBcc: attacker@evil.com", "Critical AlertBcc: attacker@evil.com"},
		{"only newlines", "\r\n\r\n", ""},
		{"unicode preserved", "Critical \u26a0\ufe0f", "Critical \u26a0\ufe0f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeHeader(tc.in)
			if got != tc.want {
				t.Errorf("SanitizeHeader(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsAny(got, "\r\n") {
				t.Errorf("SanitizeHeader(%q) result %q still contains CR or LF", tc.in, got)
			}
		})
	}
}

// FuzzSanitizeHeader proves the result never contains CR or LF, for any input.
func FuzzSanitizeHeader(f *testing.F) {
	f.Add("")
	f.Add("hello world")
	f.Add("a\r\nb")
	f.Add("\x00\x01\x02")
	f.Fuzz(func(t *testing.T, in string) {
		got := SanitizeHeader(in)
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("SanitizeHeader(%q) result %q contains CR or LF", in, got)
		}
	})
}
