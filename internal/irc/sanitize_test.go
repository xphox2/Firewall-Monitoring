package irc

import "testing"

// TestSanitizeIRCStripsControlBytes pins the CRLF/NUL injection guard: a device
// name, channel name or message carrying \r, \n or NUL must never reach the IRC
// wire, where go-ircevent would otherwise treat them as protocol line breaks
// and let a crafted string inject raw commands (QUIT/NICK/PRIVMSG NickServ).
func TestSanitizeIRCStripsControlBytes(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"#channel", "#channel"},
		{"", ""},
		{"x\r\nQUIT\r\n", "xQUIT"},
		{"a\nb\rc\x00d", "abcd"},
		{"no controls here", "no controls here"},
		{"\r\n", ""},
	}
	for _, c := range cases {
		if got := sanitizeIRC(c.in); got != c.want {
			t.Errorf("sanitizeIRC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
