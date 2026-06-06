package syslog

import "testing"

// FuzzParseRFC5424 exercises the syslog parser with arbitrary bytes
// (AUDIT-119). Syslog arrives as untrusted input over TCP/UDP, so the parser
// must never panic on malformed messages (bad priority, truncated header,
// embedded NULs, oversized fields). The seed corpus runs as a fast regression
// under plain `go test`; run `go test -fuzz=FuzzParseRFC5424 ./internal/syslog`
// for real fuzzing.
func FuzzParseRFC5424(f *testing.F) {
	seeds := []string{
		"",
		"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - msg",
		"<0>1 - - - - - -",
		"<191>1 - host app - - - body",
		"<>1 x",
		"<99999999999999999999>1 x",
		"not a syslog message at all",
		"<34>1 \x00\x00 host app - - -",
		"<34>",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Neither call may panic on untrusted input.
		_, _ = ParseRFC5424(data)
		_, _ = ParsePriority(data)
	})
}
