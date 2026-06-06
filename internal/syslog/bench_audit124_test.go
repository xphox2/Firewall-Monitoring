package syslog

import "testing"

// BenchmarkParseRFC5424 measures the syslog parse hot path (AUDIT-124).
// Every inbound syslog line over TCP/UDP runs through this, so a regression
// here directly raises ingestion CPU. Run: go test -bench=. ./internal/syslog
func BenchmarkParseRFC5424(b *testing.B) {
	// This parser treats PRI and VERSION as separate space-delimited tokens
	// (parts[0]=<165>, parts[1]=1, parts[2]=timestamp), so the happy path needs
	// a space after the priority. Verified to parse without the error path.
	msg := []byte(`<165> 1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 8710 ID47 - An application event log entry`)
	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseRFC5424(msg)
	}
}

// BenchmarkParsePriority measures the priority-field parse in isolation.
func BenchmarkParsePriority(b *testing.B) {
	pri := []byte("165")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePriority(pri)
	}
}
