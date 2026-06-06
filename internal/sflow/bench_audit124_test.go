package sflow

import "testing"

// BenchmarkParseSFlowDatagram measures the sFlow datagram header parse hot
// path (AUDIT-124). Every inbound sFlow UDP packet hits this; a regression
// raises flow-collection CPU. The fixture is a valid 28-byte sFlow v5 header
// (IPv4 agent, zero samples). Run: go test -bench=. ./internal/sflow
func BenchmarkParseSFlowDatagram(b *testing.B) {
	data := []byte{
		0, 0, 0, 5, // version 5
		0, 0, 0, 1, // address type = IPv4
		127, 0, 0, 1, // agent IP
		0, 0, 0, 0, // sub-agent id
		0, 0, 0, 7, // sequence
		0, 0, 0, 0, // uptime
		0, 0, 0, 0, // sample count
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = ParseSFlowDatagram(data)
	}
}
