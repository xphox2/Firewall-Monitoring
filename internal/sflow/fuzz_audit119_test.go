package sflow

import "testing"

// FuzzParseSFlowDatagram exercises the sFlow datagram parser with arbitrary
// bytes (AUDIT-119). sFlow arrives as untrusted UDP from the network, and
// binary parsers are prone to index-out-of-range panics on truncated or
// malformed input — a single crafted packet must not panic the receiver.
// The seed corpus doubles as a fast regression suite under plain `go test`;
// run `go test -fuzz=FuzzParseSFlowDatagram ./internal/sflow` for real fuzzing.
func FuzzParseSFlowDatagram(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 5})             // version 5, nothing else
	f.Add(make([]byte, 28))               // zeroed minimal header
	f.Add([]byte{0, 0, 0, 5, 0, 0, 0, 1}) // version + ip-version, truncated
	f.Add(append([]byte{0, 0, 0, 5, 0, 0, 0, 1}, make([]byte, 200)...))
	f.Add([]byte{255, 255, 255, 255}) // garbage version

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input. The harness fails the test if it does.
		_, _, _, _, _ = ParseSFlowDatagram(data)
	})
}
