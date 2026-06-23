package sflow

import (
	"encoding/binary"
	"testing"
)

// TestParseRawPacketHeader_BytesScaledBySamplingRate is the regression
// for the CTO-loop audit finding (2026-06-22, taocp [critical] #1):
// the server's sFlow parser stored `Bytes = frameLength` verbatim, so
// every dashboard value under-reported real traffic by 1:N. This test
// pins the new convention: a sampled flow record stores
// `frame_length * sampling_rate` in Bytes and `sampling_rate` in
// Packets, matching the collector's behavior.
//
// Without the fix, Bytes == frameLength and Packets == 1 always.
func TestParseRawPacketHeader_BytesScaledBySamplingRate(t *testing.T) {
	const (
		frameLength  = uint32(1500) // typical Ethernet MTU
		samplingRate = uint32(512)  // typical 1:512 sampling
	)
	r := &SFlowReceiver{}

	// Build a minimal raw-packet-header: Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes.
	// Layout per RFC: protocol(4) + frame_length(4) + stripped(4) + header_length(4) + header.
	hdr := make([]byte, 0, 16+54)
	hdr = binary.BigEndian.AppendUint32(hdr, 1)           // protocol = 1 (Ethernet)
	hdr = binary.BigEndian.AppendUint32(hdr, frameLength) // frame_length
	hdr = binary.BigEndian.AppendUint32(hdr, 0)           // stripped
	hdr = binary.BigEndian.AppendUint32(hdr, 54)          // header_length = 54 (Eth+IPv4+TCP)

	// Ethernet (14 bytes): dst MAC + src MAC + ethertype IPv4
	for i := 0; i < 6; i++ {
		hdr = append(hdr, 0xde)
	}
	for i := 0; i < 6; i++ {
		hdr = append(hdr, 0xad)
	}
	hdr = append(hdr, 0x08, 0x00) // ethertype IPv4
	// IPv4 (20 bytes, IHL=5, protocol=TCP=6)
	ip := make([]byte, 20)
	ip[0] = 0x45 // version=4, IHL=5
	ip[9] = 6    // protocol = TCP
	hdr = append(hdr, ip...)
	// TCP (20 bytes)
	tcp := make([]byte, 20)
	tcp[12] = 0x50 // data offset
	tcp[13] = 0x02 // SYN
	hdr = append(hdr, tcp...)

	flow := r.parseRawPacketHeader(hdr, "10.0.0.1", samplingRate, 1, 2)
	if flow == nil {
		t.Fatal("parseRawPacketHeader returned nil")
	}

	// The headline assertions: scaled bytes and packets.
	if want := uint64(frameLength) * uint64(samplingRate); flow.Bytes != want {
		t.Errorf("Bytes = %d, want %d (= frameLength*samplingRate = %d*%d); the audit found this was unscaled", flow.Bytes, want, frameLength, samplingRate)
	}
	if want := uint64(samplingRate); flow.Packets != want {
		t.Errorf("Packets = %d, want %d (= samplingRate); the audit found this was hardcoded to 1", flow.Packets, want)
	}
	if flow.FrameLength != frameLength {
		t.Errorf("FrameLength = %d, want %d (preserved unchanged)", flow.FrameLength, frameLength)
	}
	if flow.SamplingRate != samplingRate {
		t.Errorf("SamplingRate = %d, want %d", flow.SamplingRate, samplingRate)
	}
}

// TestParseRawPacketHeader_BytesUnscaledWhenSamplingRateOne pins the
// edge case: when sampling_rate <= 1 (no sampling), the sample is
// literal — Bytes == frameLength and Packets == 1. The audit's
// convention matches the collector's: only scale when sampling_rate > 1.
func TestParseRawPacketHeader_BytesUnscaledWhenSamplingRateOne(t *testing.T) {
	const (
		frameLength  = uint32(1500)
		samplingRate = uint32(1) // agent is not sampling
	)
	r := &SFlowReceiver{}

	hdr := make([]byte, 0, 16+54)
	hdr = binary.BigEndian.AppendUint32(hdr, 1)
	hdr = binary.BigEndian.AppendUint32(hdr, frameLength)
	hdr = binary.BigEndian.AppendUint32(hdr, 0)
	hdr = binary.BigEndian.AppendUint32(hdr, 54)
	for i := 0; i < 12; i++ {
		hdr = append(hdr, 0xff)
	}
	hdr = append(hdr, 0x08, 0x00)
	hdr = append(hdr, make([]byte, 40)...)

	flow := r.parseRawPacketHeader(hdr, "10.0.0.1", samplingRate, 1, 2)
	if flow == nil {
		t.Fatal("parseRawPacketHeader returned nil")
	}
	if flow.Bytes != uint64(frameLength) {
		t.Errorf("Bytes = %d, want %d (literal: samplingRate=1 means no scaling)", flow.Bytes, frameLength)
	}
	if flow.Packets != 1 {
		t.Errorf("Packets = %d, want 1 (literal sample, no scaling)", flow.Packets)
	}
}

// TestParseRawPacketHeader_ZeroFrameLength pins the liveness-only case:
// a sample with frame_length=0 (the agent reports an alive source but
// no captured packet) must NOT produce bytes/packets — both stay zero.
// The audit's convention: don't fabricate traffic from a liveness beacon.
func TestParseRawPacketHeader_ZeroFrameLength(t *testing.T) {
	r := &SFlowReceiver{}
	hdr := make([]byte, 0, 16+54)
	hdr = binary.BigEndian.AppendUint32(hdr, 1)  // protocol
	hdr = binary.BigEndian.AppendUint32(hdr, 0)  // frame_length = 0 (liveness only)
	hdr = binary.BigEndian.AppendUint32(hdr, 0)  // stripped
	hdr = binary.BigEndian.AppendUint32(hdr, 54) // header_length
	// header bytes (any 54 bytes satisfy the bounds check; the parser
	// won't actually decode anything since frameLength is 0).
	hdr = append(hdr, make([]byte, 54)...)

	flow := r.parseRawPacketHeader(hdr, "10.0.0.1", 512, 1, 2)
	if flow == nil {
		t.Fatal("parseRawPacketHeader returned nil")
	}
	if flow.Bytes != 0 {
		t.Errorf("Bytes = %d, want 0 (liveness-only sample must not fabricate bytes)", flow.Bytes)
	}
	if flow.Packets != 0 {
		t.Errorf("Packets = %d, want 0 (liveness-only sample must not fabricate packets)", flow.Packets)
	}
}
