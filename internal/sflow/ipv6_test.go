package sflow

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildIPv6 builds a bare IPv6 packet (no Ethernet) whose fixed-header Next
// Header is firstNH, followed by payload (extension headers + L4).
func buildIPv6(firstNH uint8, payload []byte) []byte {
	ip6 := make([]byte, 40)
	ip6[6] = firstNH
	ip6[7] = 64 // hop limit
	copy(ip6[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ip6[24:40], net.ParseIP("2001:db8::2").To16())
	return append(ip6, payload...)
}

// TestParseIPv6_HopByHopToTCP is the core regression for the HOPOPT bug: an
// IPv6 packet starting with a Hop-by-Hop Options extension header (Next Header
// = 0) must resolve to its real upper-layer protocol (TCP) with ports, not be
// recorded as protocol 0 (HOPOPT).
func TestParseIPv6_HopByHopToTCP(t *testing.T) {
	hbh := []byte{6, 0, 0, 0, 0, 0, 0, 0} // next_header=TCP, hdr_ext_len=0 (8 bytes)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 4444)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[13] = 0x02 // SYN

	var f ParsedFlow
	parseIPv6(buildIPv6(0, append(hbh, tcp...)), &f)

	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP) — HOPOPT chain not walked", f.Protocol)
	}
	if f.SrcPort != 4444 || f.DstPort != 443 {
		t.Errorf("ports = %d->%d, want 4444->443", f.SrcPort, f.DstPort)
	}
	if f.TCPFlags != 0x02 {
		t.Errorf("TCPFlags = 0x%02x, want 0x02", f.TCPFlags)
	}
	if f.SrcAddr != "2001:db8::1" || f.DstAddr != "2001:db8::2" {
		t.Errorf("addr mismatch: src=%q dst=%q", f.SrcAddr, f.DstAddr)
	}
}

// TestParseIPv6_HopByHopToICMPv6 verifies a portless upper-layer protocol is
// resolved through the chain to 58 (ICMPv6), not 0, with no ports.
func TestParseIPv6_HopByHopToICMPv6(t *testing.T) {
	hbh := []byte{58, 0, 0, 0, 0, 0, 0, 0}
	var f ParsedFlow
	parseIPv6(buildIPv6(0, append(hbh, 0x80, 0x00, 0x00, 0x00)), &f)

	if f.Protocol != 58 {
		t.Errorf("Protocol = %d, want 58 (ICMPv6)", f.Protocol)
	}
	if f.SrcPort != 0 || f.DstPort != 0 {
		t.Errorf("ICMPv6 must have no ports, got %d->%d", f.SrcPort, f.DstPort)
	}
}

// TestParseIPv6_ChainedExtHeadersToUDP walks two stacked extension headers
// (Hop-by-Hop then Destination Options) before reaching UDP.
func TestParseIPv6_ChainedExtHeadersToUDP(t *testing.T) {
	hbh := []byte{60, 0, 0, 0, 0, 0, 0, 0} // -> Destination Options
	dst := []byte{17, 0, 0, 0, 0, 0, 0, 0} // -> UDP
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 5353)
	binary.BigEndian.PutUint16(udp[2:], 53)

	var f ParsedFlow
	parseIPv6(buildIPv6(0, append(append(hbh, dst...), udp...)), &f)

	if f.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17 (UDP) through 2 ext headers", f.Protocol)
	}
	if f.SrcPort != 5353 || f.DstPort != 53 {
		t.Errorf("ports = %d->%d, want 5353->53", f.SrcPort, f.DstPort)
	}
}

// TestParseIPv6_NoExtHeaderToTCP verifies the common no-extension-header path.
func TestParseIPv6_NoExtHeaderToTCP(t *testing.T) {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 1111)
	binary.BigEndian.PutUint16(tcp[2:], 22)
	var f ParsedFlow
	parseIPv6(buildIPv6(6, tcp), &f)
	if f.Protocol != 6 || f.SrcPort != 1111 || f.DstPort != 22 {
		t.Errorf("got proto=%d %d->%d", f.Protocol, f.SrcPort, f.DstPort)
	}
}

// TestParseIPv6_TruncatedExtHeader verifies a chain cut off mid-extension does
// not panic and does not fabricate ports.
func TestParseIPv6_TruncatedExtHeader(t *testing.T) {
	var f ParsedFlow
	parseIPv6(buildIPv6(0, []byte{6}), &f) // next-header byte only, no length byte
	if f.SrcPort != 0 || f.DstPort != 0 {
		t.Errorf("truncated ext header produced ports: %d->%d", f.SrcPort, f.DstPort)
	}
}

// TestParseIPv4_6in4InnerDecode verifies a 6in4 tunnel (IPv4 protocol 41
// carrying IPv6) is decoded to its inner conversation: real upper-layer
// protocol, inner IPv6 addresses, and inner ports — not just "IPv6" (41).
func TestParseIPv4_6in4InnerDecode(t *testing.T) {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 7000)
	binary.BigEndian.PutUint16(tcp[2:], 8443)
	tcp[13] = 0x10 // ACK
	inner := buildIPv6(6 /* inner = TCP */, tcp)

	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 41 // 6in4 (IPv6 encapsulation)
	copy(ip[12:16], net.IPv4(203, 0, 113, 1).To4())
	copy(ip[16:20], net.IPv4(203, 0, 113, 2).To4())

	var f ParsedFlow
	parseIPv4(append(ip, inner...), &f)

	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (inner TCP) — 6in4 not decoded", f.Protocol)
	}
	if f.SrcAddr != "2001:db8::1" || f.DstAddr != "2001:db8::2" {
		t.Errorf("inner addresses not decoded: src=%q dst=%q", f.SrcAddr, f.DstAddr)
	}
	if f.SrcPort != 7000 || f.DstPort != 8443 {
		t.Errorf("inner ports = %d->%d, want 7000->8443", f.SrcPort, f.DstPort)
	}
}

// TestParseIPv4_6in4Truncated verifies that when the inner IPv6 header is
// truncated out of the sampled bytes, decoding falls back to the outer IPv4
// tunnel endpoints and protocol 41 without panicking.
func TestParseIPv4_6in4Truncated(t *testing.T) {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 41
	copy(ip[12:16], net.IPv4(203, 0, 113, 1).To4())
	copy(ip[16:20], net.IPv4(203, 0, 113, 2).To4())

	var f ParsedFlow
	parseIPv4(append(ip, make([]byte, 10)...), &f) // inner IPv6 only 10 bytes

	if f.Protocol != 41 {
		t.Errorf("Protocol = %d, want 41 (fallback on truncated inner)", f.Protocol)
	}
	if f.SrcAddr != "203.0.113.1" || f.DstAddr != "203.0.113.2" {
		t.Errorf("expected outer IPv4 fallback addrs, got src=%q dst=%q", f.SrcAddr, f.DstAddr)
	}
}

// TestParseIPv6_TooShort verifies a sub-40-byte header is rejected cleanly.
func TestParseIPv6_TooShort(t *testing.T) {
	var f ParsedFlow
	parseIPv6(make([]byte, 20), &f)
	if f.SrcAddr != "" || f.DstAddr != "" {
		t.Errorf("decoded addresses from short IPv6 header: src=%q dst=%q", f.SrcAddr, f.DstAddr)
	}
}
