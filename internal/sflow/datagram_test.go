package sflow

import (
	"encoding/binary"
	"net"
	"testing"
)

// --- byte-fixture builders (sFlow v5 / RFC 3176) ---

// ethIPv4TCP builds an Ethernet+IPv4+TCP frame with the given addresses/ports.
func ethIPv4TCP(src, dst string, sport, dport uint16) []byte {
	frame := make([]byte, 0, 54)
	frame = append(frame, 0xde, 0xde, 0xde, 0xde, 0xde, 0xde) // dst MAC
	frame = append(frame, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad) // src MAC
	frame = append(frame, 0x08, 0x00)                         // ethertype IPv4

	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	ip[9] = 6    // protocol TCP
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	frame = append(frame, ip...)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[13] = 0x02 // SYN
	frame = append(frame, tcp...)
	return frame
}

// rawPacketHeaderRecord wraps a frame in a raw-packet-header flow record
// (record type enterprise=0/format=1).
func rawPacketHeaderRecord(frameLength uint32, frame []byte) []byte {
	payload := make([]byte, 0, 16+len(frame))
	payload = binary.BigEndian.AppendUint32(payload, 1)           // header protocol = Ethernet
	payload = binary.BigEndian.AppendUint32(payload, frameLength) // frame_length
	payload = binary.BigEndian.AppendUint32(payload, 0)           // stripped
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(frame)))
	payload = append(payload, frame...)

	rec := make([]byte, 0, 8+len(payload))
	rec = binary.BigEndian.AppendUint32(rec, 1) // enterprise 0, format 1 (raw packet header)
	rec = binary.BigEndian.AppendUint32(rec, uint32(len(payload)))
	rec = append(rec, payload...)
	return rec
}

// standardFlowSample builds a standard (non-expanded) flow-sample body.
func standardFlowSample(samplingRate, inputIf, outputIf uint32, records []byte, numRecords uint32) []byte {
	b := make([]byte, 32)
	// [0:4] sequence, [4:8] source_id left zero
	binary.BigEndian.PutUint32(b[8:12], samplingRate)
	// [12:16] sample_pool, [16:20] drops left zero
	binary.BigEndian.PutUint32(b[20:24], inputIf)
	binary.BigEndian.PutUint32(b[24:28], outputIf)
	binary.BigEndian.PutUint32(b[28:32], numRecords)
	return append(b, records...)
}

// expandedFlowSample builds an expanded (format 3) flow-sample body.
func expandedFlowSample(samplingRate, inputIf, outputIf uint32, records []byte, numRecords uint32) []byte {
	b := make([]byte, 44)
	binary.BigEndian.PutUint32(b[12:16], samplingRate)
	binary.BigEndian.PutUint32(b[28:32], inputIf)
	binary.BigEndian.PutUint32(b[36:40], outputIf)
	binary.BigEndian.PutUint32(b[40:44], numRecords)
	return append(b, records...)
}

// sample wraps a sample body with its type/length header.
func sample(format uint32, body []byte) []byte {
	s := make([]byte, 0, 8+len(body))
	s = binary.BigEndian.AppendUint32(s, format) // enterprise 0, given format
	s = binary.BigEndian.AppendUint32(s, uint32(len(body)))
	return append(s, body...)
}

// datagramIPv4 builds a full v5 datagram with an IPv4 agent address.
func datagramIPv4(agent string, numSamples uint32, samples []byte) []byte {
	d := make([]byte, 28)
	binary.BigEndian.PutUint32(d[0:4], 5) // version
	binary.BigEndian.PutUint32(d[4:8], 1) // address type IPv4
	copy(d[8:12], net.ParseIP(agent).To4())
	// [12:16] sub_agent, [16:20] sequence, [20:24] uptime left zero
	binary.BigEndian.PutUint32(d[24:28], numSamples)
	return append(d, samples...)
}

func newReceiverCapturing() (*SFlowReceiver, *[]*ParsedFlow) {
	r := &SFlowReceiver{}
	var got []*ParsedFlow
	r.SetFlowHandler(func(f *ParsedFlow) { got = append(got, f) })
	return r, &got
}

// TestParseDatagramStandardFlowSample drives the full path
// parseDatagram → parseFlowSample → parseRawPacketHeader → handler.
func TestParseDatagramStandardFlowSample(t *testing.T) {
	r, got := newReceiverCapturing()
	rec := rawPacketHeaderRecord(1500, ethIPv4TCP("10.0.0.1", "10.0.0.2", 1234, 80))
	body := standardFlowSample(512, 7, 9, rec, 1)
	dg := datagramIPv4("192.0.2.1", 1, sample(1, body))

	r.parseDatagram(dg)

	if len(*got) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(*got))
	}
	f := (*got)[0]
	if f.AgentIP != "192.0.2.1" {
		t.Errorf("AgentIP = %q", f.AgentIP)
	}
	if f.SrcAddr != "10.0.0.1" || f.DstAddr != "10.0.0.2" {
		t.Errorf("addrs = %s -> %s", f.SrcAddr, f.DstAddr)
	}
	if f.SrcPort != 1234 || f.DstPort != 80 || f.Protocol != 6 {
		t.Errorf("L4 = proto %d %d->%d", f.Protocol, f.SrcPort, f.DstPort)
	}
	if f.InputIfIndex != 7 || f.OutputIfIndex != 9 {
		t.Errorf("ifindex in=%d out=%d", f.InputIfIndex, f.OutputIfIndex)
	}
	// Bytes scaled by sampling rate (RFC 3176): 1500 * 512.
	if f.Bytes != uint64(1500)*512 || f.Packets != 512 {
		t.Errorf("scaling: Bytes=%d Packets=%d", f.Bytes, f.Packets)
	}
}

// TestParseDatagramExpandedFlowSample exercises the expanded (format 3) path.
func TestParseDatagramExpandedFlowSample(t *testing.T) {
	r, got := newReceiverCapturing()
	rec := rawPacketHeaderRecord(64, ethIPv4TCP("172.16.0.5", "172.16.0.9", 5000, 443))
	body := expandedFlowSample(256, 3, 4, rec, 1)
	dg := datagramIPv4("192.0.2.9", 1, sample(3, body))

	r.parseDatagram(dg)

	if len(*got) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(*got))
	}
	f := (*got)[0]
	if f.SrcPort != 5000 || f.DstPort != 443 {
		t.Errorf("ports = %d->%d", f.SrcPort, f.DstPort)
	}
	if f.InputIfIndex != 3 || f.OutputIfIndex != 4 {
		t.Errorf("ifindex in=%d out=%d", f.InputIfIndex, f.OutputIfIndex)
	}
}

// TestParseDatagramMalformed confirms the bounds/validation guards reject bad
// datagrams without panicking or emitting flows.
func TestParseDatagramMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"too short", make([]byte, 20)},
		{"wrong version", func() []byte { d := datagramIPv4("192.0.2.1", 0, nil); binary.BigEndian.PutUint32(d[0:4], 4); return d }()},
		{"bad address type", func() []byte { d := datagramIPv4("192.0.2.1", 0, nil); binary.BigEndian.PutUint32(d[4:8], 9); return d }()},
		{"ipv6 agent but truncated", func() []byte {
			d := make([]byte, 30)
			binary.BigEndian.PutUint32(d[0:4], 5)
			binary.BigEndian.PutUint32(d[4:8], 2) // IPv6 agent needs >= 40 bytes
			return d
		}()},
		{"num_samples exceeds body", datagramIPv4("192.0.2.1", 5, nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, got := newReceiverCapturing()
			r.parseDatagram(tc.data) // must not panic
			if len(*got) != 0 {
				t.Errorf("expected no flows, got %d", len(*got))
			}
		})
	}
}

// TestParseDatagramSkipsCounterSamples confirms non-flow samples (format 2) are
// skipped, not misparsed.
func TestParseDatagramSkipsCounterSamples(t *testing.T) {
	r, got := newReceiverCapturing()
	counter := sample(2, make([]byte, 16)) // counter sample — must be ignored
	dg := datagramIPv4("192.0.2.1", 1, counter)
	r.parseDatagram(dg)
	if len(*got) != 0 {
		t.Errorf("counter sample should yield no flows, got %d", len(*got))
	}
}

// TestParseFlowSampleNilHandler confirms the early return when no handler is set.
func TestParseFlowSampleNilHandler(t *testing.T) {
	r := &SFlowReceiver{} // no handler
	r.parseFlowSample(make([]byte, 64), "192.0.2.1", false)
	// reaching here without panic is the assertion
}

// TestParseRawPacketHeaderVariants covers the protocol-dispatch branches that
// the existing tests miss: VLAN-tagged IPv4, Ethernet IPv6, direct IPv4/IPv6
// (no Ethernet), and the short/empty guards.
func TestParseRawPacketHeaderVariants(t *testing.T) {
	r := &SFlowReceiver{}

	t.Run("too short", func(t *testing.T) {
		if r.parseRawPacketHeader(make([]byte, 8), "a", 1, 0, 0) != nil {
			t.Error("expected nil for < 16 bytes")
		}
	})

	t.Run("zero header length", func(t *testing.T) {
		d := make([]byte, 16) // headerLen field stays 0
		binary.BigEndian.PutUint32(d[0:4], 1)
		if r.parseRawPacketHeader(d, "a", 1, 0, 0) != nil {
			t.Error("expected nil for headerLen 0")
		}
	})

	t.Run("vlan tagged ipv4", func(t *testing.T) {
		frame := make([]byte, 0)
		frame = append(frame, make([]byte, 12)...) // dst+src MAC
		frame = append(frame, 0x81, 0x00)          // 802.1Q
		frame = append(frame, 0x00, 0x64)          // VLAN id 100
		frame = append(frame, 0x08, 0x00)          // inner ethertype IPv4
		ip := make([]byte, 20)
		ip[0] = 0x45
		ip[9] = 17 // UDP
		copy(ip[12:16], net.ParseIP("10.1.1.1").To4())
		copy(ip[16:20], net.ParseIP("10.1.1.2").To4())
		frame = append(frame, ip...)
		udp := make([]byte, 8)
		binary.BigEndian.PutUint16(udp[0:2], 53)
		binary.BigEndian.PutUint16(udp[2:4], 9999)
		frame = append(frame, udp...)

		payload := rawPacketHeaderRecord(uint32(len(frame)), frame)[8:] // strip record header
		f := r.parseRawPacketHeader(payload, "a", 4, 0, 0)
		if f == nil || f.Protocol != 17 || f.SrcPort != 53 || f.DstPort != 9999 {
			t.Errorf("vlan ipv4 udp parse = %+v", f)
		}
	})

	t.Run("direct ipv4 protocol 11", func(t *testing.T) {
		ip := make([]byte, 20)
		ip[0] = 0x45
		ip[9] = 6
		copy(ip[12:16], net.ParseIP("8.8.8.8").To4())
		copy(ip[16:20], net.ParseIP("8.8.4.4").To4())
		ip = append(ip, make([]byte, 20)...) // TCP
		binary.BigEndian.PutUint16(ip[20:22], 100)
		binary.BigEndian.PutUint16(ip[22:24], 200)

		d := make([]byte, 16)
		binary.BigEndian.PutUint32(d[0:4], 11) // header protocol = IPv4
		binary.BigEndian.PutUint32(d[4:8], 60)
		binary.BigEndian.PutUint32(d[12:16], uint32(len(ip)))
		d = append(d, ip...)
		f := r.parseRawPacketHeader(d, "a", 1, 0, 0)
		if f == nil || f.SrcAddr != "8.8.8.8" || f.DstAddr != "8.8.4.4" {
			t.Errorf("direct ipv4 parse = %+v", f)
		}
	})
}
