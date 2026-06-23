package sflow

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ParsedFlow represents a decoded sFlow flow sample with extracted IP header fields.
type ParsedFlow struct {
	AgentIP       string
	SamplingRate  uint32
	InputIfIndex  uint32
	OutputIfIndex uint32
	SrcAddr       string
	DstAddr       string
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	Bytes         uint64
	Packets       uint64
	TCPFlags      uint8
	FrameLength   uint32
}

type FlowSample struct {
	ID             uint64          `json:"id"`
	Timestamp      time.Time       `json:"timestamp"`
	ProbeID        uint32          `json:"probe_id"`
	DeviceID       uint32          `json:"device_id"`
	SequenceNumber uint32          `json:"sequence_number"`
	SourceID       uint32          `json:"source_id"`
	SamplingRate   uint32          `json:"sampling_rate"`
	SamplePool     uint32          `json:"sample_pool"`
	InputIfIndex   uint32          `json:"input_if_index"`
	OutputIfIndex  uint32          `json:"output_if_index"`
	FlowData       json.RawMessage `json:"flow_data"`
}

type CounterSample struct {
	ID          uint64    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ProbeID     uint32    `json:"probe_id"`
	DeviceID    uint32    `json:"device_id"`
	IfIndex     uint32    `json:"if_index"`
	IfType      uint32    `json:"if_type"`
	IfSpeed     uint64    `json:"if_speed"`
	IfDirection uint32    `json:"if_direction"`
	IfInOctets  uint64    `json:"if_in_octets"`
	IfOutOctets uint64    `json:"if_out_octets"`
	IfInUcasts  uint64    `json:"if_in_ucasts"`
	IfOutUcasts uint64    `json:"if_out_ucasts"`
	IfInErrors  uint64    `json:"if_in_errors"`
	IfOutErrors uint64    `json:"if_out_errors"`
}

// FlowHandler is called for each decoded flow sample.
type FlowHandler func(*ParsedFlow)

type SFlowReceiver struct {
	ListenAddr  string
	Port        int
	conn        *net.UDPConn
	stopChan    chan struct{}
	running     atomic.Bool
	wg          sync.WaitGroup
	allowedIPs  map[string]bool
	flowHandler FlowHandler
}

func NewSFlowReceiver(listenAddr string, port int, allowedSources ...[]string) *SFlowReceiver {
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}
	if port == 0 {
		port = 6343
	}
	allowed := make(map[string]bool)
	if len(allowedSources) > 0 {
		for _, ip := range allowedSources[0] {
			if ip != "" {
				allowed[ip] = true
			}
		}
	}
	return &SFlowReceiver{
		ListenAddr: listenAddr,
		Port:       port,
		stopChan:   make(chan struct{}),
		allowedIPs: allowed,
	}
}

func (r *SFlowReceiver) SetFlowHandler(h FlowHandler) {
	r.flowHandler = h
}

func (r *SFlowReceiver) Start() error {
	if r.running.Load() {
		return errors.New("sFlow receiver already running")
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", r.ListenAddr, r.Port))
	if err != nil {
		return err
	}

	r.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	r.running.Store(true)
	r.wg.Add(1)
	go r.readLoop()

	return nil
}

func (r *SFlowReceiver) Stop() error {
	if !r.running.Load() {
		return errors.New("sFlow receiver not running")
	}

	r.running.Store(false)
	close(r.stopChan)

	if r.conn != nil {
		r.conn.Close()
	}

	r.wg.Wait()
	return nil
}

func (r *SFlowReceiver) readLoop() {
	defer r.wg.Done()

	buf := make([]byte, 65536)
	for r.running.Load() {
		select {
		case <-r.stopChan:
			return
		default:
			r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := r.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if r.running.Load() {
					return
				}
				return
			}

			if n > 0 {
				if len(r.allowedIPs) > 0 && !r.allowedIPs[addr.IP.String()] {
					continue
				}
				r.parseDatagram(buf[:n])
			}
		}
	}
}

// parseDatagram decodes an sFlow v5 datagram and dispatches flow samples to the handler.
func (r *SFlowReceiver) parseDatagram(data []byte) {
	if len(data) < 28 {
		return
	}

	version := binary.BigEndian.Uint32(data[0:4])
	if version != 5 {
		return
	}

	addrType := binary.BigEndian.Uint32(data[4:8])
	var agentIP string
	var offset int
	if addrType == 1 { // IPv4
		if len(data) < 28 {
			return
		}
		agentIP = net.IP(data[8:12]).String()
		offset = 12
	} else if addrType == 2 { // IPv6
		if len(data) < 40 {
			return
		}
		agentIP = net.IP(data[8:24]).String()
		offset = 24
	} else {
		return
	}

	// sub_agent_id(4) + sequence(4) + uptime(4) + num_samples(4)
	if len(data) < offset+16 {
		return
	}
	// _ = binary.BigEndian.Uint32(data[offset : offset+4]) // sub_agent_id
	// _ = binary.BigEndian.Uint32(data[offset+4 : offset+8]) // sequence
	// _ = binary.BigEndian.Uint32(data[offset+8 : offset+12]) // uptime
	numSamples := binary.BigEndian.Uint32(data[offset+12 : offset+16])
	offset += 16

	for i := uint32(0); i < numSamples && offset < len(data)-8; i++ {
		if offset+8 > len(data) {
			break
		}
		sampleTypeRaw := binary.BigEndian.Uint32(data[offset : offset+4])
		sampleLen := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8

		if offset+int(sampleLen) > len(data) {
			break
		}

		enterprise := sampleTypeRaw >> 12
		format := sampleTypeRaw & 0xFFF

		if enterprise == 0 && (format == 1 || format == 3) {
			// Flow sample (1) or expanded flow sample (3)
			r.parseFlowSample(data[offset:offset+int(sampleLen)], agentIP, format == 3)
		}
		// Skip counter samples and other types

		offset += int(sampleLen)
	}
}

// parseFlowSample decodes a single flow sample record.
func (r *SFlowReceiver) parseFlowSample(data []byte, agentIP string, expanded bool) {
	if r.flowHandler == nil {
		return
	}

	var offset int
	minLen := 32
	if expanded {
		minLen = 44
	}
	if len(data) < minLen {
		return
	}

	// _ = binary.BigEndian.Uint32(data[0:4]) // sequence
	var samplingRate, inputIf, outputIf uint32
	var numRecords uint32

	if expanded {
		// Expanded flow sample: source_id_type(4) + source_id_index(4) + sampling_rate(4) + sample_pool(4) + drops(4) + input_if_format(4) + input_if(4) + output_if_format(4) + output_if(4) + num_records(4)
		samplingRate = binary.BigEndian.Uint32(data[12:16])
		inputIf = binary.BigEndian.Uint32(data[28:32])
		outputIf = binary.BigEndian.Uint32(data[36:40])
		numRecords = binary.BigEndian.Uint32(data[40:44])
		offset = 44
	} else {
		// Standard flow sample: source_id(4) + sampling_rate(4) + sample_pool(4) + drops(4) + input(4) + output(4) + num_records(4)
		samplingRate = binary.BigEndian.Uint32(data[8:12])
		inputIf = binary.BigEndian.Uint32(data[20:24])
		outputIf = binary.BigEndian.Uint32(data[24:28])
		numRecords = binary.BigEndian.Uint32(data[28:32])
		offset = 32
	}

	// Parse flow records looking for raw packet header
	for j := uint32(0); j < numRecords && offset < len(data)-8; j++ {
		if offset+8 > len(data) {
			break
		}
		recTypeRaw := binary.BigEndian.Uint32(data[offset : offset+4])
		recLen := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8

		if offset+int(recLen) > len(data) {
			break
		}

		recEnterprise := recTypeRaw >> 12
		recFormat := recTypeRaw & 0xFFF

		if recEnterprise == 0 && recFormat == 1 {
			// Raw packet header record
			flow := r.parseRawPacketHeader(data[offset:offset+int(recLen)], agentIP, samplingRate, inputIf, outputIf)
			if flow != nil {
				r.flowHandler(flow)
			}
		}

		offset += int(recLen)
	}
}

// parseRawPacketHeader extracts IP/TCP/UDP fields from a sampled raw packet header.
func (r *SFlowReceiver) parseRawPacketHeader(data []byte, agentIP string, samplingRate, inputIf, outputIf uint32) *ParsedFlow {
	if len(data) < 16 {
		return nil
	}

	headerProto := binary.BigEndian.Uint32(data[0:4])
	frameLength := binary.BigEndian.Uint32(data[4:8])
	// stripped := binary.BigEndian.Uint32(data[8:12])
	headerLen := binary.BigEndian.Uint32(data[12:16])

	if headerLen == 0 || 16+int(headerLen) > len(data) {
		return nil
	}

	header := data[16 : 16+headerLen]

	flow := &ParsedFlow{
		AgentIP:       agentIP,
		SamplingRate:  samplingRate,
		InputIfIndex:  inputIf,
		OutputIfIndex: outputIf,
		FrameLength:   frameLength,
	}

	// Per sFlow v5 semantics (RFC 3176), a single sampled flow record
	// represents `sampling_rate` packets of `frame_length` bytes each.
	// The collector (Firewall-Collector/internal/sflow/sflow.go:301-309)
	// applies this scaling on its side; the server MUST do the same so
	// SUM(bytes) / SUM(packets) on the read path produces real traffic
	// volume, not 1/Nth of it. Previously the server stored frameLength
	// verbatim, under-reporting by 1:N (e.g. 512× at 1:512 sampling).
	// See tasks/lessons.md "sFlow packets × sampling_rate is non-negotiable".
	if frameLength > 0 && samplingRate > 1 {
		flow.Bytes = uint64(frameLength) * uint64(samplingRate)
		flow.Packets = uint64(samplingRate)
	} else if frameLength > 0 {
		flow.Bytes = uint64(frameLength)
		flow.Packets = 1
	}

	// Parse based on header protocol
	switch headerProto {
	case 1: // Ethernet
		if len(header) < 14 {
			return flow
		}
		etherType := binary.BigEndian.Uint16(header[12:14])
		ipStart := 14

		// Handle 802.1Q VLAN tag
		if etherType == 0x8100 {
			if len(header) < 18 {
				return flow
			}
			etherType = binary.BigEndian.Uint16(header[16:18])
			ipStart = 18
		}

		switch etherType {
		case 0x0800: // IPv4
			parseIPv4(header[ipStart:], flow)
		case 0x86DD: // IPv6
			parseIPv6(header[ipStart:], flow)
		}
	case 11: // IPv4
		parseIPv4(header, flow)
	case 12: // IPv6
		parseIPv6(header, flow)
	}

	return flow
}

// parseIPv4 extracts src/dst IP, protocol, ports, and TCP flags from an IPv4 header.
func parseIPv4(data []byte, flow *ParsedFlow) {
	if len(data) < 20 {
		return
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl {
		return
	}

	flow.Protocol = data[9]
	flow.SrcAddr = net.IP(data[12:16]).String()
	flow.DstAddr = net.IP(data[16:20]).String()

	// 6in4: an IPv4 packet whose protocol is 41 carries a full IPv6 packet.
	// Decode the inner IPv6 so the flow reflects the real conversation (inner
	// src/dst, upper-layer protocol, ports) instead of just "IPv6". parseIPv6
	// overwrites SrcAddr/DstAddr/Protocol/ports; a truncated inner header
	// leaves the outer IPv4 tunnel endpoints and protocol 41 as a fallback.
	if flow.Protocol == 41 {
		parseIPv6(data[ihl:], flow)
		return
	}

	parseTransport(data[ihl:], flow)
}

// isIPv6ExtHeader reports whether an IPv6 "Next Header" value is an extension
// header (which chains to a further header) rather than an upper-layer protocol.
// ESP (50) is deliberately excluded: its payload is encrypted, so the chain
// cannot be walked past it. No-Next-Header (59) is also terminal.
func isIPv6ExtHeader(nh uint8) bool {
	switch nh {
	case 0, // Hop-by-Hop Options
		43,  // Routing
		44,  // Fragment
		51,  // Authentication Header
		60,  // Destination Options
		135: // Mobility
		return true
	}
	return false
}

// parseIPv6 extracts src/dst IP, the real upper-layer protocol, and ports from
// an IPv6 header. It walks the extension-header chain so a packet carrying e.g.
// a Hop-by-Hop Options header (Next Header = 0, common for MLD/multicast,
// Router Alert, jumbograms) is not mis-recorded as protocol 0 (HOPOPT) with no
// ports. Sampled headers are truncated, so every read is bounds-checked and the
// walk is capped against malformed/looping chains.
func parseIPv6(data []byte, flow *ParsedFlow) {
	if len(data) < 40 {
		return
	}

	flow.SrcAddr = net.IP(data[8:24]).String()
	flow.DstAddr = net.IP(data[24:40]).String()

	nextHeader := data[6]
	offset := 40
	for i := 0; i < 8 && isIPv6ExtHeader(nextHeader); i++ {
		if offset+2 > len(data) {
			break // can't read this ext header — keep nextHeader as best effort
		}
		var extLen int
		switch nextHeader {
		case 44: // Fragment header is always 8 bytes
			extLen = 8
		case 51: // Authentication Header: (length + 2) 4-byte units
			extLen = (int(data[offset+1]) + 2) * 4
		default: // Hop-by-Hop(0), Routing(43), Dest-Opts(60), Mobility(135)
			extLen = (int(data[offset+1]) + 1) * 8
		}
		nextHeader = data[offset]
		offset += extLen
	}

	flow.Protocol = nextHeader
	if offset <= len(data) {
		parseTransport(data[offset:], flow)
	}
}

// parseTransport reads TCP/UDP ports (and TCP flags) from the L4 header,
// dispatching on flow.Protocol. Other protocols (ICMP/ICMPv6/GRE/ESP/…) have
// no ports and are left as-is.
func parseTransport(transport []byte, flow *ParsedFlow) {
	switch flow.Protocol {
	case 6: // TCP
		if len(transport) >= 14 {
			flow.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			flow.DstPort = binary.BigEndian.Uint16(transport[2:4])
			flow.TCPFlags = transport[13]
		}
	case 17: // UDP
		if len(transport) >= 4 {
			flow.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			flow.DstPort = binary.BigEndian.Uint16(transport[2:4])
		}
	}
}

// ParseSFlowDatagram returns header fields for diagnostic purposes.
func ParseSFlowDatagram(data []byte) (uint32, uint32, net.IP, uint32, error) {
	if len(data) < 28 {
		return 0, 0, nil, 0, errors.New("sFlow datagram too short")
	}

	version := binary.BigEndian.Uint32(data[0:4])
	if version != 5 {
		return 0, 0, nil, 0, errors.New("unsupported sFlow version")
	}

	addrType := binary.BigEndian.Uint32(data[4:8])
	var agentIP net.IP
	var seqOffset int
	if addrType == 1 {
		agentIP = net.IP(data[8:12])
		seqOffset = 16
	} else {
		return 0, 0, nil, 0, errors.New("unsupported agent address type")
	}

	sequence := binary.BigEndian.Uint32(data[seqOffset : seqOffset+4])
	sampleCount := binary.BigEndian.Uint32(data[seqOffset+8 : seqOffset+12])
	_ = log.Printf // keep log import used

	return version, sequence, agentIP, sampleCount, nil
}
