package sflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

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

type SFlowReceiver struct {
	ListenAddr string
	Port       int
	conn       *net.UDPConn
	stopChan   chan struct{}
	running    bool
}

func NewSFlowReceiver(listenAddr string, port int) *SFlowReceiver {
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}
	if port == 0 {
		port = 6343
	}
	return &SFlowReceiver{
		ListenAddr: listenAddr,
		Port:       port,
		stopChan:   make(chan struct{}),
	}
}

func (r *SFlowReceiver) Start() error {
	if r.running {
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

	r.running = true

	go r.readLoop()

	return nil
}

func (r *SFlowReceiver) Stop() error {
	if !r.running {
		return errors.New("sFlow receiver not running")
	}

	close(r.stopChan)
	r.running = false

	if r.conn != nil {
		return r.conn.Close()
	}

	return nil
}

func (r *SFlowReceiver) readLoop() {
	buf := make([]byte, 65536)
	for {
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
				return
			}

			if n > 0 {
				_ = r.ParseSFlowDatagram(buf[:n])
				_ = addr
			}
		}
	}
}

func (r *SFlowReceiver) ParseSFlowDatagram(data []byte) error {
	if len(data) < 24 {
		return errors.New("sFlow datagram too short")
	}

	version := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if version != 5 {
		return errors.New("unsupported sFlow version")
	}

	sequence := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])

	agentIP := net.IP(data[8:12])
	_ = agentIP

	sampleCount := uint32(data[16])<<24 | uint32(data[17])<<16 | uint32(data[18])<<8 | uint32(data[19])

	_ = sequence
	_ = sampleCount

	return nil
}

func ParseSFlowDatagram(data []byte) (uint32, uint32, net.IP, uint32, error) {
	if len(data) < 24 {
		return 0, 0, nil, 0, errors.New("sFlow datagram too short")
	}

	version := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if version != 5 {
		return 0, 0, nil, 0, errors.New("unsupported sFlow version")
	}

	sequence := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])

	agentIP := net.IP(data[8:12])

	sampleCount := uint32(data[16])<<24 | uint32(data[17])<<16 | uint32(data[18])<<8 | uint32(data[19])

	return version, sequence, agentIP, sampleCount, nil
}
