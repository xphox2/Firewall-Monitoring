package syslog

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fortiGate-Mon/internal/database"
	"fortiGate-Mon/internal/models"
)

const (
	MaxMessageSize = 64 * 1024
)

type Config struct {
	ListenAddr string
	Port       int
	UseTLS     bool
	CertFile   string
	KeyFile    string
}

type SyslogReceiver struct {
	Config   *Config
	DB       *database.Database
	listener net.Listener
	running  atomic.Bool
	stopCh   chan struct{}
}

func NewSyslogReceiver(cfg *Config, db *database.Database) *SyslogReceiver {
	return &SyslogReceiver{
		Config: cfg,
		DB:     db,
		stopCh: make(chan struct{}),
	}
}

func (s *SyslogReceiver) Start() error {
	if s.running.Load() {
		return errors.New("syslog receiver already running")
	}

	addr := fmt.Sprintf("%s:%d", s.Config.ListenAddr, s.Config.Port)

	var err error
	if s.Config.UseTLS {
		cert, err := tls.LoadX509KeyPair(s.Config.CertFile, s.Config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificates: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		s.listener, err = tls.Listen("tcp", addr, tlsConfig)
	} else {
		s.listener, err = net.Listen("tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.running.Store(true)
	go s.acceptLoop()

	log.Printf("Syslog receiver started on %s (TLS: %v)", addr, s.Config.UseTLS)
	return nil
}

func (s *SyslogReceiver) Stop() error {
	if !s.running.Load() {
		return nil
	}

	s.running.Store(false)
	close(s.stopCh)

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SyslogReceiver) acceptLoop() {
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running.Load() {
				log.Printf("Error accepting syslog connection: %v", err)
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SyslogReceiver) handleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, MaxMessageSize)
	var messageBuf bytes.Buffer

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}

		messageBuf.Write(buf[:n])

		for {
			data := messageBuf.Bytes()
			idx := bytes.IndexByte(data, '\n')
			if idx == -1 {
				if messageBuf.Len() >= MaxMessageSize {
					messageBuf.Reset()
					break
				}
				break
			}

			line := data[:idx]
			messageBuf.Reset()
			messageBuf.Write(data[idx+1:])

			if len(line) == 0 {
				continue
			}

			msg, err := ParseRFC5424(line)
			if err != nil {
				log.Printf("Failed to parse syslog message: %v", err)
				continue
			}

			if msg != nil {
				msg.SourceIP = conn.RemoteAddr().String()
				if idx := strings.LastIndex(msg.SourceIP, ":"); idx != -1 {
					msg.SourceIP = msg.SourceIP[:idx]
				}

				if err := s.DB.SaveSyslogMessage(msg); err != nil {
					log.Printf("Failed to save syslog message: %v", err)
				}
			}
		}
	}
}

func ParseRFC5424(data []byte) (*models.SyslogMessage, error) {
	if len(data) == 0 {
		return nil, nil
	}

	msg := &models.SyslogMessage{
		Timestamp: time.Now(),
	}

	parts := bytes.SplitN(data, []byte(" "), 11)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid syslog format: too few parts")
	}

	priority, err := ParsePriority(parts[0][1])
	if err != nil {
		return nil, err
	}
	msg.Priority = priority.facility*8 + priority.severity
	msg.Facility = priority.facility
	msg.Severity = priority.severity

	version := 1
	if len(parts) > 1 && len(parts[1]) > 0 {
		if v := bytesToInt(parts[1]); v > 0 {
			version = v
		}
	}

	if len(parts) > 2 {
		ts, err := ParseTimestamp(version, string(parts[2]))
		if err != nil {
			log.Printf("Failed to parse timestamp: %v", err)
			msg.Timestamp = time.Now()
		} else {
			msg.Timestamp = ts
		}
	}

	if len(parts) > 3 {
		msg.Hostname = string(parts[3])
	}

	if len(parts) > 4 {
		msg.AppName = string(parts[4])
	}

	if len(parts) > 5 {
		msg.ProcessID = string(parts[5])
	}

	if len(parts) > 6 {
		msg.MessageID = string(parts[6])
	}

	if len(parts) > 7 {
		structuredData := string(parts[7])
		if structuredData != "-" {
			msg.StructuredData = structuredData
			msg.FortiGateID = extractFortiGateID(msg.Hostname, structuredData)
		}
	}

	if len(parts) > 8 {
		msg.Message = string(bytes.Join(parts[8:], []byte(" ")))
	}

	return msg, nil
}

type priorityResult struct {
	facility int
	severity int
}

func ParsePriority(b byte) (priorityResult, error) {
	if b < '0' || b > '9' {
		return priorityResult{}, fmt.Errorf("invalid priority byte: %c", b)
	}
	val := int(b - '0')
	if val > 191 {
		return priorityResult{}, fmt.Errorf("priority value out of range: %d", val)
	}
	return priorityResult{
		facility: val / 8,
		severity: val % 8,
	}, nil
}

func ParseTimestamp(version int, ts string) (time.Time, error) {
	ts = strings.TrimSpace(ts)
	if ts == "-" || ts == "" {
		return time.Now(), nil
	}

	formats := []string{
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"Jan  2 15:04:05",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t, nil
		}
	}

	return time.Now(), fmt.Errorf("failed to parse timestamp: %s", ts)
}

func extractFortiGateID(hostname, structuredData string) uint {
	if hostname != "" && hostname != "-" {
		hostname = strings.ToLower(hostname)
		if strings.HasPrefix(hostname, "fg") || strings.HasPrefix(hostname, "fgt") {
			parts := strings.FieldsFunc(hostname, func(r rune) bool {
				return r == '-' || r == '_' || r == '.'
			})
			for _, part := range parts {
				if len(part) >= 4 {
					var numStr string
					for _, c := range part {
						if c >= '0' && c <= '9' {
							numStr += string(c)
						}
					}
					if numStr != "" {
						if id := parseFortiGateID(numStr); id > 0 {
							return id
						}
					}
				}
			}
		}
	}

	if structuredData != "" && structuredData != "-" {
		var sdData map[string]map[string]string
		if err := json.Unmarshal([]byte(structuredData), &sdData); err == nil {
			for sdID, params := range sdData {
				if strings.Contains(strings.ToLower(sdID), "fortigate") || strings.Contains(strings.ToLower(sdID), "fgt") {
					if id, ok := params["device-id"]; ok {
						if fgID := parseFortiGateID(id); fgID > 0 {
							return fgID
						}
					}
				}
			}
		}

		re := regexp.MustCompile(`\[(\d+)\]`)
		matches := re.FindStringSubmatch(structuredData)
		if len(matches) > 1 {
			if id := parseFortiGateID(matches[1]); id > 0 {
				return id
			}
		}
	}

	return 0
}

func parseFortiGateID(idStr string) uint {
	idStr = strings.TrimPrefix(idStr, "0")
	if idStr == "" {
		return 0
	}
	var id uint
	for _, c := range idStr {
		if c >= '0' && c <= '9' {
			id = id*10 + uint(c-'0')
		}
	}
	return id
}

func bytesToInt(b []byte) int {
	var val int
	for _, c := range b {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
		}
	}
	return val
}

type UDPSyslogReceiver struct {
	Config  *Config
	DB      *database.Database
	conn    *net.UDPConn
	running atomic.Bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

func NewUDPSyslogReceiver(cfg *Config, db *database.Database) *UDPSyslogReceiver {
	return &UDPSyslogReceiver{
		Config: cfg,
		DB:     db,
		stopCh: make(chan struct{}),
	}
}

func (u *UDPSyslogReceiver) Start() error {
	if u.running.Load() {
		return errors.New("UDP syslog receiver already running")
	}

	addr := fmt.Sprintf("%s:%d", u.Config.ListenAddr, u.Config.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	u.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", addr, err)
	}

	u.running.Store(true)
	u.wg.Add(1)
	go u.readLoop()

	log.Printf("UDP syslog receiver started on %s", addr)
	return nil
}

func (u *UDPSyslogReceiver) Stop() error {
	if !u.running.Load() {
		return nil
	}

	u.running.Load()
	close(u.stopCh)

	if u.conn != nil {
		u.conn.Close()
	}

	u.wg.Wait()
	return nil
}

func (u *UDPSyslogReceiver) readLoop() {
	defer u.wg.Done()

	buf := make([]byte, MaxMessageSize)
	for u.running.Load() {
		u.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if u.running.Load() {
				log.Printf("Error reading UDP syslog: %v", err)
			}
			continue
		}

		data := buf[:n]
		if len(data) == 0 {
			continue
		}

		msg, err := ParseRFC5424(data)
		if err != nil {
			log.Printf("Failed to parse UDP syslog message from %s: %v", clientAddr, err)
			continue
		}

		if msg != nil {
			msg.SourceIP = clientAddr.IP.String()
			if err := u.DB.SaveSyslogMessage(msg); err != nil {
				log.Printf("Failed to save UDP syslog message: %v", err)
			}
		}
	}
}

type SyslogServer struct {
	TCP *SyslogReceiver
	UDP *UDPSyslogReceiver
}

func NewSyslogServer(cfg *Config, db *database.Database) *SyslogServer {
	return &SyslogServer{
		TCP: NewSyslogReceiver(cfg, db),
		UDP: NewUDPSyslogReceiver(cfg, db),
	}
}

func (s *SyslogServer) Start() error {
	var errs []error

	if err := s.TCP.Start(); err != nil {
		errs = append(errs, fmt.Errorf("TCP: %w", err))
	}

	if err := s.UDP.Start(); err != nil {
		errs = append(errs, fmt.Errorf("UDP: %w", err))
	}

	if len(errs) > 0 {
		s.TCP.Stop()
		s.UDP.Stop()
		return errors.Join(errs...)
	}

	return nil
}

func (s *SyslogServer) Stop() error {
	var errs []error

	if err := s.TCP.Stop(); err != nil {
		errs = append(errs, err)
	}

	if err := s.UDP.Stop(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
