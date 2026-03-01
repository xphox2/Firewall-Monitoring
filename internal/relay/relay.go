package relay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"firewall-mon/internal/models"
)

type RelayConfig struct {
	ServerURL       string
	RegistrationKey string
	ProbeName       string
	SiteID          uint
	TLSCertFile     string
	TLSKeyFile      string
	CACertFile      string
	SyncInterval    time.Duration
}

type RelayClient struct {
	Config      RelayConfig
	httpClient  *http.Client
	running     atomic.Bool
	approved    atomic.Bool
	mu          sync.Mutex
	trapQueue   []*TrapEvent
	pingQueue   []*PingResult
	syslogQueue []*SyslogMessage
	flowQueue   []*FlowSample
	syncTicker  *time.Ticker
	stopChan    chan struct{}
	probeID     uint
}

type TrapEvent struct {
	ID          uint      `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	DeviceID    uint      `json:"device_id"`
	ProbeID     uint      `json:"probe_id"`
	SourceIP    string    `json:"source_ip"`
	TrapOID     string    `json:"trap_oid"`
	TrapType    string    `json:"trap_type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
}

type PingResult struct {
	ID           uint      `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     uint      `json:"device_id"`
	ProbeID      uint      `json:"probe_id"`
	TargetIP     string    `json:"target_ip"`
	Success      bool      `json:"success"`
	Latency      float64   `json:"latency"`
	PacketLoss   float64   `json:"packet_loss"`
	TTL          int       `json:"ttl"`
	ErrorMessage string    `json:"error_message"`
}

type SyslogMessage struct {
	ID             uint      `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	DeviceID       uint      `json:"device_id"`
	ProbeID        uint      `json:"probe_id"`
	Hostname       string    `json:"hostname"`
	AppName        string    `json:"app_name"`
	ProcessID      string    `json:"process_id"`
	MessageID      string    `json:"message_id"`
	StructuredData string    `json:"structured_data"`
	Message        string    `json:"message"`
	Priority       int       `json:"priority"`
	Facility       int       `json:"facility"`
	Severity       int       `json:"severity"`
	SourceIP       string    `json:"source_ip"`
}

type FlowSample struct {
	ID              uint      `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	DeviceID        uint      `json:"device_id"`
	ProbeID         uint      `json:"probe_id"`
	SamplerAddress  string    `json:"sampler_address"`
	SequenceNumber  uint32    `json:"sequence_number"`
	SamplingRate    uint32    `json:"sampling_rate"`
	SamplePool      uint32    `json:"sample_pool"`
	SampleAlgorithm uint8     `json:"sample_algorithm"`
	EngineID        uint8     `json:"engine_id"`
	EngineType      uint8     `json:"engine_type"`
	SrcAddr         string    `json:"src_addr"`
	DstAddr         string    `json:"dst_addr"`
	SrcPort         uint16    `json:"src_port"`
	DstPort         uint16    `json:"dst_port"`
	Protocol        uint8     `json:"protocol"`
	Bytes           uint64    `json:"bytes"`
	Packets         uint64    `json:"packets"`
	InputIfIndex    uint32    `json:"input_if_index"`
	OutputIfIndex   uint32    `json:"output_if_index"`
	SrcAS           uint32    `json:"src_as"`
	DstAS           uint32    `json:"dst_as"`
	SrcMask         uint8     `json:"src_mask"`
	DstMask         uint8     `json:"dst_mask"`
	TOS             uint8     `json:"tos"`
	TCPFlags        uint8     `json:"tcp_flags"`
}

type DataHandler interface {
	HandleTrap(trap *TrapEvent)
	HandlePingResult(result *PingResult)
	HandleSyslogMessage(msg *SyslogMessage)
	HandleFlowSample(sample *FlowSample)
}

type BaseDataHandler struct{}

func (h *BaseDataHandler) HandleTrap(trap *TrapEvent)             {}
func (h *BaseDataHandler) HandlePingResult(result *PingResult)    {}
func (h *BaseDataHandler) HandleSyslogMessage(msg *SyslogMessage) {}
func (h *BaseDataHandler) HandleFlowSample(sample *FlowSample)    {}

func NewRelayClient(config RelayConfig) *RelayClient {
	if config.ServerURL == "" {
		config.ServerURL = "https://stats.technicallabs.org"
	}
	if config.SyncInterval == 0 {
		config.SyncInterval = 30 * time.Second
	}

	client := &RelayClient{
		Config:   config,
		stopChan: make(chan struct{}),
	}

	client.httpClient = client.buildHTTPClient()

	return client
}

func (r *RelayClient) buildHTTPClient() *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
	}

	if r.Config.TLSCertFile != "" && r.Config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(r.Config.TLSCertFile, r.Config.TLSKeyFile)
		if err != nil {
			log.Printf("Warning: Failed to load client cert: %v", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	if r.Config.CACertFile != "" {
		caCert, err := os.ReadFile(r.Config.CACertFile)
		if err != nil {
			log.Printf("Warning: Failed to read CA cert: %v", err)
		} else {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caPool
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func (r *RelayClient) Start() error {
	if r.running.Load() {
		return fmt.Errorf("relay client already running")
	}

	if err := r.Register(); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if !r.approved.Load() {
		return fmt.Errorf("probe not approved by server")
	}

	r.running.Store(true)
	r.syncTicker = time.NewTicker(r.Config.SyncInterval)

	go r.syncLoop()
	go r.heartbeatLoop()

	log.Printf("Relay client started for probe %s (ID: %d)", r.Config.ProbeName, r.probeID)
	return nil
}

func (r *RelayClient) Stop() error {
	if !r.running.Load() {
		return fmt.Errorf("relay client not running")
	}

	r.running.Store(false)
	r.syncTicker.Stop()
	close(r.stopChan)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.flushQueues()

	log.Printf("Relay client stopped")
	return nil
}

func (r *RelayClient) Register() error {
	regReq := RegistrationRequest{
		RegistrationKey: r.Config.RegistrationKey,
		ProbeName:       r.Config.ProbeName,
		SiteID:          r.Config.SiteID,
	}

	jsonData, err := json.Marshal(regReq)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	url := r.Config.ServerURL + "/api/probes/register"
	resp, err := r.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("registration rejected with status: %d", resp.StatusCode)
	}

	var regResp RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	if !regResp.Approved {
		return fmt.Errorf("probe not approved: %s", regResp.Message)
	}

	r.probeID = regResp.ProbeID
	r.approved.Store(true)

	log.Printf("Probe registered successfully with ID: %d", r.probeID)
	return nil
}

func (r *RelayClient) Heartbeat() error {
	if !r.running.Load() {
		return fmt.Errorf("relay client not running")
	}

	hb := HeartbeatRequest{
		ProbeID: r.probeID,
		Status:  "online",
	}

	jsonData, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	url := r.Config.ServerURL + "/api/probes/" + fmt.Sprint(r.probeID) + "/heartbeat"
	resp, err := r.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		r.approved.Store(false)
		return fmt.Errorf("probe no longer approved")
	}

	return nil
}

func (r *RelayClient) SendTrap(trap *TrapEvent) error {
	if !r.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	r.mu.Lock()
	r.trapQueue = append(r.trapQueue, trap)
	r.mu.Unlock()

	return nil
}

func (r *RelayClient) SendPingResult(result *PingResult) error {
	if !r.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	r.mu.Lock()
	r.pingQueue = append(r.pingQueue, result)
	r.mu.Unlock()

	return nil
}

func (r *RelayClient) SendSyslogMessage(msg *SyslogMessage) error {
	if !r.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	r.mu.Lock()
	r.syslogQueue = append(r.syslogQueue, msg)
	r.mu.Unlock()

	return nil
}

func (r *RelayClient) SendFlowSample(sample *FlowSample) error {
	if !r.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	r.mu.Lock()
	r.flowQueue = append(r.flowQueue, sample)
	r.mu.Unlock()

	return nil
}

func (r *RelayClient) StartCollector(handlers ...DataHandler) {
	if len(handlers) == 0 {
		return
	}

	for _, handler := range handlers {
		go r.runCollectorHandler(handler)
	}
}

func (r *RelayClient) runCollectorHandler(handler DataHandler) {
	for {
		select {
		case <-r.stopChan:
			return
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (r *RelayClient) syncLoop() {
	for {
		select {
		case <-r.stopChan:
			return
		case <-r.syncTicker.C:
			r.syncData()
		}
	}
}

func (r *RelayClient) heartbeatLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopChan:
			return
		case <-ticker.C:
			if err := r.Heartbeat(); err != nil {
				log.Printf("Heartbeat error: %v", err)
			}
		}
	}
}

func (r *RelayClient) syncData() {
	r.mu.Lock()

	traps := make([]*TrapEvent, len(r.trapQueue))
	copy(traps, r.trapQueue)
	r.trapQueue = nil

	pings := make([]*PingResult, len(r.pingQueue))
	copy(pings, r.pingQueue)
	r.pingQueue = nil

	syslogs := make([]*SyslogMessage, len(r.syslogQueue))
	copy(syslogs, r.syslogQueue)
	r.syslogQueue = nil

	flows := make([]*FlowSample, len(r.flowQueue))
	copy(flows, r.flowQueue)
	r.flowQueue = nil

	r.mu.Unlock()

	if len(traps) > 0 {
		r.sendBatch("traps", traps)
	}
	if len(pings) > 0 {
		r.sendBatch("pings", pings)
	}
	if len(syslogs) > 0 {
		r.sendBatch("syslog", syslogs)
	}
	if len(flows) > 0 {
		r.sendBatch("flows", flows)
	}
}

func (r *RelayClient) sendBatch(endpoint string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal batch: %v", err)
		return
	}

	url := r.Config.ServerURL + "/api/probes/" + fmt.Sprint(r.probeID) + "/" + endpoint

	for retries := 0; retries < 3; retries++ {
		resp, err := r.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Failed to send %s batch (attempt %d): %v", endpoint, retries+1, err)
			time.Sleep(time.Duration(retries+1) * time.Second)
			continue
		}

		status := resp.StatusCode
		resp.Body.Close()

		if status >= 200 && status < 300 {
			log.Printf("Sent %d %s to server", countItems(data), endpoint)
			return
		}

		if status == 404 {
			r.approved.Store(false)
			log.Printf("Probe no longer approved")
			return
		}

		log.Printf("Failed to send %s batch: status %d", endpoint, status)
		time.Sleep(time.Duration(retries+1) * time.Second)
	}
}

func countItems(data interface{}) int {
	switch v := data.(type) {
	case []*TrapEvent:
		return len(v)
	case []*PingResult:
		return len(v)
	case []*SyslogMessage:
		return len(v)
	case []*FlowSample:
		return len(v)
	default:
		return 0
	}
}

func (r *RelayClient) flushQueues() {
	r.syncData()
}

type RegistrationRequest struct {
	RegistrationKey string `json:"registration_key"`
	ProbeName       string `json:"probe_name"`
	SiteID          uint   `json:"site_id"`
}

type RegistrationResponse struct {
	Approved bool   `json:"approved"`
	ProbeID  uint   `json:"probe_id"`
	Message  string `json:"message"`
}

type HeartbeatRequest struct {
	ProbeID uint   `json:"probe_id"`
	Status  string `json:"status"`
}

func ConvertModelTrapEvent(m *models.TrapEvent) *TrapEvent {
	return &TrapEvent{
		ID:          m.ID,
		Timestamp:   m.Timestamp,
		DeviceID:    m.DeviceID,
		SourceIP:    m.SourceIP,
		TrapOID:     m.TrapOID,
		TrapType:    m.TrapType,
		Severity:    m.Severity,
		Message:     m.Message,
	}
}

func ConvertModelPingResult(m *models.PingResult) *PingResult {
	return &PingResult{
		ID:           m.ID,
		Timestamp:    m.Timestamp,
		DeviceID:     m.DeviceID,
		ProbeID:      m.ProbeID,
		TargetIP:     m.TargetIP,
		Success:      m.Success,
		Latency:      m.Latency,
		PacketLoss:   m.PacketLoss,
		TTL:          m.TTL,
		ErrorMessage: m.ErrorMessage,
	}
}

func (r *RelayClient) GetProbeID() uint {
	return r.probeID
}

type DeviceInfo struct {
	ID            uint   `json:"id"`
	Name          string `json:"name"`
	IPAddress     string `json:"ip_address"`
	SNMPPort      int    `json:"snmp_port"`
	SNMPCommunity string `json:"snmp_community"`
	SNMPVersion   string `json:"snmp_version"`
	Enabled       bool   `json:"enabled"`
}

type DevicesResponse struct {
	Success bool         `json:"success"`
	Data    []DeviceInfo `json:"data"`
}

func (r *RelayClient) FetchDevices() ([]DeviceInfo, error) {
	if !r.approved.Load() {
		return nil, fmt.Errorf("probe not approved")
	}

	url := r.Config.ServerURL + "/api/probes/" + fmt.Sprint(r.probeID) + "/devices"
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch devices: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch devices returned status %d", resp.StatusCode)
	}

	var result DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode devices response: %w", err)
	}

	return result.Data, nil
}

func (r *RelayClient) SendSystemStatuses(statuses []models.SystemStatus) error {
	if !r.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	jsonData, err := json.Marshal(statuses)
	if err != nil {
		return fmt.Errorf("failed to marshal system statuses: %w", err)
	}

	url := r.Config.ServerURL + "/api/probes/" + fmt.Sprint(r.probeID) + "/system-status"
	resp, err := r.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send system statuses: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send system statuses returned status %d", resp.StatusCode)
}

func (r *RelayClient) SendInterfaceStats(stats []models.InterfaceStats) error {
	if !r.approved.Load() {
		return fmt.Errorf("probe not approved")
	}

	jsonData, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("failed to marshal interface stats: %w", err)
	}

	url := r.Config.ServerURL + "/api/probes/" + fmt.Sprint(r.probeID) + "/interface-stats"
	resp, err := r.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send interface stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("send interface stats returned status %d", resp.StatusCode)
}

func ConvertModelSyslogMessage(m *models.SyslogMessage) *SyslogMessage {
	return &SyslogMessage{
		Timestamp:      m.Timestamp,
		DeviceID:       m.DeviceID,
		ProbeID:        m.ProbeID,
		Hostname:       m.Hostname,
		AppName:        m.AppName,
		ProcessID:      m.ProcessID,
		MessageID:      m.MessageID,
		StructuredData: m.StructuredData,
		Message:        m.Message,
		Priority:       m.Priority,
		Facility:       m.Facility,
		Severity:       m.Severity,
		SourceIP:       m.SourceIP,
	}
}
