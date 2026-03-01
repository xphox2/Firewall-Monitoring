package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/ping"
	"firewall-mon/internal/relay"
	"firewall-mon/internal/sflow"
	"firewall-mon/internal/snmp"
	"firewall-mon/internal/syslog"
)

type ProbeConfig struct {
	Name            string
	SiteID          uint
	RegistrationKey string
	ServerURL       string
	ListenTrap      string
	ListenSyslog    string
	ListenSFlow     string
	TLSEnabled      bool
	TLSCert         string
	TLSKey          string
	CACert          string
	SyncInterval    time.Duration
}

func LoadProbeConfig() *ProbeConfig {
	cfg := &ProbeConfig{
		ServerURL:    getEnv("PROBE_SERVER_URL", "https://stats.technicallabs.org"),
		ListenTrap:   getEnv("PROBE_LISTEN_TRAP", "0.0.0.0:162"),
		ListenSyslog: getEnv("PROBE_LISTEN_SYSLOG", "0.0.0.0:514"),
		ListenSFlow:  getEnv("PROBE_LISTEN_SFLOW", "0.0.0.0:6343"),
	}

	cfg.Name = os.Getenv("PROBE_NAME")
	cfg.SiteID = parseUintEnv("PROBE_SITE_ID")
	cfg.RegistrationKey = os.Getenv("PROBE_REGISTRATION_KEY")
	cfg.TLSEnabled = parseBoolEnv("PROBE_TLS_ENABLED")
	cfg.TLSCert = os.Getenv("PROBE_TLS_CERT")
	cfg.TLSKey = os.Getenv("PROBE_TLS_KEY")
	cfg.CACert = os.Getenv("PROBE_CA_CERT")
	cfg.SyncInterval = parseDurationEnv("PROBE_SYNC_INTERVAL", 30*time.Second)

	if cfg.Name == "" {
		log.Fatal("PROBE_NAME is required")
	}
	if cfg.SiteID == 0 {
		log.Fatal("PROBE_SITE_ID is required")
	}
	if cfg.RegistrationKey == "" {
		log.Fatal("PROBE_REGISTRATION_KEY is required")
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseUintEnv(key string) uint {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint(parsed)
		}
	}
	return 0
}

func parseBoolEnv(key string) bool {
	if value := os.Getenv(key); value != "" {
		return value == "1" || value == "true" || value == "yes"
	}
	return false
}

func parseDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

type Probe struct {
	Config          *ProbeConfig
	RelayClient     *relay.RelayClient
	TrapReceiver    *snmp.TrapReceiver
	SyslogTCPServer *syslog.SyslogReceiver
	SyslogUDPServer *syslog.UDPSyslogReceiver
	SFlowReceiver   *sflow.SFlowReceiver
	PingCollector   *ping.PingCollector
	stopChan        chan struct{}
}

func NewProbe(cfg *ProbeConfig) *Probe {
	relayConfig := relay.RelayConfig{
		ServerURL:       cfg.ServerURL,
		RegistrationKey: cfg.RegistrationKey,
		ProbeName:       cfg.Name,
		SiteID:          cfg.SiteID,
		TLSCertFile:     cfg.TLSCert,
		TLSKeyFile:      cfg.TLSKey,
		CACertFile:      cfg.CACert,
		SyncInterval:    cfg.SyncInterval,
	}

	return &Probe{
		Config:      cfg,
		stopChan:    make(chan struct{}),
		RelayClient: relay.NewRelayClient(relayConfig),
	}
}

func (p *Probe) Start() error {
	fmt.Println("========================================")
	fmt.Println("  Firewall Monitor Probe Starting")
	fmt.Println("========================================")
	fmt.Printf("  Probe Name:      %s\n", p.Config.Name)
	fmt.Printf("  Site ID:         %d\n", p.Config.SiteID)
	fmt.Printf("  Server URL:      %s\n", p.Config.ServerURL)
	fmt.Printf("  Sync Interval:   %v\n", p.Config.SyncInterval)
	fmt.Println("========================================")
	fmt.Println()

	fmt.Println("[1/4] Registering with central server...")
	if err := p.RelayClient.Register(); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	fmt.Printf("  -> Probe registered successfully (ID: %d)\n", p.RelayClient.GetProbeID())
	fmt.Println()

	fmt.Println("[2/4] Starting SNMP Trap listener...")
	snmpConfig := &config.Config{
		SNMP: config.SNMPConfig{
			TrapListenAddr: p.Config.ListenTrap,
			TrapCommunity:  getEnv("SNMP_TRAP_COMMUNITY", "public"),
		},
	}
	trapReceiver, err := snmp.NewTrapReceiver(snmpConfig)
	if err != nil {
		return fmt.Errorf("failed to create trap receiver: %w", err)
	}
	p.TrapReceiver = trapReceiver

	trapHandler := func(trap *models.TrapEvent) {
		relayTrap := relay.ConvertModelTrapEvent(trap)
		if err := p.RelayClient.SendTrap(relayTrap); err != nil {
			log.Printf("Failed to send trap: %v", err)
		}
	}

	if err := trapReceiver.Start(trapHandler); err != nil {
		return fmt.Errorf("failed to start trap receiver: %w", err)
	}
	fmt.Printf("  -> Listening on %s\n", p.Config.ListenTrap)
	fmt.Println()

	fmt.Println("[3/4] Starting Syslog listener...")
	syslogCfg := &syslog.Config{
		ListenAddr: "0.0.0.0",
		Port:       514,
		UseTLS:     p.Config.TLSEnabled,
		CertFile:   p.Config.TLSCert,
		KeyFile:    p.Config.TLSKey,
	}

	p.SyslogTCPServer = syslog.NewSyslogReceiver(syslogCfg, nil)
	p.SyslogUDPServer = syslog.NewUDPSyslogReceiver(syslogCfg, nil)

	if err := p.SyslogTCPServer.Start(); err != nil {
		log.Printf("Warning: TCP syslog server failed to start: %v", err)
	} else {
		fmt.Printf("  -> TCP listening on 0.0.0.0:514\n")
	}

	if err := p.SyslogUDPServer.Start(); err != nil {
		log.Printf("Warning: UDP syslog server failed to start: %v", err)
	} else {
		fmt.Printf("  -> UDP listening on 0.0.0.0:514\n")
	}
	fmt.Println()

	fmt.Println("[4/4] Starting sFlow listener...")
	parts := splitHostPort(p.Config.ListenSFlow)
	port := 6343
	if len(parts) > 1 {
		if parsedPort, err := strconv.Atoi(parts[1]); err == nil {
			port = parsedPort
		}
	}
	sflowReceiver := sflow.NewSFlowReceiver(parts[0], port)
	p.SFlowReceiver = sflowReceiver

	if err := sflowReceiver.Start(); err != nil {
		return fmt.Errorf("failed to start sFlow receiver: %w", err)
	}
	fmt.Printf("  -> Listening on %s\n", p.Config.ListenSFlow)
	fmt.Println()

	if err := p.RelayClient.Start(); err != nil {
		return fmt.Errorf("failed to start relay client: %w", err)
	}

	fmt.Println("========================================")
	fmt.Println("  Probe is running")
	fmt.Println("========================================")
	fmt.Println()

	go p.startHeartbeat()
	go p.startSNMPPolling()

	return nil
}

func (p *Probe) startHeartbeat() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			if err := p.RelayClient.Heartbeat(); err != nil {
				log.Printf("Heartbeat failed: %v", err)
			}
		}
	}
}

func (p *Probe) startSNMPPolling() {
	// Fetch device list every 5 minutes, poll each device every 60s
	fetchTicker := time.NewTicker(5 * time.Minute)
	defer fetchTicker.Stop()

	var devices []relay.DeviceInfo

	// Initial fetch
	if fetched, err := p.RelayClient.FetchDevices(); err != nil {
		log.Printf("Initial device fetch failed: %v", err)
	} else {
		devices = fetched
		log.Printf("Fetched %d assigned devices for SNMP polling", len(devices))
	}

	pollTicker := time.NewTicker(60 * time.Second)
	defer pollTicker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-fetchTicker.C:
			if fetched, err := p.RelayClient.FetchDevices(); err != nil {
				log.Printf("Device fetch failed: %v", err)
			} else {
				devices = fetched
				log.Printf("Refreshed device list: %d devices", len(devices))
			}
		case <-pollTicker.C:
			for _, dev := range devices {
				if !dev.Enabled {
					continue
				}
				go p.pollDevice(dev)
			}
		}
	}
}

func (p *Probe) pollDevice(dev relay.DeviceInfo) {
	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			SNMPHost: dev.IPAddress,
			SNMPPort: dev.SNMPPort,
			Community:     dev.SNMPCommunity,
			Version:       dev.SNMPVersion,
			Timeout:       10 * time.Second,
			Retries:       1,
		},
	}

	client, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("SNMP connect failed for %s (%s): %v", dev.Name, dev.IPAddress, err)
		return
	}
	defer client.Close()

	status, err := client.GetSystemStatus()
	if err != nil {
		log.Printf("SNMP poll failed for %s (%s): %v", dev.Name, dev.IPAddress, err)
		return
	}

	status.DeviceID = dev.ID
	status.Timestamp = time.Now()
	if err := p.RelayClient.SendSystemStatuses([]models.SystemStatus{*status}); err != nil {
		log.Printf("Failed to send system status for %s: %v", dev.Name, err)
	}

	ifaces, err := client.GetInterfaceStats()
	if err != nil {
		log.Printf("SNMP interface poll failed for %s: %v", dev.Name, err)
		return
	}

	now := time.Now()
	for i := range ifaces {
		ifaces[i].DeviceID = dev.ID
		ifaces[i].Timestamp = now
	}
	if err := p.RelayClient.SendInterfaceStats(ifaces); err != nil {
		log.Printf("Failed to send interface stats for %s: %v", dev.Name, err)
	}
}

func (p *Probe) Stop() error {
	fmt.Println()
	fmt.Println("Shutting down probe...")

	close(p.stopChan)

	if p.TrapReceiver != nil {
		p.TrapReceiver.Stop()
	}

	if p.SyslogTCPServer != nil {
		p.SyslogTCPServer.Stop()
	}

	if p.SyslogUDPServer != nil {
		p.SyslogUDPServer.Stop()
	}

	if p.SFlowReceiver != nil {
		p.SFlowReceiver.Stop()
	}

	if p.PingCollector != nil {
		p.PingCollector.Stop()
	}

	if p.RelayClient != nil {
		p.RelayClient.Stop()
	}

	fmt.Println("Probe stopped")
	return nil
}

func splitHostPort(addr string) []string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return []string{addr[:i], addr[i+1:]}
		}
	}
	return []string{addr}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg := LoadProbeConfig()

	probe := NewProbe(cfg)

	if err := probe.Start(); err != nil {
		log.Fatalf("Failed to start probe: %v", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	probe.Stop()
}
