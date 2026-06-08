package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
	"firewall-mon/internal/relay"
	"firewall-mon/internal/sflow"
	"firewall-mon/internal/snmp"
	"firewall-mon/internal/syslog"
	"firewall-mon/internal/tracing"
)

type ProbeConfig struct {
	Name                 string
	SiteID               uint
	RegistrationKey      string
	ServerURL            string
	ListenTrap           string
	ListenSyslog         string
	ListenSFlow          string
	TLSEnabled           bool
	TLSCert              string
	TLSKey               string
	CACert               string
	SyncInterval         time.Duration
	SyslogAllowedSources string
	SFlowAllowedSources  string
}

func LoadProbeConfig() *ProbeConfig {
	cfg := &ProbeConfig{
		ServerURL:    getEnv("PROBE_SERVER_URL", ""),
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
	cfg.SyslogAllowedSources = getEnv("SYSLOG_ALLOWED_SOURCES", "")
	cfg.SFlowAllowedSources = getEnv("SFLOW_ALLOWED_SOURCES", "")

	if cfg.Name == "" {
		log.Fatal("PROBE_NAME is required")
	}
	if cfg.SiteID == 0 {
		log.Fatal("PROBE_SITE_ID is required")
	}
	if cfg.RegistrationKey == "" {
		log.Fatal("PROBE_REGISTRATION_KEY is required")
	}
	if cfg.ServerURL == "" {
		log.Fatal("PROBE_SERVER_URL is required")
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

// parseCSVList splits a comma-separated string into a slice, trimming whitespace.
func parseCSVList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

type Probe struct {
	Config          *ProbeConfig
	RelayClient     *relay.RelayClient
	TrapReceiver    *snmp.TrapReceiver
	SyslogTCPServer *syslog.SyslogReceiver
	SyslogUDPServer *syslog.UDPSyslogReceiver
	SFlowReceiver   *sflow.SFlowReceiver
	stopChan        chan struct{}

	// AUDIT-087: device polls run as `go p.pollDevice(...)`. Without a
	// context they were untracked — after Stop() closed stopChan, in-flight
	// polls kept running unbounded. ctx is cancelled on Stop so polls bail
	// at their next checkpoint, and pollWG lets cleanup() wait (bounded) for
	// in-flight polls to drain before tearing down the relay client they
	// write through.
	ctx    context.Context
	cancel context.CancelFunc
	pollWG sync.WaitGroup
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

	ctx, cancel := context.WithCancel(context.Background())
	return &Probe{
		Config:      cfg,
		stopChan:    make(chan struct{}),
		RelayClient: relay.NewRelayClient(relayConfig),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (p *Probe) Start() error {
	// AUDIT-159: banner / status output uses log.* instead of fmt.*
	// so the probe's stdout matches the rest of the codebase (the
	// rest of this file already uses log.Printf for error paths).
	// The "log" import was already present in this file; we just
	// swap the call sites. fmt.Errorf in the error returns below
	// is left alone — wrapping errors with %w is a different concern
	// from output formatting.
	log.Println("========================================")
	log.Println("  Firewall Monitor Probe Starting")
	log.Println("========================================")
	log.Printf("  Probe Name:      %s", p.Config.Name)
	log.Printf("  Site ID:         %d", p.Config.SiteID)
	log.Printf("  Server URL:      %s", p.Config.ServerURL)
	log.Printf("  Sync Interval:   %v", p.Config.SyncInterval)
	log.Println("========================================")
	log.Println()

	log.Println("[1/4] Registering with central server...")
	if err := p.RelayClient.Register(); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	log.Printf("  -> Probe registered successfully (ID: %d)", p.RelayClient.GetProbeID())
	log.Println()

	log.Println("[2/4] Starting SNMP Trap listener...")
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
	log.Printf("  -> Listening on %s", p.Config.ListenTrap)
	log.Println()

	log.Println("[3/4] Starting Syslog listener...")
	syslogCfg := &syslog.Config{
		ListenAddr:       "0.0.0.0",
		Port:             514,
		UseTLS:           p.Config.TLSEnabled,
		CertFile:         p.Config.TLSCert,
		KeyFile:          p.Config.TLSKey,
		AllowedSourceIPs: parseCSVList(p.Config.SyslogAllowedSources),
	}

	p.SyslogTCPServer = syslog.NewSyslogReceiver(syslogCfg, nil)
	p.SyslogUDPServer = syslog.NewUDPSyslogReceiver(syslogCfg, nil)

	p.SyslogTCPServer.SetHandler(func(msg *models.SyslogMessage) {
		relayMsg := relay.ConvertModelSyslogMessage(msg)
		if err := p.RelayClient.SendSyslogMessage(relayMsg); err != nil {
			log.Printf("Failed to relay TCP syslog: %v", err)
		}
	})
	p.SyslogUDPServer.SetHandler(func(msg *models.SyslogMessage) {
		relayMsg := relay.ConvertModelSyslogMessage(msg)
		if err := p.RelayClient.SendSyslogMessage(relayMsg); err != nil {
			log.Printf("Failed to relay UDP syslog: %v", err)
		}
	})

	if err := p.SyslogTCPServer.Start(); err != nil {
		log.Printf("Warning: TCP syslog server failed to start: %v", err)
	} else {
		log.Printf("  -> TCP listening on 0.0.0.0:514")
	}

	if err := p.SyslogUDPServer.Start(); err != nil {
		log.Printf("Warning: UDP syslog server failed to start: %v", err)
	} else {
		log.Printf("  -> UDP listening on 0.0.0.0:514")
	}
	log.Println()

	log.Println("[4/4] Starting sFlow listener...")
	parts := splitHostPort(p.Config.ListenSFlow)
	port := 6343
	if len(parts) > 1 {
		if parsedPort, err := strconv.Atoi(parts[1]); err == nil {
			port = parsedPort
		}
	}
	sflowReceiver := sflow.NewSFlowReceiver(parts[0], port, parseCSVList(p.Config.SFlowAllowedSources))
	p.SFlowReceiver = sflowReceiver

	// Wire decoded sFlow samples to the relay pipeline
	sflowReceiver.SetFlowHandler(func(f *sflow.ParsedFlow) {
		if f == nil || f.SrcAddr == "" || f.DstAddr == "" {
			return
		}
		p.RelayClient.SendFlowSample(&relay.FlowSample{
			Timestamp:      time.Now(),
			SamplerAddress: f.AgentIP,
			SamplingRate:   f.SamplingRate,
			SrcAddr:        f.SrcAddr,
			DstAddr:        f.DstAddr,
			SrcPort:        f.SrcPort,
			DstPort:        f.DstPort,
			Protocol:       f.Protocol,
			Bytes:          f.Bytes,
			Packets:        f.Packets,
			InputIfIndex:   f.InputIfIndex,
			OutputIfIndex:  f.OutputIfIndex,
		})
	})

	if err := sflowReceiver.Start(); err != nil {
		return fmt.Errorf("failed to start sFlow receiver: %w", err)
	}
	log.Printf("  -> Listening on %s", p.Config.ListenSFlow)
	log.Println()

	if err := p.RelayClient.Start(); err != nil {
		p.cleanup()
		return fmt.Errorf("failed to start relay client: %w", err)
	}

	go p.startHeartbeat()
	go p.startSNMPPolling()

	log.Println("========================================")
	log.Println("  Probe is running")
	log.Println("========================================")
	log.Println()

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
				// AUDIT-087: track each poll so cleanup() can wait for
				// in-flight polls, and pass the cancellable ctx so a poll
				// bails promptly once Stop() is called.
				p.pollWG.Add(1)
				go func(d relay.DeviceInfo) {
					defer p.pollWG.Done()
					p.pollDevice(p.ctx, d)
				}(dev)
			}
		}
	}
}

func (p *Probe) pollDevice(ctx context.Context, dev relay.DeviceInfo) {
	// AUDIT-087: bail before doing any work if shutdown already started.
	if ctx.Err() != nil {
		return
	}

	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			SNMPHost:   dev.IPAddress,
			SNMPPort:   dev.SNMPPort,
			Community:  dev.SNMPCommunity,
			Version:    dev.SNMPVersion,
			V3Username: dev.SNMPV3Username,
			V3AuthType: dev.SNMPV3AuthType,
			V3AuthPass: dev.SNMPV3AuthPass,
			V3PrivType: dev.SNMPV3PrivType,
			V3PrivPass: dev.SNMPV3PrivPass,
			Timeout:    10 * time.Second,
			Retries:    1,
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

	// AUDIT-087: stop here if shutdown started during the system-status poll.
	if ctx.Err() != nil {
		return
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

	// AUDIT-087: stop here if shutdown started during the interface poll.
	if ctx.Err() != nil {
		return
	}

	// Collect VPN tunnel status (IPSec + dialup + SSL-VPN + GRE)
	vpnStatuses, sslvpnUsers, sslvpnTunnels, vpnErr := client.GetAllVPNTunnels()
	if vpnErr == nil && len(vpnStatuses) > 0 {
		for i := range vpnStatuses {
			vpnStatuses[i].DeviceID = dev.ID
			vpnStatuses[i].Timestamp = now
		}
		if err := p.RelayClient.SendVPNStatuses(vpnStatuses); err != nil {
			log.Printf("Failed to send VPN statuses for %s: %v", dev.Name, err)
		}
		if sslvpnUsers > 0 || sslvpnTunnels > 0 {
			log.Printf("Device %s: SSL-VPN: %d users, %d sessions", dev.Name, sslvpnUsers, sslvpnTunnels)
		}
	}
}

func (p *Probe) cleanup() {
	close(p.stopChan)

	// AUDIT-087: signal in-flight device polls to stop, then wait (bounded)
	// for them to drain before tearing down the relay client they write
	// through. The 5s ceiling guarantees shutdown can't hang on a poll stuck
	// in a slow SNMP timeout; a poll that outlives it only issues a couple of
	// harmless HTTP POSTs (the relay Send* methods are stateless).
	if p.cancel != nil {
		p.cancel()
	}
	pollsDrained := make(chan struct{})
	go func() {
		p.pollWG.Wait()
		close(pollsDrained)
	}()
	select {
	case <-pollsDrained:
	case <-time.After(5 * time.Second):
		log.Println("Timed out waiting for in-flight device polls to finish; proceeding with shutdown")
	}

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

	if p.RelayClient != nil {
		p.RelayClient.Stop()
	}
}

func (p *Probe) Stop() error {
	log.Println()
	log.Println("Shutting down probe...")

	p.cleanup()

	log.Println("Probe stopped")
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

	// AUDIT-150: OpenTelemetry tracing for the probe side of the probe→api hop.
	// OFF unless OTEL_TRACES_ENABLED=true; when on, the relay's HTTP client emits
	// client spans + injects W3C trace context so the call connects to the api's
	// server span. Shutdown flushes buffered spans on exit.
	// This repo's cmd/probe carries no release version (the versioned production
	// probe is the separate Firewall-Collector repo), so the span resource uses "dev".
	traceShutdown, err := tracing.Init(context.Background(), "fwmon-probe", "dev")
	if err != nil {
		log.Printf("Tracing init failed (continuing without tracing): %v", err)
	}
	defer func() { _ = traceShutdown(context.Background()) }()

	probe := NewProbe(cfg)

	if err := probe.Start(); err != nil {
		log.Fatalf("Failed to start probe: %v", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	probe.Stop()
}
