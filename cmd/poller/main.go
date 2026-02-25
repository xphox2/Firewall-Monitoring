package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fortiGate-Mon/internal/alerts"
	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"
	"fortiGate-Mon/internal/notifier"
	"fortiGate-Mon/internal/snmp"
	"fortiGate-Mon/internal/uptime"
)

type Poller struct {
	config       *config.Config
	snmpClient   *snmp.SNMPClient
	alertManager *alerts.AlertManager
	uptimeTrack  *uptime.UptimeTracker
	stopChan     chan struct{}
}

func NewPoller(cfg *config.Config) *Poller {
	notif := notifier.NewNotifier(cfg)
	alertMgr := alerts.NewAlertManager(cfg, notif)

	return &Poller{
		config:       cfg,
		alertManager: alertMgr,
		uptimeTrack:  uptime.NewUptimeTracker(cfg),
		stopChan:     make(chan struct{}),
	}
}

func (p *Poller) Connect() error {
	client, err := snmp.NewSNMPClient(p.config)
	if err != nil {
		return err
	}
	p.snmpClient = client
	return nil
}

func (p *Poller) Start() error {
	if p.config.SNMP.PollInterval < 30*time.Second {
		p.config.SNMP.PollInterval = 30 * time.Second
	}

	log.Printf("Starting SNMP poller with interval: %v", p.config.SNMP.PollInterval)

	ticker := time.NewTicker(p.config.SNMP.PollInterval)
	defer ticker.Stop()

	p.poll()

	for {
		select {
		case <-ticker.C:
			p.poll()
		case <-p.stopChan:
			log.Println("Poller stopped")
			return nil
		}
	}
}

func (p *Poller) poll() {
	if p.snmpClient == nil {
		log.Println("SNMP client not connected")
		return
	}

	status, err := p.snmpClient.GetSystemStatus()
	if err != nil {
		log.Printf("Error polling system status: %v", err)
		return
	}

	log.Printf("Polled - CPU: %.1f%%, Memory: %.1f%%, Sessions: %d",
		status.CPUUsage, status.MemoryUsage, status.SessionCount)

	if err := p.alertManager.CheckSystemStatus(status); err != nil {
		log.Printf("Error checking alerts: %v", err)
	}

	interfaces, err := p.snmpClient.GetInterfaceStats()
	if err != nil {
		log.Printf("Error polling interface stats: %v", err)
	} else {
		if err := p.alertManager.CheckInterfaceStatus(interfaces); err != nil {
			log.Printf("Error checking interface alerts: %v", err)
		}
	}

	p.uptimeTrack.RecordUptime(status.Uptime)
}

func (p *Poller) Stop() error {
	close(p.stopChan)
	if p.snmpClient != nil {
		return p.snmpClient.Close()
	}
	return nil
}

func main() {
	cfg := config.Load()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting FortiGate SNMP Poller...")

	poller := NewPoller(cfg)

	if err := poller.Connect(); err != nil {
		log.Printf("Failed to connect to SNMP: %v", err)
		os.Exit(1)
	}
	defer poller.Stop()

	go func() {
		if err := poller.Start(); err != nil {
			log.Printf("Poller error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down poller...")
	poller.Stop()
	log.Println("Poller exited")
}

var _ models.SystemStatus
