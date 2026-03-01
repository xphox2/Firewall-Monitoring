package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/database"
	"fortiGate-Mon/internal/models"
	"fortiGate-Mon/internal/snmp"
)

type Poller struct {
	cfg      *config.Config
	db       *database.Database
	stopChan chan struct{}
}

func NewPoller(cfg *config.Config, db *database.Database) *Poller {
	return &Poller{
		cfg:      cfg,
		db:       db,
		stopChan: make(chan struct{}),
	}
}

func (p *Poller) Start() error {
	if p.cfg.SNMP.PollInterval < 30*time.Second {
		p.cfg.SNMP.PollInterval = 30 * time.Second
	}

	log.Printf("Starting SNMP poller with interval: %v", p.cfg.SNMP.PollInterval)

	// Poll immediately on startup
	p.pollAllDevices()

	ticker := time.NewTicker(p.cfg.SNMP.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.pollAllDevices()
		case <-p.stopChan:
			log.Println("Poller stopped")
			return nil
		}
	}
}

func (p *Poller) pollAllDevices() {
	if p.db == nil {
		log.Println("Database not connected, skipping poll")
		return
	}

	devices, err := p.db.GetAllFortiGates()
	if err != nil {
		log.Printf("Error getting devices: %v", err)
		return
	}

	if len(devices) == 0 {
		log.Println("No devices configured, skipping poll")
		return
	}

	log.Printf("Polling %d devices...", len(devices))

	for _, device := range devices {
		if !device.Enabled {
			continue
		}
		p.pollDevice(&device)
	}
}

func (p *Poller) pollDevice(device *models.FortiGate) {
	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			FortiGateHost: device.IPAddress,
			FortiGatePort: device.SNMPPort,
			Community:     device.SNMPCommunity,
			Version:       device.SNMPVersion,
			Timeout:       5 * time.Second,
			Retries:       2,
		},
	}

	client, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("Device %s (%s): failed to connect - %v", device.Name, device.IPAddress, err)
		p.updateDeviceStatus(device, "offline")
		return
	}
	defer client.Close()

	status, err := client.GetSystemStatus()
	if err != nil {
		log.Printf("Device %s (%s): poll error - %v", device.Name, device.IPAddress, err)
		p.updateDeviceStatus(device, "offline")
		return
	}

	log.Printf("Device %s (%s): CPU=%.1f%% Memory=%.1f%% Sessions=%d",
		device.Name, device.IPAddress, status.CPUUsage, status.MemoryUsage, status.SessionCount)

	// Save system status to database
	if p.db != nil {
		status.FortiGateID = device.ID
		status.Timestamp = time.Now()
		if err := p.db.SaveSystemStatus(status); err != nil {
			log.Printf("Device %s: failed to save status - %v", device.Name, err)
		}
	}

	// Save interface stats to database
	interfaces, err := client.GetInterfaceStats()
	if err == nil && len(interfaces) > 0 && p.db != nil {
		now := time.Now()
		for i := range interfaces {
			interfaces[i].FortiGateID = device.ID
			interfaces[i].Timestamp = now
		}
		if err := p.db.SaveInterfaceStats(interfaces); err != nil {
			log.Printf("Device %s: failed to save interface stats - %v", device.Name, err)
		}
	}

	p.updateDeviceStatus(device, "online")
}

func (p *Poller) updateDeviceStatus(device *models.FortiGate, status string) {
	device.Status = status
	device.LastPolled = time.Now()
	if p.db != nil {
		p.db.UpdateFortiGate(device)
	}
}

func (p *Poller) Stop() error {
	select {
	case <-p.stopChan:
		return nil
	default:
		close(p.stopChan)
	}
	return nil
}

func main() {
	cfg := config.Load()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting FortiGate SNMP Poller...")

	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Printf("Warning: Failed to connect to database: %v", err)
	} else {
		log.Println("Database connected")
		defer db.Close()
	}

	poller := NewPoller(cfg, db)

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
