package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/snmp"
)

type Poller struct {
	cfg          *config.Config
	db           *database.Database
	alertManager *alerts.AlertManager
	stopChan     chan struct{}
}

func NewPoller(cfg *config.Config, db *database.Database, am *alerts.AlertManager) *Poller {
	return &Poller{
		cfg:          cfg,
		db:           db,
		alertManager: am,
		stopChan:     make(chan struct{}),
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

	// Cleanup old data daily
	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			p.pollAllDevices()
		case <-cleanupTicker.C:
			if p.db != nil {
				if err := p.db.CleanupOldData(90); err != nil {
					log.Printf("Data cleanup error: %v", err)
				} else {
					log.Println("Old data cleanup completed (>90 days)")
				}
			}
			if p.alertManager != nil {
				p.alertManager.PruneExpiredCooldowns()
			}
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

	// Refresh alert thresholds from DB so admin UI changes take effect
	if p.alertManager != nil {
		p.alertManager.RefreshThresholds(p.db.Gorm())
	}

	devices, err := p.db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices: %v", err)
		return
	}

	if len(devices) == 0 {
		log.Println("No devices configured, skipping poll")
		return
	}

	log.Printf("Polling %d devices...", len(devices))

	// Poll devices concurrently with a semaphore to limit concurrent SNMP connections
	sem := make(chan struct{}, 5) // max 5 concurrent polls
	var wg sync.WaitGroup
	for i := range devices {
		if !devices[i].Enabled {
			continue
		}
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore
		go func(device *models.Device) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore
			p.pollDevice(device)
		}(&devices[i])
	}
	wg.Wait()
}

func (p *Poller) pollDevice(device *models.Device) {
	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			SNMPHost: device.IPAddress,
			SNMPPort: device.SNMPPort,
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
		status.DeviceID = device.ID
		status.Timestamp = time.Now()
		if err := p.db.SaveSystemStatus(status); err != nil {
			log.Printf("Device %s: failed to save status - %v", device.Name, err)
		}
	}

	// Check alert thresholds
	if p.alertManager != nil {
		if err := p.alertManager.CheckSystemStatus(status); err != nil {
			log.Printf("Device %s: alert check error - %v", device.Name, err)
		}
	}

	// Save interface stats to database
	interfaces, err := client.GetInterfaceStats()
	if err == nil && len(interfaces) > 0 {
		if p.db != nil {
			now := time.Now()
			for i := range interfaces {
				interfaces[i].DeviceID = device.ID
				interfaces[i].Timestamp = now
			}
			if err := p.db.SaveInterfaceStats(interfaces); err != nil {
				log.Printf("Device %s: failed to save interface stats - %v", device.Name, err)
			}
		}
		// Check interface alerts
		if p.alertManager != nil {
			if err := p.alertManager.CheckInterfaceStatus(interfaces); err != nil {
				log.Printf("Device %s: interface alert check error - %v", device.Name, err)
			}
		}
	}

	p.updateDeviceStatus(device, "online")
}

func (p *Poller) updateDeviceStatus(device *models.Device, status string) {
	device.Status = status
	device.LastPolled = time.Now()
	if p.db != nil {
		if err := p.db.UpdateDevice(device); err != nil {
			log.Printf("Device %s: failed to update status - %v", device.Name, err)
		}
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
	log.Println("Starting SNMP Poller...")

	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Database connected")
	defer db.Close()

	notif := notifier.NewNotifier(cfg)
	alertManager := alerts.NewAlertManager(cfg, notif)

	poller := NewPoller(cfg, db, alertManager)

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
