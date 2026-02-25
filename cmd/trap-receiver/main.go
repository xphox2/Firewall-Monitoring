package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"fortiGate-Mon/internal/alerts"
	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/models"
	"fortiGate-Mon/internal/notifier"
	"fortiGate-Mon/internal/snmp"
)

func main() {
	cfg := config.Load()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting FortiGate SNMP Trap Receiver...")

	trapReceiver, err := snmp.NewTrapReceiver(cfg)
	if err != nil {
		log.Printf("Failed to create trap receiver: %v", err)
		os.Exit(1)
	}

	notif := notifier.NewNotifier(cfg)
	alertManager := alerts.NewAlertManager(cfg, notif)

	err = trapReceiver.Start(func(trap *models.TrapEvent) {
		log.Printf("Received trap: %s - %s (Severity: %s)",
			trap.TrapType, trap.Message, trap.Severity)

		if err := alertManager.ProcessTrap(trap); err != nil {
			log.Printf("Error processing trap: %v", err)
		}
	})

	if err != nil {
		log.Printf("Failed to start trap receiver: %v", err)
		os.Exit(1)
	}

	log.Printf("Trap receiver listening on %s", cfg.SNMP.TrapListenAddr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down trap receiver...")
	trapReceiver.Stop()
	log.Println("Trap receiver exited")
}
