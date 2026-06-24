package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/secrets"
	"firewall-mon/internal/snmp"
)

// trapMetricsAddr resolves the trap-receiver observability bind address.
// TRAP_METRICS_ADDR overrides the default; "off" disables it (M11).
func trapMetricsAddr() string {
	addr := os.Getenv("TRAP_METRICS_ADDR")
	if addr == "" {
		addr = ":9102"
	}
	if addr == "off" {
		return ""
	}
	return addr
}

// shutdownObs gracefully stops an observability server (nil-safe).
func shutdownObs(srv *http.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = srv.Shutdown(ctx)
	cancel()
}

func main() {
	cfg := config.Load()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting SNMP Trap Receiver...")

	// AUDIT-008: load the persisted JWT secret so we derive the same AES
	// key as cmd/api — required for am.db.DecryptField to read SMTP/IRC
	// credentials saved through the admin UI. If we generated a different
	// secret here, every encrypted setting would be unreadable from this
	// process and alert emails would fail to authenticate.
	secretsDir := os.Getenv("SECRETS_DIR")
	if secretsDir == "" {
		secretsDir = "/data"
	}
	jwtSecret, jwtSource, err := secrets.LoadOrGenerate(cfg.Server.JWTSecretKey, secretsDir, ".jwt-secret")
	if err != nil {
		log.Fatalf("JWT secret: %v (set JWT_SECRET_KEY env, or ensure %s is writable)", err, secretsDir)
	}
	cfg.Server.JWTSecretKey = jwtSecret
	if jwtSource == secrets.Generated {
		log.Printf("trap-receiver generated JWT secret to %s/.jwt-secret (chmod 600) — won race with cmd/api/cmd/poller on first start", secretsDir)
	} else if jwtSource == secrets.FromFile {
		log.Printf("trap-receiver loaded JWT secret from %s/.jwt-secret (chmod 600)", secretsDir)
	}

	trapReceiver, err := snmp.NewTrapReceiver(cfg)
	if err != nil {
		log.Printf("Failed to create trap receiver: %v", err)
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// AUDIT-012/094: trap ingestion needs a global SNMP_TRAP_COMMUNITY. Many
	// deployments don't use one (each firewall can have its own community), so a
	// missing value is a normal "traps off" state, NOT a fatal error — refusing
	// to start here would (under the entrypoint supervisor) crash-loop the whole
	// container and take the API/web UI offline. Instead, log once and idle so
	// the rest of the stack runs normally. Set SNMP_TRAP_COMMUNITY to enable.
	if !trapReceiver.Enabled() {
		log.Printf("SNMP trap ingestion DISABLED: SNMP_TRAP_COMMUNITY is not set, so no trap listener is opened (AUDIT-012: an empty community would accept any spoofable packet on port 162). Set SNMP_TRAP_COMMUNITY to enable. Idling.")
		// M11: still expose /metrics /healthz /readyz while idling so the daemon
		// is observable (and reports "up") even with trap ingestion off.
		obsSrv := metrics.StartObservabilityServer(trapMetricsAddr(), "trap-receiver", nil)
		defer shutdownObs(obsSrv)
		<-quit
		log.Println("Trap receiver exited")
		return
	}

	// AUDIT-005: open a real DB connection and pass it to the AlertManager.
	// Previously this passed nil, which made am.saveAlert a no-op
	// (alerts.go:532-539) — every trap arrived, was logged to stdout, and
	// vanished. The trap-batcher's buffer was never written to either.
	// AUDIT-036: per-process DB pool default (DB_MAX_OPEN_CONNS overrides).
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = 5
	}
	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("trap-receiver: failed to initialize database: %v", err)
	}
	defer db.Close()

	// M11: expose /metrics /healthz /readyz so the trap-receiver isn't a black
	// box. /readyz pings the DB; /metrics carries the trap rate-limiter and Go
	// runtime collectors.
	if sqlDB, dberr := db.Gorm().DB(); dberr == nil {
		metrics.RegisterDBPool(sqlDB, "fwmon_trap")
	}
	obsSrv := metrics.StartObservabilityServer(trapMetricsAddr(), "trap-receiver", func() bool {
		sqlDB, derr := db.Gorm().DB()
		return derr == nil && sqlDB.Ping() == nil
	})
	defer shutdownObs(obsSrv)

	notif := notifier.NewNotifier(cfg)
	alertManager := alerts.NewAlertManager(cfg, notif, db)
	alertManager.RefreshThresholds(db.Gorm())

	err = trapReceiver.Start(func(trap *models.TrapEvent) {
		log.Printf("Received trap: %s - %s (Severity: %s)",
			trap.TrapType, trap.Message, trap.Severity)

		if err := alertManager.ProcessTrap(trap, nil); err != nil {
			log.Printf("Error processing trap: %v", err)
		}
	})

	if err != nil {
		log.Printf("Failed to start trap receiver: %v", err)
		os.Exit(1)
	}

	log.Printf("Trap receiver listening on %s", cfg.SNMP.TrapListenAddr)

	<-quit

	log.Println("Shutting down trap receiver...")
	trapReceiver.Stop()
	log.Println("Trap receiver exited")
}
