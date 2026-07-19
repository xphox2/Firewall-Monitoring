package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/api/handlers"
	"firewall-mon/internal/api/middleware"
	"firewall-mon/internal/audit"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/classify"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/irc"
	"firewall-mon/internal/logging"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/secrets"
	"firewall-mon/internal/snmp"
	"firewall-mon/internal/tracing"

	"github.com/gin-gonic/gin"
)

// ServerVersion is the build-baked server version. Bumped in CHANGELOG
// and exposed via GET /api/version so the admin UI can console-log it
// on every page load — that lets operators instantly verify whether
// their redeploy actually shipped (a browser refresh alone won't update
// embedded JS/HTML, since they're compiled into this binary).
const ServerVersion = "0.11.125"

// runMigrateCmd implements `fwmon-api migrate` (AUDIT-044): connect, apply any
// pending migrations, print status, exit non-zero on failure.
func runMigrateCmd() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	database.AppVersion = ServerVersion
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("migrate: connect: %v", err)
	}
	defer db.Close()
	if err := db.RunMigrations(); err != nil {
		log.Printf("migrate: FAILED: %v", err)
		os.Exit(1)
	}
	db.PrintMigrationStatus()
}

// runMigrateStatusCmd implements `fwmon-api migrate-status` (AUDIT-044): connect
// and report applied/pending migrations without changing anything.
func runMigrateStatusCmd() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	database.AppVersion = ServerVersion
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("migrate-status: connect: %v", err)
	}
	defer db.Close()
	db.PrintMigrationStatus()
}

func main() {
	// AUDIT-076: install the structured (slog) logger first, before any other
	// package logs. This also routes the legacy `log` package through slog, so
	// every existing log.Printf gains levels/fields/redaction (LOG_FORMAT,
	// LOG_LEVEL env). Done before the migrate-subcommand switch so out-of-band
	// `migrate`/`migrate-status` runs are structured too.
	logging.Init()

	// AUDIT-044: explicit migration subcommands. `migrate` connects, applies any
	// pending migrations, prints status, and exits; `migrate-status` just reports
	// applied/pending without changing anything. The long-running services still
	// auto-apply migrations on startup (NewDatabase) as a self-heal, so these are
	// for operators who want to run/inspect migrations out-of-band.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			runMigrateCmd()
			return
		case "migrate-status":
			runMigrateStatusCmd()
			return
		}
	}

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	database.AppVersion = ServerVersion // AUDIT-044: stamp schema_migrations rows

	// AUDIT-150: OpenTelemetry tracing. OFF unless OTEL_TRACES_ENABLED=true, in
	// which case spans export over OTLP/HTTP to OTEL_EXPORTER_OTLP_ENDPOINT. The
	// shutdown flushes buffered spans on graceful exit; it's a no-op when disabled.
	traceShutdown, err := tracing.Init(context.Background(), "fwmon-api", ServerVersion)
	if err != nil {
		log.Printf("Tracing init failed (continuing without tracing): %v", err)
	}
	defer func() { _ = traceShutdown(context.Background()) }()

	// AUDIT-008: persist auto-generated JWT secret to disk so subsequent
	// restarts use the SAME key. Otherwise every restart (a) invalidates
	// every existing JWT login token and (b) derives a different AES-256
	// key for the {enc}<base64> ENC fields (SNMP / IRC / SMTP creds),
	// making them permanently unreadable. The secrets dir defaults to
	// /data (the Docker volume mount); set SECRETS_DIR to override for
	// non-Docker installs.
	secretsDir := os.Getenv("SECRETS_DIR")
	if secretsDir == "" {
		secretsDir = "/data"
	}
	jwtSecret, jwtSource, err := secrets.LoadOrGenerate(cfg.Server.JWTSecretKey, secretsDir, ".jwt-secret")
	if err != nil {
		log.Fatalf("JWT secret: %v (set JWT_SECRET_KEY env, or ensure %s is writable)", err, secretsDir)
	}
	cfg.Server.JWTSecretKey = jwtSecret
	switch jwtSource {
	case secrets.FromFile:
		log.Printf("JWT secret loaded from %s/.jwt-secret (chmod 600)", secretsDir)
	case secrets.Generated:
		log.Printf("JWT secret auto-generated and persisted to %s/.jwt-secret (chmod 600); set JWT_SECRET_KEY env to override", secretsDir)
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies(nil) // Do not trust proxy headers for client IP

	// API versioning aliases (v0.10.219, bundle H1).
	//
	// AUDIT-138: hand-coded path-rewrite, not a generic middleware.
	// Safe today because the slice math is `p[len(prefix):]` — the
	// prefix is consumed exactly, and a `..` in the path can't
	// escape into admin paths because the prefix check fails for
	// anything that doesn't start with the literal `/api/v1/` or
	// `/admin/api/v1/`. Fragile in the sense that adding a third
	// version (e.g. `/api/v2/`) is a code change, not a config
	// change. The right next step is the real versioning work
	// tracked in AUDIT-090; until that lands, this is the
	// intentional interim design.
	//
	// Mount /api/v1/* as a synonym for /api/* (and /admin/api/v1/* for
	// /admin/api/*) via a path-rewrite middleware. /api/ stays the
	// canonical path for now — both existing admin JS and the
	// Firewall-Collector probe binary call /api/ paths unchanged. The
	// versioned aliases give us a clean upgrade lane: when a future
	// breaking change ships, we add /api/v2/* alongside the existing
	// routes and operate both during a deprecation window.
	//
	// Implementation: rewrite the request URL before route matching so
	// downstream handlers and middleware see the canonical path. No
	// per-route duplication, no redirect roundtrip.
	router.Use(func(c *gin.Context) {
		p := c.Request.URL.Path
		switch {
		case strings.HasPrefix(p, "/api/v1/"):
			c.Request.URL.Path = "/api/" + p[len("/api/v1/"):]
		case strings.HasPrefix(p, "/admin/api/v1/"):
			c.Request.URL.Path = "/admin/api/" + p[len("/admin/api/v1/"):]
		}
		c.Next()
	})

	// AUDIT-036: per-process DB pool default (DB_MAX_OPEN_CONNS overrides).
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = 15
	}
	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Println("Database initialized")

	// AUDIT-040: API singleton guard. cmd/api keeps four state stores in process
	// memory (IRC bots, login-lockout counters, rate-limit buckets, uptime
	// baseline); a second instance would double-run them. Hold a lifetime
	// Postgres advisory lock; refuse to start if another API already holds it
	// (unless ALLOW_MULTI_API opts into follower mode — HTTP only, no IRC bots).
	isPrimary := false
	releaseSingleton := func() {}
	{
		deadline := time.Now().Add(cfg.Server.APISingletonLockWait)
		for {
			release, acquired, lockErr := db.AcquireAPISingletonLock()
			if lockErr != nil {
				// Probe/infra error: bias toward proceeding as primary rather
				// than blocking on a transient DB hiccup (cf. tryAcquireStartupLock).
				log.Printf("AUDIT-040: singleton lock probe failed (%v); proceeding as primary.", lockErr)
				isPrimary, releaseSingleton = true, release
				break
			}
			if acquired {
				isPrimary, releaseSingleton = true, release
				break
			}
			release() // no-op; we didn't get the lock
			if time.Now().Before(deadline) {
				log.Printf("AUDIT-040: another API holds the singleton lock; retrying for up to %s...", cfg.Server.APISingletonLockWait)
				time.Sleep(2 * time.Second)
				continue
			}
			break
		}
		if !isPrimary {
			if cfg.Server.AllowMultiAPI {
				log.Println("============================================================")
				log.Println("WARNING: AUDIT-040 — starting in FOLLOWER mode (ALLOW_MULTI_API=true).")
				log.Println("         Another API instance holds the singleton lock.")
				log.Println("         IRC bots are DISABLED on this instance (nick-collision guard).")
				log.Println("         Login lockout, rate-limit, and uptime are PER-INSTANCE and")
				log.Println("         WILL DIVERGE from the primary. See docs/OPERATIONS.md.")
				log.Println("============================================================")
			} else {
				log.Fatalf("AUDIT-040: another fwmon-api instance is already running (singleton " +
					"advisory lock held). Refusing to start to avoid double IRC bots, divergent " +
					"login-lockout/rate-limit state, and inconsistent uptime. Run exactly ONE API " +
					"process, or set ALLOW_MULTI_API=true for follower mode (HTTP only, no IRC bots). " +
					"See docs/OPERATIONS.md 'Running a single API instance (AUDIT-040)'.")
			}
		}
	}
	defer releaseSingleton() // drops the lock on graceful shutdown so the next restart re-acquires

	// AUDIT-077: expose the database/sql connection-pool stats on /metrics so
	// pool exhaustion is observable before it turns into request timeouts.
	if sqlDB, dberr := db.Gorm().DB(); dberr == nil {
		metrics.RegisterDBPool(sqlDB, "fwmon")
	}

	authManager := auth.NewAuthManager(cfg, db)

	// AUDIT-008: admin password persistence. The previous code generated a
	// fresh random password on every restart if ADMIN_PASSWORD was unset
	// — but only persisted it to /data/.admin-password if the write
	// succeeded, and InitAdmin only sets the hash on FIRST run. Result:
	// on restart, the operator saw a NEW password printed that did NOT
	// match the bcrypt hash already in the DB → permanently locked out.
	//
	// New flow when ADMIN_PASSWORD is unset:
	//   1. If /data/.admin-password exists, load it (this is what the DB
	//      hash was computed from on first run).
	//   2. Otherwise, persist the just-generated value to disk so future
	//      restarts can find it.
	//   3. Any I/O failure is fatal — silently continuing recreates the
	//      bug we're closing.
	if cfg.IsGeneratedPassword() {
		if existing, ok, err := secrets.LoadPassword(secretsDir, ".admin-password"); err != nil {
			log.Fatalf("admin password: cannot read persisted file: %v", err)
		} else if ok {
			cfg.Auth.AdminPassword = existing
			log.Printf("Admin password loaded from %s/.admin-password (chmod 600); set ADMIN_PASSWORD env to override", secretsDir)
		} else {
			// First run — pin the config-generated password to disk.
			if _, err := secrets.PersistGeneratedPassword(cfg.Auth.AdminPassword, secretsDir, ".admin-password"); err != nil {
				log.Fatalf("admin password: failed to persist auto-generated password to %s/.admin-password: %v (set ADMIN_PASSWORD env, or ensure %s is writable)", secretsDir, err, secretsDir)
			}
			log.Println("========================================")
			log.Println("AUTO-GENERATED ADMIN PASSWORD")
			log.Printf("Username: %s", cfg.Auth.AdminUsername)
			log.Printf("Password file: %s/.admin-password (chmod 600)", secretsDir)
			log.Println("Set ADMIN_PASSWORD env var to override on next start.")
			log.Println("========================================")
		}
	}

	// Initialize admin in database (skips if admin already exists from migration)
	if db != nil {
		hashedPassword, err := authManager.HashPassword(cfg.Auth.AdminPassword)
		if err != nil {
			log.Fatalf("Failed to hash admin password: %v", err)
		}
		// Force a first-login password change only when the bootstrap password was
		// auto-generated (it gets written to the container log and .admin-password
		// file). An operator who set ADMIN_PASSWORD deliberately is trusted as-is.
		if err := db.InitAdmin(cfg.Auth.AdminUsername, hashedPassword, cfg.IsGeneratedPassword()); err != nil {
			log.Printf("WARNING: admin initialization failed: %v", err)
		}
	}

	// AUDIT-084: background workers get a cancellable context so they exit on
	// graceful shutdown instead of relying on process death (which skips
	// deferred cleanup if the shutdown path ever changes). bgCancel is called
	// from the shutdown block below.
	bgCtx, bgCancel := context.WithCancel(context.Background())

	// Periodically prune expired login attempts to prevent unbounded map growth
	logging.SafeGo("login-attempt-pruner", func() { // REL-01
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				authManager.PruneExpiredAttempts()
			case <-bgCtx.Done():
				return
			}
		}
	})

	// Clear plaintext password from memory after initialization
	cfg.Auth.AdminPassword = ""

	handler := handlers.NewHandler(cfg, authManager, db)

	// Periodically reload the threat-intel matcher so feed edits and expiries
	// take effect in the ingest path without a restart (the matcher lives on the
	// handler because ingest — ReceiveFlowSamples — runs in this process).
	logging.SafeGo("threat-intel-refresh", func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				handler.RefreshThreatMatcher()
			case <-bgCtx.Done():
				return
			}
		}
	})

	// Periodically hot-reload the geo databases so a freshly downloaded MaxMind
	// update (written atomically via rename) applies to sFlow geo/ASN enrichment
	// without a restart, and without unmapping a live reader under an in-flight
	// lookup (audit L4). No-op when geo is disabled.
	logging.SafeGo("geoip-reload", func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				handler.ReloadGeoIP()
			case <-bgCtx.Done():
				return
			}
		}
	})

	// Optional paid live-update path: when MAXMIND_LICENSE_KEY is set, download the
	// configured editions into GEOIP_DB_DIR on a schedule (they take precedence
	// over the embedded free bundle). nil updater (no key) => the goroutine exits
	// immediately. After each successful sync we reload so the new files swap in
	// without waiting for the 6h reload tick.
	if updater := classify.NewMaxMindUpdater(cfg.Server.MaxMindLicenseKey, cfg.Server.MaxMindAccountID, cfg.Server.MaxMindEditionIDs, cfg.Server.GeoIPDBDir); updater != nil {
		logging.SafeGo("geoip-update", func() {
			runUpdate := func() {
				ctx, cancel := context.WithTimeout(bgCtx, 15*time.Minute)
				defer cancel()
				if n, err := updater.UpdateAll(ctx); n > 0 {
					handler.ReloadGeoIP()
					log.Printf("geoip-update: %d edition(s) refreshed", n)
				} else if err != nil {
					log.Printf("geoip-update: no editions refreshed: %v", err)
				}
			}
			runUpdate() // initial sync shortly after startup
			ticker := time.NewTicker(cfg.Server.GeoIPUpdateInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					runUpdate()
				case <-bgCtx.Done():
					return
				}
			}
		})
	}

	// Real-time NOC dashboard broadcaster: one goroutine recomputes the snapshot
	// on a ticker and fans it out to all connected SSE clients (handler.nocHub).
	logging.SafeGo("noc-broadcaster", func() {
		handler.RunNOCHub(bgCtx)
	})

	// Create alert manager for data ingestion handlers (syslog alerts, etc.)
	notif := notifier.NewNotifier(cfg)
	alertMgr := alerts.NewAlertManager(cfg, notif, db)
	alertMgr.RefreshThresholds(db.Gorm())
	handler.SetAlertManager(alertMgr)

	// LC-9: periodically refresh the alert policy/maintenance/threshold cache so
	// admin edits (policies, maintenance windows, SMTP/webhook credentials) take
	// effect in THIS process's alert paths (syslog-critical, SSH host-key,
	// config-change) without a restart — the poller refreshes every poll cycle;
	// this process previously loaded the cache exactly once at startup.
	logging.SafeGo("alert-config-refresh", func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				alertMgr.RefreshThresholds(db.Gorm())
			case <-bgCtx.Done():
				return
			}
		}
	})

	// Wire the notifier + version for on-demand report sends / rendering from
	// the admin Reports page (scheduled reports run in the poller process).
	handler.SetNotifier(notif)
	handler.SetVersion(ServerVersion)

	snmpClient, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("Warning: Failed to connect to SNMP: %v", err)
	} else {
		handler.SetSNMPClient(snmpClient)
		defer snmpClient.Close()
	}

	ircManager := irc.NewManager(db.Gorm())
	ircManager.SetDecryptFunc(db.DecryptField)
	ircManager.SetStatusProvider(func() (map[string]interface{}, error) {
		var devices []models.Device
		db.Gorm().Find(&devices)

		var devList []map[string]interface{}
		for _, d := range devices {
			dev := map[string]interface{}{
				"name":   d.Name,
				"status": d.Status,
			}
			var status models.SystemStatus
			if err := db.Gorm().Where("device_id = ?", d.ID).Order("timestamp DESC").First(&status).Error; err == nil {
				dev["cpu"] = status.CPUUsage
				dev["mem"] = status.MemoryUsage
				dev["sessions"] = status.SessionCount
				dev["uptime"] = status.Uptime
			}
			var vpnUp, vpnTotal int64
			db.Gorm().Model(&models.VPNStatus{}).
				Where("device_id = ? AND timestamp = (SELECT MAX(v2.timestamp) FROM vpn_status v2 WHERE v2.device_id = ? AND v2.tunnel_name = vpn_status.tunnel_name)", d.ID, d.ID).
				Count(&vpnTotal)
			db.Gorm().Model(&models.VPNStatus{}).
				Where("device_id = ? AND status = ? AND timestamp = (SELECT MAX(v2.timestamp) FROM vpn_status v2 WHERE v2.device_id = ? AND v2.tunnel_name = vpn_status.tunnel_name)", d.ID, "up", d.ID).
				Count(&vpnUp)
			dev["vpn_up"] = int(vpnUp)
			dev["vpn_total"] = int(vpnTotal)

			var alertCount int64
			db.Gorm().Model(&models.Alert{}).Where("device_id = ? AND acknowledged = ?", d.ID, false).Count(&alertCount)
			dev["alerts"] = int(alertCount)

			devList = append(devList, dev)
		}

		return map[string]interface{}{
			"devices": devList,
		}, nil
	})
	ircManager.SetStatsProvider(func() (map[string]interface{}, error) {
		var devices []models.Device
		db.Gorm().Find(&devices)
		var totalDevices = len(devices)
		var cpuAvg, memAvg float64
		if totalDevices > 0 {
			var totalCPU, totalMem float64
			for _, d := range devices {
				var status models.SystemStatus
				if err := db.Gorm().Where("device_id = ?", d.ID).Order("timestamp DESC").First(&status).Error; err == nil {
					totalCPU += status.CPUUsage
					totalMem += status.MemoryUsage
				}
			}
			cpuAvg = totalCPU / float64(totalDevices)
			memAvg = totalMem / float64(totalDevices)
		}
		return map[string]interface{}{
			"total_devices": totalDevices,
			"cpu_avg":       cpuAvg,
			"memory_avg":    memAvg,
		}, nil
	})
	// AUDIT-040: only the singleton primary runs the IRC bots — a follower
	// starting them would collide on the bot's IRC nick. The manager is still
	// wired into the handler so the admin IRC config pages (DB CRUD) work on a
	// follower; only the bot connections are gated.
	if isPrimary {
		ircManager.Start()
	} else {
		log.Println("AUDIT-040: IRC bots disabled (follower / not the singleton primary).")
	}
	handler.SetIRCManager(ircManager)
	defer ircManager.Stop()

	setupRoutes(router, cfg, handler, authManager, db)

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:           router,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second, // AUDIT-023: protect against slow-loris header attacks
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    1 << 16, // 64KB
	}

	// AUDIT-086: previously the listen goroutine called log.Fatal on any
	// listener error, which exits the process immediately and skips every
	// `defer` registered above (ircManager.Stop, snmpClient.Close, etc.).
	// Now the goroutine surfaces the error on errCh and the main goroutine
	// picks it up via select alongside the signal channel; both paths run
	// the same graceful-shutdown sequence and let defers fire on return.
	errCh := make(chan error, 1)
	go func() {
		log.Printf("Server starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
		var err error
		if cfg.Server.EnableTLS {
			err = server.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("Received signal %v, shutting down server...", sig)
	case err := <-errCh:
		log.Printf("HTTP listener failed: %v — initiating graceful shutdown", err)
	}

	// AUDIT-084: stop background workers (login-attempt pruner) before the
	// server drains, so their tickers don't fire mid-shutdown.
	bgCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		// Don't log.Fatal: that would skip the deferred ircManager.Stop /
		// snmpClient.Close. Log the error and let main return so defers run.
		log.Printf("Server.Shutdown error: %v", err)
	}

	log.Println("Server exited")
}

func setupRoutes(router *gin.Engine, cfg *config.Config, handler *handlers.Handler, authManager *auth.AuthManager, db *database.Database) {
	router.Use(middleware.SecureHeaders())
	router.Use(middleware.CORS(cfg))
	router.Use(middleware.RequestID())             // AUDIT-135: before RequestLogger so the ID is logged
	router.Use(tracing.GinMiddleware("fwmon-api")) // AUDIT-150: server span + W3C extract, before RequestLogger so logs get trace_id
	router.Use(middleware.RequestLogger())
	router.Use(metrics.Middleware())              // AUDIT-077: record request latency by route/method/status
	router.Use(middleware.BodySizeLimit(5 << 20)) // 5MB max request body
	// Rate limiter applied per-group below instead of globally so authenticated
	// admin users don't share buckets with unauthenticated requests.

	// Static assets: serve from ./cmd/api/static on disk if it exists (so a
	// git pull + service restart picks up JS/CSS changes the same way it
	// picks up HTML changes — no binary rebuild needed). Fall back to the
	// embedded FS when the source dir isn't present (Docker runtime, single-
	// binary deploys without source). Source-on-disk is intentionally
	// preferred so operators can hot-fix without recompiling.
	if info, err := os.Stat("./cmd/api/static"); err == nil && info.IsDir() {
		router.Static("/static", "./cmd/api/static")
		log.Println("Static assets: serving from ./cmd/api/static (disk)")
	} else {
		subFS, _ := fs.Sub(staticFiles, "static")
		router.StaticFS("/static", http.FS(subFS))
		log.Println("Static assets: serving from embedded FS (disk dir not found)")
	}
	router.LoadHTMLGlob("./web/**/*.html")

	router.GET("/", func(c *gin.Context) {
		middleware.RenderHTML(c, http.StatusOK, "index.html", nil)
	})

	// Public version endpoint — no auth required so the admin UI can
	// console-log it on page load to confirm what's deployed.
	router.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"version": ServerVersion})
	})

	// AUDIT-077: Prometheus exposition. Intentionally unauthenticated — the
	// convention is to protect /metrics at the network layer (firewall the
	// scrape port / bind internally). It exposes only aggregate timings and
	// route templates, no secrets.
	router.GET("/metrics", gin.WrapH(metrics.Handler()))

	// Minimal SVG favicon to prevent 404
	router.GET("/favicon.ico", func(c *gin.Context) {
		svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#161b22"/><path d="M8 10h16M8 16h16M8 22h12" stroke="#58a6ff" stroke-width="2.5" stroke-linecap="round"/><circle cx="25" cy="22" r="3" fill="#3fb950"/></svg>`
		c.Data(http.StatusOK, "image/svg+xml", []byte(svg))
	})

	// AUDIT-112: RFC 9116 security.txt for vulnerability-disclosure programs.
	// Served at both the canonical /.well-known/ path and the legacy root path.
	// The Expires field is required by RFC 9116 and is generated 6 months out
	// at request time so it never goes stale (the spec recommends < 1 year).
	securityTxt := func(c *gin.Context) {
		expires := time.Now().UTC().AddDate(0, 6, 0).Format(time.RFC3339)
		body := "# Firewall-Mon security contact (RFC 9116)\n" +
			"Contact: https://github.com/xphox2/Firewall-Monitoring/security/advisories/new\n" +
			"Policy: https://github.com/xphox2/Firewall-Monitoring/blob/master/SECURITY.md\n" +
			"Preferred-Languages: en\n" +
			"Expires: " + expires + "\n"
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(body))
	}
	router.GET("/.well-known/security.txt", securityTxt)
	router.GET("/security.txt", securityTxt)

	router.GET("/admin/login", func(c *gin.Context) {
		middleware.RenderHTML(c, http.StatusOK, "login.html", nil)
	})

	api := router.Group("/api")
	api.Use(middleware.RateLimiter(cfg))
	{
		api.GET("/health", handler.GetHealth)
		api.GET("/readyz", handler.GetHealth)                // M8/k8s: readiness alias — same DB + encryption-key gate
		api.POST("/client-error", handler.ReportClientError) // AUDIT-129: browser JS error beacon (rate-limited, logged)

		public := api.Group("/public")
		public.Use(middleware.PublicRateLimiter())
		public.Use(middleware.CheckAdminAuth(authManager))
		{
			public.GET("/devices", handler.GetPublicDevices)
			public.GET("/dashboard", handler.GetPublicDashboard)
			public.GET("/interfaces", handler.GetPublicInterfaces)
			public.GET("/interfaces/chart", handler.GetPublicInterfaceChart)
			public.GET("/status-history", handler.GetPublicStatusHistory)
			public.GET("/vpn", handler.GetPublicVPN)
			public.GET("/connections", handler.GetPublicConnections)
			public.GET("/display-settings", handler.GetPublicDisplaySettings)
		}

		api.POST("/auth/login", middleware.LoginRateLimiter(), handler.Login)
		// 2FA second step (P0-3): exchanges the pending_2fa cookie + a TOTP or
		// recovery code for a session. Same rate limiter as login.
		api.POST("/auth/totp", middleware.LoginRateLimiter(), handler.TOTPLogin)

		api.POST("/probes/register", handler.RegisterProbe)
		api.POST("/probes/heartbeat", handler.ProbeHeartbeat)

		// Probe data ingestion endpoints (rate limited, authenticated per-request)
		api.POST("/probes/:id/syslog", middleware.ProbeRateLimiter(), handler.ReceiveSyslogMessages)
		api.POST("/probes/:id/traps", middleware.ProbeRateLimiter(), handler.ReceiveTrapEvents)
		api.POST("/probes/:id/flows", middleware.ProbeRateLimiter(), handler.ReceiveFlowSamples)
		api.POST("/probes/:id/flow-counters", middleware.ProbeRateLimiter(), handler.ReceiveFlowCounterSamples)
		api.POST("/probes/:id/pings", middleware.ProbeRateLimiter(), handler.ReceivePingResults)
		api.POST("/probes/:id/system-status", middleware.ProbeRateLimiter(), handler.ReceiveSystemStatuses)
		api.POST("/probes/:id/interface-stats", middleware.ProbeRateLimiter(), handler.ReceiveInterfaceStats)
		api.POST("/probes/:id/vpn-status", middleware.ProbeRateLimiter(), handler.ReceiveVPNStatuses)
		api.POST("/probes/:id/hardware-sensors", middleware.ProbeRateLimiter(), handler.ReceiveHardwareSensors)
		api.POST("/probes/:id/processor-stats", middleware.ProbeRateLimiter(), handler.ReceiveProcessorStats)
		api.POST("/probes/:id/disk-usage", middleware.ProbeRateLimiter(), handler.ReceiveDiskUsage)
		api.POST("/probes/:id/load-average", middleware.ProbeRateLimiter(), handler.ReceiveLoadAverage)
		api.POST("/probes/:id/ha-status", middleware.ProbeRateLimiter(), handler.ReceiveHAStatuses)
		api.POST("/probes/:id/security-stats", middleware.ProbeRateLimiter(), handler.ReceiveSecurityStats)
		api.POST("/probes/:id/sdwan-health", middleware.ProbeRateLimiter(), handler.ReceiveSDWANHealth)
		api.POST("/probes/:id/license-info", middleware.ProbeRateLimiter(), handler.ReceiveLicenseInfo)
		api.POST("/probes/:id/interface-addresses", middleware.ProbeRateLimiter(), handler.ReceiveInterfaceAddresses)
		api.POST("/probes/:id/config-revision", middleware.ProbeRateLimiter(), handler.ReceiveConfigRevision)
		api.POST("/probes/:id/process-snapshot", middleware.ProbeRateLimiter(), handler.ReceiveProcessSnapshot)
		api.POST("/probes/:id/interface-errors", middleware.ProbeRateLimiter(), handler.ReceiveInterfaceErrors)
		api.POST("/probes/:id/sensor-details", middleware.ProbeRateLimiter(), handler.ReceiveSensorDetails)
		api.POST("/probes/:id/license-details", middleware.ProbeRateLimiter(), handler.ReceiveLicenseDetails)
		// Relay schema v4: collector reports the outcome of a heartbeat-
		// delivered command (idempotent by command_id).
		api.POST("/probes/:id/command-result", middleware.ProbeRateLimiter(), handler.ReceiveCommandResult)
		// Relay schema v5: L2 topology state snapshots (ARP/FDB + LLDP/CDP)
		// for the port-to-port connection map — replace semantics per device.
		api.POST("/probes/:id/topology-entries", middleware.ProbeRateLimiter(), handler.ReceiveTopologyEntries)
		api.POST("/probes/:id/topology-neighbors", middleware.ProbeRateLimiter(), handler.ReceiveTopologyNeighbors)

		// Probe fetches its assigned devices
		api.GET("/probes/:id/devices", middleware.ProbeRateLimiter(), handler.GetProbeDevices)
	}

	admin := router.Group("/admin")
	admin.Use(middleware.AdminAuth(authManager, db))
	admin.Use(middleware.CSRFProtection(cfg))
	// AUDIT-078: record authenticated admin mutations. After auth+CSRF so it
	// only fires for genuine admin actions and the actor is on the context.
	admin.Use(audit.Middleware(db))
	// Forced first-login password change: block all admin API routes (except the
	// change-password/logout/csrf endpoints and the SPA pages) for an account
	// still flagged must_change_password, so the rotation can't be skipped by
	// calling the API directly. After AdminAuth so user_id is on the context.
	admin.Use(handler.RequirePasswordChanged())
	// RBAC (P0-1): viewer=read-only, operator=day-to-day mutations, admin=all.
	// Maps hold route templates; everything not listed falls to the method
	// defaults (GET/HEAD=viewer, mutation=operator). Keep adminOnlyRoutes in
	// sync when adding routes that expose settings, users, or credential
	// material — the role-matrix test enumerates router.Routes() as a guard.
	admin.Use(middleware.RequireRole(
		map[string]bool{ // selfServiceRoutes — any authenticated role
			"/admin/api/csrf-token":        true,
			"/admin/api/logout":            true,
			"/admin/api/settings/password": true,
			"/admin/api/me":                true,
			"/admin/api/me/mfa-decline":    true,
			"/admin/api/me/dashboard":      true,
			"/admin/api/2fa/setup":         true,
			"/admin/api/2fa/verify":        true,
			"/admin/api/2fa/disable":       true,
		},
		map[string]bool{ // adminOnlyRoutes — role=admin, any method
			"/admin/api/settings":                  true,
			"/admin/api/settings/test-email":       true,
			"/admin/api/settings/test-webhook":     true,
			"/admin/api/users":                     true,
			"/admin/api/users/:id":                 true,
			"/admin/api/users/:id/reset-password":  true,
			"/admin/api/users/:id/reset-2fa":       true,
			"/admin/api/tokens":                    true,
			"/admin/api/tokens/:id":                true,
			"/admin/api/probes/:id/regenerate-key": true,
			// Revealing a stored device credential in plaintext is admin-only,
			// even though day-to-day device edits are operator-level.
			"/admin/api/devices/:id/reveal-secret": true,
			// IPSec provisioning carries PSK credential material — admin-only.
			"/admin/api/ipsec/capabilities":        true,
			"/admin/api/ipsec/preview":             true,
			"/admin/api/ipsec/tunnels":             true,
			"/admin/api/ipsec/tunnels/:id":         true,
			"/admin/api/ipsec/tunnels/:id/preview": true,
			// Wizard interface hints expose per-device addressing to the admin-only
			// IPSec wizard; keep behind the same admin gate.
			"/admin/api/devices/:id/ipsec-hints": true,
			// LC-17: IRC server/channel config carries credential material
			// (server/NickServ/SASL passwords, channel keys) and the test
			// endpoint dials an arbitrary request-supplied host with request-
			// supplied credentials — same class as settings/test-email and
			// settings/test-webhook above. Connect/disconnect/send/commands
			// stay operator-level (day-to-day ops, no credential exposure).
			"/admin/api/irc/servers":      true,
			"/admin/api/irc/servers/:id":  true,
			"/admin/api/irc/servers/test": true,
			"/admin/api/irc/channels":     true,
			"/admin/api/irc/channels/:id": true,
			// v0.11.46: threat-feed control (per-feed disable purges indicators;
			// master switch; storm-digest threshold) is destructive admin config.
			"/admin/api/threat-intel/feeds/:source": true,
			"/admin/api/threat-intel/global":        true,
			"/admin/api/threat-intel/storm-tuning":  true,
			// v35: event-rule CRUD + tester. A suppress rule can silence security
			// alerting, and the tester reads raw syslog content — admin-only.
			"/admin/api/event-rules":          true,
			"/admin/api/event-rules/:id":      true,
			"/admin/api/event-rules/test":     true,
			"/admin/api/event-rules/template": true,
			// v48: event rule profiles — a toggle Off silences an alert type for
			// a whole scope; same class as event rules. The registry, effective
			// view and assignment endpoints ride along (assignment changes what
			// gets suppressed where).
			"/admin/api/event-rule-profiles":                 true,
			"/admin/api/event-rule-profiles/:id":             true,
			"/admin/api/event-rule-profiles/:id/clone":       true,
			"/admin/api/event-rule-profiles/:id/toggles":     true,
			"/admin/api/event-rule-profiles/:id/assignments": true,
			"/admin/api/alert-types":                         true,
			"/admin/api/devices/:id/event-profile":           true,
			"/admin/api/sites/:id/event-profile":             true,
			"/admin/api/event-config/effective":              true,
			// Suggests a suppress/customize rule from an alert (rule creation is
			// admin-only, and the syslog path reads raw log content) — admin-only.
			"/admin/api/alerts/:id/suggested-rule": true,
		},
	))
	{
		admin.GET("", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/dashboard", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/devices", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/settings", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/profile", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/reports", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/audit", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/connections", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		// Probes and Sites are SPA pages (folded into admin.html); the shell
		// reads the trailing path segment and shows page-probes / page-sites.
		admin.GET("/probes", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/sites", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/syslog", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/flows", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/noc", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/alerts", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/threat-intel", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/alerting", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/ipsec", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/alert-policies", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/event-rules", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/maintenance", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/traps", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/network", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "network.html", nil)
		})

		admin.GET("/devices/:id", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "device-detail.html", nil)
		})

		admin.GET("/connections/:id", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "connection-detail.html", nil)
		})

		admin.GET("/api/csrf-token", handler.GetCSRFToken)
		admin.GET("/api/dashboard", handler.GetDashboardAll)
		admin.GET("/api/dashboard/:id", handler.GetAdminDashboard)
		admin.GET("/api/alerts", handler.GetAlerts)
		// Incidents (F12): grouped alert storms, read-only.
		admin.GET("/api/incidents", handler.ListIncidents)
		admin.GET("/api/incidents/:id/alerts", handler.GetIncidentAlerts)
		admin.GET("/api/traps", handler.GetTraps)
		admin.GET("/api/uptime", handler.GetUptime)
		admin.POST("/api/uptime/reset", handler.ResetUptime)

		admin.GET("/api/audit", handler.GetAuditLogs) // AUDIT-078: admin-action trail

		admin.GET("/api/devices", handler.GetDevices)
		admin.POST("/api/devices", handler.CreateDevice)
		admin.POST("/api/devices/test", handler.TestDeviceConnection)
		admin.PUT("/api/devices/:id", handler.UpdateDevice)
		admin.DELETE("/api/devices/:id", handler.DeleteDevice)
		// Reveal one decrypted device credential — admin-only (in adminOnlyRoutes),
		// rate-limited like login (it re-verifies a password), audit-logged.
		admin.POST("/api/devices/:id/reveal-secret", middleware.LoginRateLimiter(), handler.RevealDeviceSecret)

		// IPSec provisioning wizard (PR-A: intent CRUD + capabilities + preview;
		// no live device writes). Tunnels carry PSK credential material, so the
		// mutations are admin-only (in adminOnlyRoutes).
		admin.GET("/api/ipsec/capabilities", handler.IPSecCapabilities)
		admin.POST("/api/ipsec/preview", handler.PreviewIPSecIntent)
		admin.GET("/api/ipsec/tunnels", handler.ListIPSecTunnels)
		admin.POST("/api/ipsec/tunnels", handler.CreateIPSecTunnel)
		admin.GET("/api/ipsec/tunnels/:id", handler.GetIPSecTunnel)
		admin.PUT("/api/ipsec/tunnels/:id", handler.UpdateIPSecTunnel)
		admin.DELETE("/api/ipsec/tunnels/:id", handler.DeleteIPSecTunnel)
		admin.GET("/api/ipsec/tunnels/:id/preview", handler.PreviewIPSecTunnel)
		// Read-only endpoint hints: the picked device's real interfaces + addresses
		// so the wizard populates egress/LAN/subnets from live data (admin-only).
		admin.GET("/api/devices/:id/ipsec-hints", handler.GetIPSecEndpointHints)

		admin.GET("/api/sites", handler.GetSites)
		admin.POST("/api/sites", handler.CreateSite)
		admin.PUT("/api/sites/:id", handler.UpdateSite)
		admin.DELETE("/api/sites/:id", handler.DeleteSite)
		admin.GET("/api/sites/:id", handler.GetSite)

		admin.GET("/api/probes", handler.GetProbes)
		admin.POST("/api/probes", handler.CreateProbe)
		admin.PUT("/api/probes/:id", handler.UpdateProbe)
		admin.DELETE("/api/probes/:id", handler.DeleteProbe)
		admin.GET("/api/probes/:id", handler.GetProbe)
		admin.POST("/api/probes/test", handler.TestProbeConnection)
		admin.GET("/api/probes/stats", handler.GetProbesStatsBatch)       // AUDIT-064: batch stats (static path, sibling of /:id)
		admin.GET("/api/probes/stats/global", handler.GetTelemetryTotals) // orphan-safe running totals (probe-independent)
		admin.POST("/api/probes/:id/approve", handler.ApproveProbe)
		admin.POST("/api/probes/:id/reject", handler.RejectProbe)
		admin.POST("/api/probes/:id/decommission", handler.DecommissionProbe)
		admin.POST("/api/probes/:id/recommission", handler.RecommissionProbe)
		// Relay schema v4 command channel: minimal enqueue (noop-only in PR-1)
		// + list, for verifying the server→collector round-trip end-to-end.
		admin.POST("/api/probes/:id/commands", handler.CreateProbeCommand)
		admin.GET("/api/probes/:id/commands", handler.GetProbeCommands)
		admin.DELETE("/api/probes/:id/commands/:cmdid", handler.CancelProbeCommand)
		admin.POST("/api/probes/:id/regenerate-key", handler.RegenerateProbeKey)

		admin.GET("/api/syslog", handler.GetSyslogMessages)
		admin.GET("/api/syslog/:id", handler.GetSyslogMessage)
		admin.GET("/api/flows", handler.GetFlowSamples)
		admin.GET("/api/probes/:id/stats", handler.GetProbeStats)

		admin.GET("/api/devices/:id/detail", handler.GetDeviceDetail)
		admin.GET("/api/devices/:id/interfaces/:ifIndex/history", handler.GetInterfaceHistory)
		admin.GET("/api/devices/:id/interfaces/:ifIndex/chart", handler.GetInterfaceChart)
		admin.GET("/api/devices/:id/interfaces/:ifIndex/sflow-chart", handler.GetInterfaceSFlowChart)
		admin.GET("/api/devices/:id/status-history", handler.GetDeviceStatusHistory)

		admin.POST("/api/alerts/:id/acknowledge", handler.AcknowledgeAlert)
		admin.POST("/api/alerts/:id/snooze", handler.SnoozeAlert)
		admin.POST("/api/alerts/:id/unsnooze", handler.UnsnoozeAlert)
		admin.POST("/api/alerts/bulk-acknowledge", handler.BulkAcknowledgeAlerts)
		admin.POST("/api/alerts/bulk-acknowledge-filter", handler.BulkAcknowledgeAlertsByFilter)
		// AUDIT-143: bulk-snooze endpoints, mirroring the bulk-ack shape.
		admin.POST("/api/alerts/bulk-snooze", handler.BulkSnoozeAlerts)
		admin.POST("/api/alerts/bulk-snooze-filter", handler.BulkSnoozeAlertsByFilter)
		admin.POST("/api/alerts/:id/notes", handler.UpdateAlertNotes)
		// Source suppression is unified under Event Rules (v0.11.93): a temporary
		// flow_security suppress rule replaces the old per-IP Silence-Source path.
		admin.GET("/api/alerts/:id", handler.GetAlert)
		admin.GET("/api/alerts/:id/suggested-rule", handler.SuggestEventRuleForAlert)
		admin.GET("/api/flows/stats", handler.GetFlowStats)
		admin.GET("/api/flows/detections", handler.GetFlowDetections)
		admin.POST("/api/flows/detections/:id/ack", handler.AckFlowDetection)
		admin.GET("/api/noc/stream", handler.GetNOCStream)
		admin.GET("/api/noc/snapshot", handler.GetNOCSnapshot)
		// Manual threat-intel add/delete are shared with the dedicated Threat
		// Intelligence page (/admin/threat-intel); listing lives there via
		// /api/threat-intel/search. The Flows page no longer has feed UI, so the
		// old GET /api/flows/threat-intel listing endpoint was removed.
		admin.POST("/api/flows/threat-intel", handler.AddThreatIntel)
		admin.DELETE("/api/flows/threat-intel/:id", handler.DeleteThreatIntel)
		admin.GET("/api/threat-intel/search", handler.SearchThreatIntel)
		admin.GET("/api/threat-intel/lookup", handler.LookupThreatIntel)
		admin.GET("/api/geo/lookup", handler.LookupGeoBatch)
		admin.GET("/api/threat-intel/feeds", handler.GetThreatFeeds)
		// v0.11.46: admin-only feed control + storm-digest tuning (admin-gated via
		// adminOnlyRoutes below).
		admin.PATCH("/api/threat-intel/feeds/:source", handler.PatchThreatFeed)
		admin.PATCH("/api/threat-intel/global", handler.PatchThreatFeedsGlobal)
		admin.GET("/api/threat-intel/storm-tuning", handler.GetStormTuning)
		admin.PATCH("/api/threat-intel/storm-tuning", handler.PatchStormTuning)
		admin.GET("/api/alerts/stats", handler.GetAlertStats)
		admin.GET("/api/traps/stats", handler.GetTrapStats)
		admin.GET("/api/syslog/stats", handler.GetSyslogStats)
		admin.GET("/api/dashboard/stats", handler.GetDashboardStats)
		admin.GET("/api/dashboard/diag", handler.GetDeviceDataDiag)
		admin.GET("/api/dashboard/summary", handler.GetDashboardSummary)
		admin.GET("/api/dashboard/noisy", handler.GetNoisyDevices)
		admin.GET("/api/dashboard/health", handler.GetDashboardHealth)
		admin.GET("/api/system", handler.GetSystemHealth)

		admin.GET("/api/connections", handler.GetDeviceConnections)
		admin.GET("/api/connections/vpn-map", handler.GetVPNMapData)
		admin.GET("/api/connections/status-summary", handler.GetConnectionStatusSummary)
		admin.POST("/api/connections", handler.CreateDeviceConnection)
		admin.PUT("/api/connections/:id", handler.UpdateDeviceConnection)
		admin.DELETE("/api/connections/:id", handler.DeleteDeviceConnection)
		admin.GET("/api/connections/:id/detail", handler.GetConnectionDetail)
		admin.GET("/api/connections/:id/traffic", handler.GetConnectionTraffic)
		admin.GET("/api/connections/:id/flows", handler.GetConnectionFlows)
		admin.GET("/api/connections/:id/events", handler.GetConnectionEvents)
		admin.GET("/api/devices/:id/vpn/:tunnel/chart", handler.GetVPNTunnelChart)
		admin.GET("/api/devices/:id/security-stats", handler.GetDeviceSecurityStats)
		admin.GET("/api/devices/:id/sdwan-health", handler.GetDeviceSDWANHealth)
		admin.GET("/api/devices/:id/ha-status", handler.GetDeviceHAStatus)
		admin.GET("/api/devices/:id/config-history", handler.GetDeviceConfigHistory)
		admin.GET("/api/devices/:id/config-history/diff", handler.GetDeviceConfigDiff)
		admin.GET("/api/devices/:id/config-history/:revId", handler.GetDeviceConfigRevisionDownload)
		admin.GET("/api/devices/:id/config-history/:revId/view", handler.GetDeviceConfigRevision)
		admin.DELETE("/api/devices/:id/config-history/:revId", handler.DeleteDeviceConfigRevision)
		admin.GET("/api/devices/:id/process-history", handler.GetDeviceProcessHistory)
		admin.GET("/api/devices/:id/interface-errors", handler.GetDeviceInterfaceErrors)

		// Alert policies
		admin.GET("/api/alert-policies", handler.ListAlertPolicies)
		admin.POST("/api/alert-policies", handler.CreateAlertPolicy)
		admin.GET("/api/alert-policies/:id", handler.GetAlertPolicy)
		admin.PUT("/api/alert-policies/:id", handler.UpdateAlertPolicy)
		admin.DELETE("/api/alert-policies/:id", handler.DeleteAlertPolicy)
		admin.POST("/api/alert-policies/:id/clone", handler.CloneAlertPolicy)
		admin.PUT("/api/alert-policies/:id/rules", handler.BatchUpsertAlertRules)

		// Event rules (v35): unified vendor-aware alert/suppress rule engine.
		admin.GET("/api/event-rules", handler.ListEventRules)
		admin.GET("/api/event-rules/template", handler.GetEventRuleTemplate)
		admin.POST("/api/event-rules", handler.CreateEventRule)
		admin.POST("/api/event-rules/test", handler.TestEventRule)
		admin.PUT("/api/event-rules/:id", handler.UpdateEventRule)
		admin.DELETE("/api/event-rules/:id", handler.DeleteEventRule)

		// Event rule profiles (v48): Default > Site > Device toggle+rule chain.
		admin.GET("/api/event-rule-profiles", handler.ListEventRuleProfiles)
		admin.POST("/api/event-rule-profiles", handler.CreateEventRuleProfile)
		admin.GET("/api/event-rule-profiles/:id", handler.GetEventRuleProfile)
		admin.PUT("/api/event-rule-profiles/:id", handler.UpdateEventRuleProfile)
		admin.DELETE("/api/event-rule-profiles/:id", handler.DeleteEventRuleProfile)
		admin.POST("/api/event-rule-profiles/:id/clone", handler.CloneEventRuleProfile)
		admin.PUT("/api/event-rule-profiles/:id/toggles", handler.PutProfileToggles)
		admin.GET("/api/event-rule-profiles/:id/assignments", handler.GetEventProfileAssignments)
		admin.PUT("/api/event-rule-profiles/:id/assignments", handler.BatchAssignEventProfile)
		admin.GET("/api/alert-types", handler.ListAlertTypes)
		admin.PUT("/api/devices/:id/event-profile", handler.SetDeviceEventProfile)
		admin.PUT("/api/sites/:id/event-profile", handler.SetSiteEventProfile)
		admin.GET("/api/event-config/effective", handler.GetEffectiveEventConfig)

		// Device/Site alert configs
		admin.GET("/api/alert-config/effective", handler.GetEffectiveAlertConfig)
		admin.GET("/api/alert-config/overview", handler.GetAlertConfigOverview)
		admin.GET("/api/devices/:id/alert-config", handler.GetDeviceAlertConfig)
		admin.PUT("/api/devices/:id/alert-config", handler.UpsertDeviceAlertConfig)
		admin.DELETE("/api/devices/:id/alert-config", handler.DeleteDeviceAlertConfig)
		admin.GET("/api/sites/:id/alert-config", handler.GetSiteAlertConfig)
		admin.PUT("/api/sites/:id/alert-config", handler.UpsertSiteAlertConfig)
		admin.DELETE("/api/sites/:id/alert-config", handler.DeleteSiteAlertConfig)

		// Maintenance windows
		admin.GET("/api/maintenance-windows/active", handler.GetActiveMaintenanceWindows)
		admin.GET("/api/maintenance-windows", handler.ListMaintenanceWindows)
		admin.POST("/api/maintenance-windows", handler.CreateMaintenanceWindow)
		admin.PUT("/api/maintenance-windows/:id", handler.UpdateMaintenanceWindow)
		admin.DELETE("/api/maintenance-windows/:id", handler.DeleteMaintenanceWindow)

		admin.POST("/api/logout", handler.Logout)
		// User management (RBAC, P0-1) — admin-only via adminOnlyRoutes above;
		// /api/me is self-service so the SPA can gate UI by role.
		admin.GET("/api/me", handler.GetMe)
		// Self-service profile (v28): own email/display-name, and the
		// explicit MFA-onboarding decline. Both in selfServiceRoutes.
		admin.PUT("/api/me", handler.UpdateProfile)
		admin.POST("/api/me/mfa-decline", handler.DeclineMFAPrompt)
		// Self-service system-health dashboard layout (show/hide + order).
		admin.GET("/api/me/dashboard", handler.GetMyDashboardPrefs)
		admin.PUT("/api/me/dashboard", handler.SetMyDashboardPrefs)
		admin.GET("/api/users", handler.ListUsers)
		admin.POST("/api/users", handler.CreateUser)
		admin.PUT("/api/users/:id", handler.UpdateUser)
		admin.DELETE("/api/users/:id", handler.DeleteUser)
		admin.POST("/api/users/:id/reset-password", handler.ResetUserPassword)
		// TOTP 2FA (P0-3): self-service enrollment + admin-only reset.
		admin.POST("/api/2fa/setup", handler.Setup2FA)
		admin.POST("/api/2fa/verify", handler.Verify2FA)
		admin.POST("/api/2fa/disable", handler.Disable2FA)
		admin.POST("/api/users/:id/reset-2fa", handler.ResetUser2FA)
		// Scoped API tokens (P0-2) — admin-only; creation is session-only
		// (enforced in the handler: no token-mints-token).
		admin.GET("/api/tokens", handler.ListAPITokens)
		admin.POST("/api/tokens", handler.CreateAPIToken)
		admin.DELETE("/api/tokens/:id", handler.RevokeAPIToken)

		admin.GET("/api/settings", handler.GetSettings)
		admin.POST("/api/settings", handler.UpdateSettings)
		admin.POST("/api/settings/password", handler.ChangePassword)
		admin.POST("/api/settings/test-email", handler.TestEmail)
		admin.POST("/api/settings/test-webhook", handler.TestWebhook)
		admin.GET("/api/display-settings", handler.GetPublicDisplaySettings)

		admin.GET("/api/reports/preview", handler.PreviewReport)
		admin.POST("/api/reports/send", handler.SendReportNow)

		// IRC is an SPA page (folded into admin.html).
		admin.GET("/irc", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/api/irc/servers", handler.GetIRCServer)
		admin.POST("/api/irc/servers", handler.CreateIRCServer)
		admin.PUT("/api/irc/servers/:id", handler.UpdateIRCServer)
		admin.DELETE("/api/irc/servers/:id", handler.DeleteIRCServer)
		admin.POST("/api/irc/servers/:id/connect", handler.ConnectIRCServer)
		admin.POST("/api/irc/servers/:id/disconnect", handler.DisconnectIRCServer)
		admin.POST("/api/irc/servers/test", handler.TestIRCServer)

		admin.GET("/api/irc/channels", handler.GetIRCChannels)
		admin.POST("/api/irc/channels", handler.CreateIRCChannel)
		admin.PUT("/api/irc/channels/:id", handler.UpdateIRCChannel)
		admin.DELETE("/api/irc/channels/:id", handler.DeleteIRCChannel)

		admin.GET("/api/irc/commands", handler.GetIRCCommands)
		admin.POST("/api/irc/commands", handler.CreateIRCCommand)
		admin.PUT("/api/irc/commands/:id", handler.UpdateIRCCommand)
		admin.DELETE("/api/irc/commands/:id", handler.DeleteIRCCommand)

		admin.POST("/api/irc/send", handler.SendIRCMessage)
	}
}
