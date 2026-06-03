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
	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/irc"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/secrets"
	"firewall-mon/internal/snmp"

	"github.com/gin-gonic/gin"
)

// ServerVersion is the build-baked server version. Bumped in CHANGELOG
// and exposed via GET /api/version so the admin UI can console-log it
// on every page load — that lets operators instantly verify whether
// their redeploy actually shipped (a browser refresh alone won't update
// embedded JS/HTML, since they're compiled into this binary).
const ServerVersion = "0.10.271"

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

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

	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Println("Database initialized")

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
		db.InitAdmin(cfg.Auth.AdminUsername, hashedPassword)
	}

	// Periodically prune expired login attempts to prevent unbounded map growth
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			authManager.PruneExpiredAttempts()
		}
	}()

	// Clear plaintext password from memory after initialization
	cfg.Auth.AdminPassword = ""

	handler := handlers.NewHandler(cfg, authManager, db)

	// Create alert manager for data ingestion handlers (syslog alerts, etc.)
	notif := notifier.NewNotifier(cfg)
	alertMgr := alerts.NewAlertManager(cfg, notif, db)
	alertMgr.RefreshThresholds(db.Gorm())
	handler.SetAlertManager(alertMgr)

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
	ircManager.Start()
	handler.SetIRCManager(ircManager)
	defer ircManager.Stop()

	setupRoutes(router, cfg, handler, authManager)

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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		// Don't log.Fatal: that would skip the deferred ircManager.Stop /
		// snmpClient.Close. Log the error and let main return so defers run.
		log.Printf("Server.Shutdown error: %v", err)
	}

	log.Println("Server exited")
}

func setupRoutes(router *gin.Engine, cfg *config.Config, handler *handlers.Handler, authManager *auth.AuthManager) {
	router.Use(middleware.SecureHeaders())
	router.Use(middleware.CORS(cfg))
	router.Use(middleware.RequestLogger())
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

	// Minimal SVG favicon to prevent 404
	router.GET("/favicon.ico", func(c *gin.Context) {
		svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#161b22"/><path d="M8 10h16M8 16h16M8 22h12" stroke="#58a6ff" stroke-width="2.5" stroke-linecap="round"/><circle cx="25" cy="22" r="3" fill="#3fb950"/></svg>`
		c.Data(http.StatusOK, "image/svg+xml", []byte(svg))
	})

	router.GET("/admin/login", func(c *gin.Context) {
		middleware.RenderHTML(c, http.StatusOK, "login.html", nil)
	})

	api := router.Group("/api")
	api.Use(middleware.RateLimiter(cfg))
	{
		api.GET("/health", handler.GetHealth)

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

		api.POST("/probes/register", handler.RegisterProbe)
		api.POST("/probes/heartbeat", handler.ProbeHeartbeat)

		// Probe data ingestion endpoints (rate limited, authenticated per-request)
		api.POST("/probes/:id/syslog", middleware.ProbeRateLimiter(), handler.ReceiveSyslogMessages)
		api.POST("/probes/:id/traps", middleware.ProbeRateLimiter(), handler.ReceiveTrapEvents)
		api.POST("/probes/:id/flows", middleware.ProbeRateLimiter(), handler.ReceiveFlowSamples)
		api.POST("/probes/:id/pings", middleware.ProbeRateLimiter(), handler.ReceivePingResults)
		api.POST("/probes/:id/system-status", middleware.ProbeRateLimiter(), handler.ReceiveSystemStatuses)
		api.POST("/probes/:id/interface-stats", middleware.ProbeRateLimiter(), handler.ReceiveInterfaceStats)
		api.POST("/probes/:id/vpn-status", middleware.ProbeRateLimiter(), handler.ReceiveVPNStatuses)
		api.POST("/probes/:id/hardware-sensors", middleware.ProbeRateLimiter(), handler.ReceiveHardwareSensors)
		api.POST("/probes/:id/processor-stats", middleware.ProbeRateLimiter(), handler.ReceiveProcessorStats)
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

		// Probe fetches its assigned devices
		api.GET("/probes/:id/devices", middleware.ProbeRateLimiter(), handler.GetProbeDevices)
	}

	admin := router.Group("/admin")
	admin.Use(middleware.AdminAuth(authManager))
	admin.Use(middleware.CSRFProtection(cfg))
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

		admin.GET("/reports", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/connections", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/probes", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "probes.html", nil)
		})

		admin.GET("/sites", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "sites.html", nil)
		})

		admin.GET("/probe-pending", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "probe-pending.html", nil)
		})

		admin.GET("/syslog", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/flows", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/interfaces", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/alerts", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "admin.html", nil)
		})

		admin.GET("/alert-policies", func(c *gin.Context) {
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
		admin.GET("/api/traps", handler.GetTraps)
		admin.GET("/api/uptime", handler.GetUptime)
		admin.POST("/api/uptime/reset", handler.ResetUptime)

		admin.GET("/api/devices", handler.GetDevices)
		admin.POST("/api/devices", handler.CreateDevice)
		admin.POST("/api/devices/test", handler.TestDeviceConnection)
		admin.PUT("/api/devices/:id", handler.UpdateDevice)
		admin.DELETE("/api/devices/:id", handler.DeleteDevice)

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
		admin.GET("/api/probes/pending", handler.GetPendingProbes)
		admin.POST("/api/probes/:id/approve", handler.ApproveProbe)
		admin.POST("/api/probes/:id/reject", handler.RejectProbe)
		admin.POST("/api/probes/:id/regenerate-key", handler.RegenerateProbeKey)

		admin.GET("/api/syslog", handler.GetSyslogMessages)
		admin.GET("/api/syslog/:id", handler.GetSyslogMessage)
		admin.GET("/api/flows", handler.GetFlowSamples)
		admin.GET("/api/probes/:id/stats", handler.GetProbeStats)

		admin.GET("/api/devices/:id/detail", handler.GetDeviceDetail)
		admin.GET("/api/devices/:id/interfaces/:ifIndex/history", handler.GetInterfaceHistory)
		admin.GET("/api/devices/:id/interfaces/:ifIndex/chart", handler.GetInterfaceChart)
		admin.GET("/api/devices/:id/status-history", handler.GetDeviceStatusHistory)
		admin.GET("/api/interfaces", handler.GetAllInterfaces)

		admin.POST("/api/alerts/:id/acknowledge", handler.AcknowledgeAlert)
		admin.POST("/api/alerts/:id/snooze", handler.SnoozeAlert)
		admin.POST("/api/alerts/:id/unsnooze", handler.UnsnoozeAlert)
		admin.POST("/api/alerts/bulk-acknowledge", handler.BulkAcknowledgeAlerts)
		admin.POST("/api/alerts/bulk-acknowledge-filter", handler.BulkAcknowledgeAlertsByFilter)
		admin.POST("/api/alerts/:id/notes", handler.UpdateAlertNotes)
		admin.GET("/api/alerts/:id", handler.GetAlert)
		admin.GET("/api/flows/stats", handler.GetFlowStats)
		admin.GET("/api/alerts/stats", handler.GetAlertStats)
		admin.GET("/api/traps/stats", handler.GetTrapStats)
		admin.GET("/api/syslog/stats", handler.GetSyslogStats)
		admin.GET("/api/dashboard/stats", handler.GetDashboardStats)
		admin.GET("/api/dashboard/diag", handler.GetDeviceDataDiag)

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

		// Device/Site alert configs
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

		admin.GET("/api/settings", handler.GetSettings)
		admin.POST("/api/settings", handler.UpdateSettings)
		admin.POST("/api/settings/password", handler.ChangePassword)
		admin.POST("/api/settings/test-email", handler.TestEmail)
		admin.POST("/api/settings/test-webhook", handler.TestWebhook)
		admin.GET("/api/display-settings", handler.GetPublicDisplaySettings)

		admin.GET("/api/reports/preview", handler.PreviewReport)
		admin.POST("/api/reports/send", handler.SendReportNow)

		admin.GET("/irc", func(c *gin.Context) {
			middleware.RenderHTML(c, http.StatusOK, "irc.html", nil)
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
