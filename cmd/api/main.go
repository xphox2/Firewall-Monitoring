package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	"firewall-mon/internal/snmp"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	if cfg.Server.JWTSecretKey == "" {
		secret, err := auth.GenerateSecureToken(32)
		if err != nil {
			log.Fatal("Failed to generate JWT secret")
		}
		cfg.Server.JWTSecretKey = secret
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies(nil) // Do not trust proxy headers for client IP

	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Println("Database initialized")

	authManager := auth.NewAuthManager(cfg, db)

	// Initialize admin in database
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

	if cfg.IsGeneratedPassword() {
		log.Println("========================================")
		log.Println("AUTO-GENERATED ADMIN PASSWORD")
		log.Printf("Username: %s", cfg.Auth.AdminUsername)
		log.Printf("Password has been auto-generated.")
		log.Println("Check container logs at startup or set ADMIN_PASSWORD env var.")
		// Print password only once to stderr for retrieval
		fmt.Fprintf(os.Stderr, "Generated admin password: %s\n", cfg.Auth.AdminPassword)
		log.Println("========================================")
	}

	// Clear plaintext password from memory after initialization
	cfg.Auth.AdminPassword = ""

	handler := handlers.NewHandler(cfg, authManager, db)

	// Create alert manager for data ingestion handlers (syslog alerts, etc.)
	notif := notifier.NewNotifier(cfg)
	alertMgr := alerts.NewAlertManager(cfg, notif, db)
	alertMgr.RefreshThresholds(db.Gorm())
	handler.SetAlertManager(alertMgr)

	snmpClient, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("Warning: Failed to connect to SNMP: %v", err)
	} else {
		handler.SetSNMPClient(snmpClient)
		defer snmpClient.Close()
	}

	ircManager := irc.NewManager(db.Gorm())
	ircManager.SetStatusProvider(func() (map[string]interface{}, error) {
		var deviceCount, onlineCount, offlineCount, alertCount int64
		db.Gorm().Model(&models.Device{}).Count(&deviceCount)
		db.Gorm().Model(&models.Device{}).Where("status = ?", "online").Count(&onlineCount)
		db.Gorm().Model(&models.Device{}).Where("status = ?", "offline").Count(&offlineCount)
		db.Gorm().Model(&models.Alert{}).Where("acknowledged = ?", false).Count(&alertCount)

		var devices []models.Device
		db.Gorm().Find(&devices)
		var cpuAvg, memAvg float64
		var totalSessions int
		if len(devices) > 0 {
			var totalCPU, totalMem float64
			for _, d := range devices {
				var status models.SystemStatus
				if err := db.Gorm().Where("device_id = ?", d.ID).Order("timestamp DESC").First(&status).Error; err == nil {
					totalCPU += status.CPUUsage
					totalMem += status.MemoryUsage
					totalSessions += status.SessionCount
				}
			}
			cpuAvg = totalCPU / float64(len(devices))
			memAvg = totalMem / float64(len(devices))
		}

		var vpnUp, vpnTotal int64
		db.Gorm().Model(&models.VPNStatus{}).
			Where("timestamp = (SELECT MAX(v2.timestamp) FROM vpn_status v2 WHERE v2.device_id = vpn_status.device_id AND v2.tunnel_name = vpn_status.tunnel_name)").
			Count(&vpnTotal)
		db.Gorm().Model(&models.VPNStatus{}).
			Where("status = ? AND timestamp = (SELECT MAX(v2.timestamp) FROM vpn_status v2 WHERE v2.device_id = vpn_status.device_id AND v2.tunnel_name = vpn_status.tunnel_name)", "up").
			Count(&vpnUp)

		return map[string]interface{}{
			"device_count":    int(deviceCount),
			"online_devices":  int(onlineCount),
			"offline_devices": int(offlineCount),
			"alert_count":     int(alertCount),
			"cpu_avg":         cpuAvg,
			"memory_avg":      memAvg,
			"sessions":        totalSessions,
			"vpn_up":          int(vpnUp),
			"vpn_total":       int(vpnTotal),
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
		Addr:           fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:        router,
		ReadTimeout:    cfg.Server.ReadTimeout,
		WriteTimeout:   cfg.Server.WriteTimeout,
		IdleTimeout:    cfg.Server.IdleTimeout,
		MaxHeaderBytes: 1 << 16, // 64KB
	}

	go func() {
		log.Printf("Server starting on %s:%s", cfg.Server.Host, cfg.Server.Port)
		if cfg.Server.EnableTLS {
			if err := server.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}

	log.Println("Server exited")
}

func setupRoutes(router *gin.Engine, cfg *config.Config, handler *handlers.Handler, authManager *auth.AuthManager) {
	router.Use(middleware.SecureHeaders())
	router.Use(middleware.RequestLogger())
	router.Use(middleware.RateLimiter(cfg))
	router.Use(middleware.BodySizeLimit(5 << 20)) // 5MB max request body

	subFS, _ := fs.Sub(staticFiles, "static")
	router.StaticFS("/static", http.FS(subFS))
	router.LoadHTMLGlob("./web/**/*.html")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// Minimal SVG favicon to prevent 404
	router.GET("/favicon.ico", func(c *gin.Context) {
		svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#161b22"/><path d="M8 10h16M8 16h16M8 22h12" stroke="#58a6ff" stroke-width="2.5" stroke-linecap="round"/><circle cx="25" cy="22" r="3" fill="#3fb950"/></svg>`
		c.Data(http.StatusOK, "image/svg+xml", []byte(svg))
	})

	router.GET("/admin/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	api := router.Group("/api")
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

		// Probe fetches its assigned devices
		api.GET("/probes/:id/devices", middleware.ProbeRateLimiter(), handler.GetProbeDevices)
	}

	admin := router.Group("/admin")
	admin.Use(middleware.AdminAuth(authManager))
	admin.Use(middleware.CSRFProtection(cfg))
	{
		admin.GET("", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/dashboard", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/devices", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/settings", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/connections", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/probes", func(c *gin.Context) {
			c.HTML(http.StatusOK, "probes.html", nil)
		})

		admin.GET("/sites", func(c *gin.Context) {
			c.HTML(http.StatusOK, "sites.html", nil)
		})

		admin.GET("/probe-pending", func(c *gin.Context) {
			c.HTML(http.StatusOK, "probe-pending.html", nil)
		})

		admin.GET("/syslog", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/flows", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/interfaces", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/alerts", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/traps", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/network", func(c *gin.Context) {
			c.HTML(http.StatusOK, "network.html", nil)
		})

		admin.GET("/devices/:id", func(c *gin.Context) {
			c.HTML(http.StatusOK, "device-detail.html", nil)
		})

		admin.GET("/connections/:id", func(c *gin.Context) {
			c.HTML(http.StatusOK, "connection-detail.html", nil)
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
		admin.GET("/api/flows", handler.GetFlowSamples)
		admin.GET("/api/probes/:id/stats", handler.GetProbeStats)

		admin.GET("/api/devices/:id/detail", handler.GetDeviceDetail)
		admin.GET("/api/devices/:id/interfaces/:ifIndex/history", handler.GetInterfaceHistory)
		admin.GET("/api/devices/:id/interfaces/:ifIndex/chart", handler.GetInterfaceChart)
		admin.GET("/api/devices/:id/status-history", handler.GetDeviceStatusHistory)
		admin.GET("/api/interfaces", handler.GetAllInterfaces)

		admin.POST("/api/alerts/:id/acknowledge", handler.AcknowledgeAlert)
		admin.GET("/api/flows/stats", handler.GetFlowStats)
		admin.GET("/api/alerts/stats", handler.GetAlertStats)
		admin.GET("/api/traps/stats", handler.GetTrapStats)
		admin.GET("/api/syslog/stats", handler.GetSyslogStats)
		admin.GET("/api/dashboard/stats", handler.GetDashboardStats)
		admin.GET("/api/dashboard/diag", handler.GetDeviceDataDiag)

		admin.GET("/api/connections", handler.GetDeviceConnections)
		admin.GET("/api/connections/vpn-map", handler.GetVPNMapData)
		admin.POST("/api/connections", handler.CreateDeviceConnection)
		admin.PUT("/api/connections/:id", handler.UpdateDeviceConnection)
		admin.DELETE("/api/connections/:id", handler.DeleteDeviceConnection)
		admin.GET("/api/connections/:id/detail", handler.GetConnectionDetail)
		admin.GET("/api/connections/:id/traffic", handler.GetConnectionTraffic)
		admin.GET("/api/connections/:id/flows", handler.GetConnectionFlows)
		admin.GET("/api/devices/:id/vpn/:tunnel/chart", handler.GetVPNTunnelChart)
		admin.GET("/api/devices/:id/security-stats", handler.GetDeviceSecurityStats)
		admin.GET("/api/devices/:id/sdwan-health", handler.GetDeviceSDWANHealth)
		admin.GET("/api/devices/:id/ha-status", handler.GetDeviceHAStatus)

		admin.POST("/api/logout", handler.Logout)

		admin.GET("/api/settings", handler.GetSettings)
		admin.POST("/api/settings", handler.UpdateSettings)
		admin.POST("/api/settings/password", handler.ChangePassword)
		admin.POST("/api/settings/test-email", handler.TestEmail)
		admin.POST("/api/settings/test-webhook", handler.TestWebhook)
		admin.GET("/api/display-settings", handler.GetPublicDisplaySettings)

		admin.GET("/irc", func(c *gin.Context) {
			c.HTML(http.StatusOK, "irc.html", nil)
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
