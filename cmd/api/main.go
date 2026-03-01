package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"firewall-mon/internal/api/handlers"
	"firewall-mon/internal/api/middleware"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
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

	snmpClient, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("Warning: Failed to connect to SNMP: %v", err)
	} else {
		handler.SetSNMPClient(snmpClient)
		defer snmpClient.Close()
	}

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

	router.Static("/static", "./static")
	router.LoadHTMLGlob("./web/**/*.html")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	router.GET("/admin/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	api := router.Group("/api")
	{
		api.GET("/health", handler.GetHealth)
		api.GET("/public/dashboard", handler.GetPublicDashboard)
		api.GET("/public/interfaces", handler.GetPublicInterfaces)
		api.GET("/public/display-settings", handler.GetPublicDisplaySettings)

		api.POST("/auth/login", middleware.LoginRateLimiter(), handler.Login)

		api.POST("/probes/register", handler.RegisterProbe)
		api.POST("/probes/heartbeat", handler.ProbeHeartbeat)

		// Probe data ingestion endpoints (no admin auth - probe-facing)
		api.POST("/probes/:id/syslog", handler.ReceiveSyslogMessages)
		api.POST("/probes/:id/traps", handler.ReceiveTrapEvents)
		api.POST("/probes/:id/flows", handler.ReceiveFlowSamples)
		api.POST("/probes/:id/pings", handler.ReceivePingResults)
		api.POST("/probes/:id/system-status", handler.ReceiveSystemStatuses)
		api.POST("/probes/:id/interface-stats", handler.ReceiveInterfaceStats)

		// Probe fetches its assigned devices
		api.GET("/probes/:id/devices", handler.GetProbeDevices)
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
			log.Println("DEBUG: Serving sites.html")
			c.HTML(http.StatusOK, "sites.html", nil)
		})

		admin.GET("/probe-pending", func(c *gin.Context) {
			log.Println("DEBUG: Serving probe-pending.html")
			c.HTML(http.StatusOK, "probe-pending.html", nil)
		})

		admin.GET("/syslog", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/flows", func(c *gin.Context) {
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

		admin.GET("/api/connections", handler.GetDeviceConnections)
		admin.POST("/api/connections", handler.CreateDeviceConnection)
		admin.PUT("/api/connections/:id", handler.UpdateDeviceConnection)
		admin.DELETE("/api/connections/:id", handler.DeleteDeviceConnection)

		admin.POST("/api/logout", handler.Logout)

		admin.GET("/api/settings", handler.GetSettings)
		admin.POST("/api/settings", handler.UpdateSettings)
		admin.POST("/api/settings/password", handler.ChangePassword)
		admin.GET("/api/display-settings", handler.GetPublicDisplaySettings)
	}
}
