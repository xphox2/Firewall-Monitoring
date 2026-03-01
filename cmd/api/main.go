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

	"fortiGate-Mon/internal/alerts"
	"fortiGate-Mon/internal/api/handlers"
	"fortiGate-Mon/internal/api/middleware"
	"fortiGate-Mon/internal/auth"
	"fortiGate-Mon/internal/config"
	"fortiGate-Mon/internal/database"
	"fortiGate-Mon/internal/notifier"
	"fortiGate-Mon/internal/snmp"

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

	notif := notifier.NewNotifier(cfg)
	_ = alerts.NewAlertManager(cfg, notif)

	setupRoutes(router, cfg, handler, authManager)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
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
	router.Use(middleware.GetRealIP())

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

		api.POST("/auth/login", handler.Login)
		api.POST("/auth/logout", handler.Logout)
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

		admin.GET("/settings", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/connections", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", nil)
		})

		admin.GET("/api/dashboard", handler.GetDashboardAll)
		admin.GET("/api/dashboard/:id", handler.GetAdminDashboard)
		admin.GET("/api/alerts", handler.GetAlerts)
		admin.GET("/api/traps", handler.GetTraps)
		admin.GET("/api/uptime", handler.GetUptime)
		admin.POST("/api/uptime/reset", handler.ResetUptime)

		admin.GET("/api/fortigates", handler.GetFortiGates)
		admin.POST("/api/fortigates", handler.CreateFortiGate)
		admin.POST("/api/fortigates/test", handler.TestDeviceConnection)
		admin.PUT("/api/fortigates/:id", handler.UpdateFortiGate)
		admin.DELETE("/api/fortigates/:id", handler.DeleteFortiGate)

		admin.GET("/api/connections", handler.GetFortiGateConnections)
		admin.POST("/api/connections", handler.CreateFortiGateConnection)
		admin.PUT("/api/connections/:id", handler.UpdateFortiGateConnection)
		admin.DELETE("/api/connections/:id", handler.DeleteFortiGateConnection)

		admin.GET("/api/settings", handler.GetSettings)
		admin.POST("/api/settings", handler.UpdateSettings)
		admin.POST("/api/settings/password", handler.ChangePassword)
		admin.GET("/api/display-settings", handler.GetPublicDisplaySettings)
	}
}
