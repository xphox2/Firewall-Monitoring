package handlers

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/irc"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/snmp"
	"firewall-mon/internal/uptime"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	config       *config.Config
	authManager  *auth.AuthManager
	snmpClient   *snmp.SNMPClient
	uptimeTrack  *uptime.UptimeTracker
	alertManager *alerts.AlertManager
	ircManager   *irc.Manager
	notifier     *notifier.Notifier
	version      string
	db           *database.Database
	mu           sync.RWMutex
}

func NewHandler(cfg *config.Config, authManager *auth.AuthManager, db *database.Database) *Handler {
	return &Handler{
		config:      cfg,
		authManager: authManager,
		uptimeTrack: uptime.NewUptimeTracker(cfg),
		db:          db,
	}
}

// reqDB returns the request-scoped database handle: h.db bound to the request
// context (AUDIT-032/079) so a client disconnect cancels in-flight queries and
// frees the pooled connection instead of leaving it checked out — the
// dashboard-polling pool-exhaustion outage. It returns nil exactly when h.db is
// nil, so the existing `httputil.RequireDB(c, ...)` / `== nil` / `!= nil` guards
// keep working unchanged when callers swap `h.db` for `db := h.reqDB(c)`.
//
// Browser-facing handlers (admin UI, public dashboard, auth) use this. The
// probe-ingestion handlers (handlers_data.go) deliberately keep using h.db (the
// durable background context) so a probe's in-flight write over a flaky WAN is
// never cancelled mid-flight.
func (h *Handler) reqDB(c *gin.Context) *database.Database {
	if h.db == nil {
		return nil
	}
	return h.db.WithContext(c.Request.Context())
}

func (h *Handler) SetIRCManager(mgr *irc.Manager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ircManager = mgr
}

func (h *Handler) GetIRCManager() *irc.Manager {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ircManager
}

func (h *Handler) SetAlertManager(am *alerts.AlertManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.alertManager = am
}

func (h *Handler) SetSNMPClient(client *snmp.SNMPClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.snmpClient = client
}

// SetNotifier wires the notifier used for on-demand report sends from the
// admin panel (the scheduled reports run in the poller process).
func (h *Handler) SetNotifier(n *notifier.Notifier) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notifier = n
}

// SetVersion records the server version stamped into rendered reports.
func (h *Handler) SetVersion(v string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.version = v
}

// healthCheckDBTimeout caps the time the /api/health endpoint will wait
// for a DB ping. AUDIT-091: the previous GetHealth was a no-op (just
// returned {"status":"healthy"} with no actual check), so a container
// running with a dead Postgres would still report healthy. With this
// timeout, a hung DB makes the endpoint return 503 inside ~1 second,
// and Docker's HEALTHCHECK (which uses `--timeout=3s` in the Dockerfile)
// reports "unhealthy" in time for a restart loop to kick in.
const healthCheckDBTimeout = 1 * time.Second

func (h *Handler) GetHealth(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	health := gin.H{
		"status":         "healthy",
		"snmp_connected": h.snmpClient != nil,
		"database":       h.db != nil,
	}
	// AUDIT-091 (collocated with AUDIT-045): actually ping the DB with a
	// bounded timeout. The 1-second deadline is tight enough that a
	// wedged DB doesn't keep the health endpoint slow (which would mask
	// the failure in a longer Docker HEALTHCHECK timeout), and loose
	// enough that a normal Postgres roundtrip completes with margin.
	//
	// We intentionally do NOT also test the SNMP client here. SNMP
	// connectivity is by definition a polling concern, not a startup
	// concern — a target device being down is not a reason to mark the
	// API unhealthy and trigger a container restart loop. The
	// "snmp_connected" boolean above is informational for operators
	// reading the JSON, not a health gate.
	dbOK := true
	if h.db != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), healthCheckDBTimeout)
		defer cancel()
		if err := h.db.Gorm().WithContext(ctx).Exec("SELECT 1").Error; err != nil {
			dbOK = false
			health["db_error"] = err.Error()
		}
	} else {
		dbOK = false
		health["db_error"] = "database not initialized"
	}
	health["database"] = dbOK
	if !dbOK {
		health["status"] = "unhealthy"
		c.JSON(http.StatusServiceUnavailable, response.Success(health))
		return
	}
	c.JSON(http.StatusOK, response.Success(health))
}

// isBlockedIP reports whether an IP is a forbidden SSRF target. Delegates to
// httputil.IsBlockedIP, which (AUDIT-020) also covers multicast, CGNAT
// (100.64.0.0/10) and 0.0.0.0/8 — ranges the raw net.IP predicates miss.
func isBlockedIP(ip net.IP) bool {
	return httputil.IsBlockedIP(ip)
}

// isValidExternalIP validates that the IP/hostname does not resolve to a blocked address
// to prevent SSRF attacks against internal services.
func isValidExternalIP(ipStr string) bool {
	// Try parsing as IP first
	ip := net.ParseIP(ipStr)
	if ip != nil {
		return !isBlockedIP(ip)
	}

	// It's a hostname - resolve it and validate all resolved IPs
	addrs, err := net.LookupHost(ipStr)
	if err != nil {
		// Cannot resolve - reject to be safe
		return false
	}
	for _, addr := range addrs {
		resolved := net.ParseIP(addr)
		if resolved != nil && isBlockedIP(resolved) {
			return false
		}
	}
	return len(addrs) > 0
}

var validVendors = map[string]bool{
	"fortigate": true,
	"paloalto":  true,
	"cisco_asa": true,
	"sonicwall": true,
	"firewalla": true,
	"pfsense":   true,
	"opnsense":  true,
	"generic":   true,
}

func isValidVendor(vendor string) bool {
	return validVendors[vendor]
}
