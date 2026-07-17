package handlers

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/auth"
	"firewall-mon/internal/classify"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/irc"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/snmp"
	"firewall-mon/internal/threatintel"
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
	geoResolver  *classify.GeoResolver
	threatMatch  threatintel.Holder
	nocHub       *nocHub
	version      string
	// startTime is the process boot time, used by GetSystemHealth to report
	// server uptime on the dashboard's Server Platform card.
	startTime time.Time
	// dashCache holds short-TTL, singleflight-deduped snapshots of the fleet-wide
	// dashboard health composite so many workstations / rapid refreshes compute it
	// at most once per TTL. Global aggregate only — never per-user/per-request.
	dashCache *ttlCache
	// db is the repository interface (database.Store), not the concrete
	// *database.Database god-object — handlers depend on the narrow method set
	// and can be unit-tested with a fake store. The runtime value is still the
	// GORM-backed *database.Database supplied by NewHandler.
	db database.Store
	mu sync.RWMutex

	// agentDropsLast tracks the last CUMULATIVE sFlow sample-pool drops
	// counter seen per agent, so recordAgentDrops (M2 of the 2026-07-01
	// audit) can fold per-batch deltas into flow_agent_drops. Guarded by
	// agentDropsMu; bounded by maxTrackedDropAgents.
	agentDropsMu   sync.Mutex
	agentDropsLast map[string]uint64

	// denyPatternCached is the TTL-cached block-policy-name glob used by the
	// syslog-ingest deny projection (Tranche 4 Phase 2), guarded by h.mu.
	denyPatternCached string
	denyPatternExpiry time.Time
}

func NewHandler(cfg *config.Config, authManager *auth.AuthManager, db *database.Database) *Handler {
	// Geo/ASN resolver for sFlow enrichment. Enabled by default with an embedded
	// free DB-IP Lite bundle; the optional paid MaxMind updater writes newer
	// databases into GeoIPDBDir which take precedence. A nil resolver is nil-safe,
	// so when geo is disabled the ingest path simply leaves the columns empty.
	geo, err := classify.NewGeoResolver(cfg.Server.GeoIPEnabled, cfg.Server.GeoIPDBDir, cfg.Server.GeoIPCacheDir)
	switch {
	case geo.Enabled() && err != nil:
		// One database opened, the other didn't: enrichment IS running, just with
		// reduced coverage. Don't report it as disabled (audit L4).
		log.Printf("geoip: partial load (%v) — enrichment enabled [%s] with reduced coverage", err, geo.Source())
	case geo.Enabled():
		log.Printf("geoip: geo/ASN enrichment enabled [%s]", geo.Source())
	case err != nil:
		log.Printf("geoip: %v — geo/ASN enrichment disabled", err)
	}
	h := &Handler{
		config:      cfg,
		authManager: authManager,
		uptimeTrack: uptime.NewUptimeTracker(cfg),
		geoResolver: geo,
		db:          db,
		startTime:   time.Now(),
		dashCache:   newTTLCache(),
	}
	// Load the initial threat-intel matcher from the DB. A background refresh
	// goroutine (cmd/api) reloads it periodically so feed edits + expiries apply.
	// Guard on the concrete *Database: tests construct handlers with a typed-nil
	// db, which is a non-nil Store interface, so the interface-level nil check in
	// RefreshThreatMatcher wouldn't catch it.
	if db != nil {
		h.RefreshThreatMatcher()
		h.nocHub = newNOCHub(db, nocSnapshotInterval)
	}
	return h
}

// RunNOCHub runs the NOC snapshot broadcaster until ctx is cancelled. Called once
// from a background goroutine in cmd/api so the live dashboard has data to stream.
func (h *Handler) RunNOCHub(ctx context.Context) {
	if h.nocHub != nil {
		h.nocHub.Run(ctx)
	}
}

// RefreshThreatMatcher rebuilds the in-memory threat-intel matcher from the
// active feed rows and swaps it in atomically. Safe to call concurrently with
// ingest lookups. Logged-and-ignored on DB error (the old matcher stays in use).
func (h *Handler) RefreshThreatMatcher() {
	if h.db == nil {
		return
	}
	// v0.11.46: the master switch is admin-UI-managed (env is only the default).
	// When feeds are off, the matcher is EMPTY — ingest stops threat-flagging
	// immediately — while the per-feed rows are kept in the DB so flipping the
	// master back on is instant (no re-fetch). Per-feed disable is enforced inside
	// GetActiveThreatIntel (and by purging that feed's rows).
	if !h.db.GetBoolSetting("threat_feeds_enabled", h.config.ThreatFeed.Enabled) {
		h.threatMatch.Store(threatintel.New(nil, time.Now()))
		return
	}
	rows, err := h.db.GetActiveThreatIntel()
	if err != nil {
		log.Printf("threat-intel: refresh failed: %v", err)
		return
	}
	h.threatMatch.Store(threatintel.New(rows, time.Now()))
}

// ReloadGeoIP re-stats the GeoLite2 databases and hot-swaps any that changed on
// disk, so a MaxMind update takes effect in the ingest path without a restart
// (audit L4). Nil-safe when geo is disabled. Intended for a periodic ticker.
func (h *Handler) ReloadGeoIP() {
	h.geoResolver.Reload()
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
func (h *Handler) reqDB(c *gin.Context) database.Store {
	if h.db == nil {
		return nil
	}
	return h.db.WithContextStore(c.Request.Context())
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

	// M8: surface the encryption key-check verdict. A rotated/lost
	// ENCRYPTION_KEY makes every stored secret silently undecryptable; the
	// poller/trap-receiver fail-fast on this, but the API stays up so an
	// operator can fix the key — so it reports the failure here (503) instead
	// of serving "healthy" while every SNMP poll quietly fails.
	encOK := true
	if h.db != nil {
		var encDetail string
		encOK, encDetail = h.db.EncryptionVerified()
		health["encryption"] = encOK
		if !encOK {
			health["encryption_error"] = encDetail
		}
	}

	if !dbOK || !encOK {
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
