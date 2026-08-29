package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// validConnectionTypes is the server-side allowlist for the client-settable
// connection_type field (AUDIT-184: an unvalidated value was rendered into
// innerHTML by the badge renderers — stored XSS). The authoritative set is the
// union of connectionFamily's cases (internal/database/connection_detail.go:
// tunnel = ipsec/ssl/gre/tunnel, overlay = vxlan/l3ipvlan, direct =
// ethernet/lag/l2vlan/bridge/wan, offnet) and every value the poller's
// auto-detection emits. The admin UI's select is a strict SUBSET of this
// (admin.html omits ethernet/bridge/offnet), so the server list must be this
// superset — otherwise editing an auto-detected ethernet link's notes together
// with its type would 400.
var validConnectionTypes = map[string]bool{
	"ipsec": true, "ssl": true, "gre": true, "tunnel": true,
	"vxlan": true, "l3ipvlan": true,
	"ethernet": true, "lag": true, "l2vlan": true, "bridge": true, "wan": true,
	"offnet": true,
}

func (h *Handler) GetConnectionStatusSummary(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(map[string]interface{}{
			"connections": []interface{}{},
			"devices":     []interface{}{},
		}))
		return
	}

	conns, err := db.GetConnectionStatuses()
	if err != nil {
		httputil.InternalError(c, "Failed to get connection statuses", err)
		return
	}

	devs, err := db.GetDeviceStatuses()
	if err != nil {
		httputil.InternalError(c, "Failed to get device statuses", err)
		return
	}

	// Attach each device's worst open-alert severity so the connection map can
	// pulse alerting nodes. Best-effort: a failure here just omits the overlay
	// (the map still shows online/offline borders and down-connection edges).
	if sev, err := db.GetDeviceAlertSeverities(); err == nil {
		for _, dev := range devs {
			if id := mapUint(dev["id"]); id != 0 {
				dev["alert_severity"] = sev[id]
			}
		}
	}

	c.JSON(http.StatusOK, response.Success(map[string]interface{}{
		"connections": conns,
		"devices":     devs,
	}))
}

// mapUint coerces a value scanned from a map[string]interface{} row (GORM uses
// int64/uint/int depending on the driver) into a uint. Returns 0 if not numeric.
func mapUint(v interface{}) uint {
	switch n := v.(type) {
	case uint:
		return n
	case int64:
		return uint(n)
	case int:
		return uint(n)
	case uint64:
		return uint(n)
	case int32:
		return uint(n)
	default:
		return 0
	}
}

func (h *Handler) GetConnectionEvents(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var conn models.DeviceConnection
	if err := db.Gorm().First(&conn, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Connection not found"))
		return
	}

	// Unified parsing (v0.10.217, bundle D2). The previous inline cap of
	// 720 hours (30 days) was lower than the shared 8760 cap — left in
	// place for now to avoid widening this endpoint's row set without
	// product review. Migrated to httputil.ParseHours by manual clamp.
	hours := httputil.ParseHours(c)
	if hours > 720 {
		hours = 720
	}

	events, err := db.GetConnectionEvents(conn.SourceDeviceID, conn.DestDeviceID, hours)
	if err != nil {
		httputil.InternalError(c, "Failed to get events", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(events))
}

func (h *Handler) GetDeviceConnections(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]models.DeviceConnection{}))
		return
	}

	connections, err := db.GetAllConnections()
	if err != nil {
		httputil.InternalError(c, "Failed to get connections", err)
		return
	}

	// The preloaded endpoint devices carry encrypted credential columns —
	// mask them like every other device GET (they leaked ciphertext before).
	httputil.RedactConnections(connections)
	c.JSON(http.StatusOK, response.Success(connections))
}

func (h *Handler) CreateDeviceConnection(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var conn models.DeviceConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// Drop any client-supplied embedded device objects: GORM's Create would
	// upsert them as associations, and the response would echo them back.
	// Endpoints are referenced by ID only.
	conn.SourceDevice = nil
	conn.DestDevice = nil

	// AUDIT API1: reset the server-owned primary key so a client can't set it.
	// A client-supplied ID inserts at that PK and desyncs the Postgres identity
	// sequence (later auto-increment inserts then collide); every sibling create
	// handler already zeroes this. (DeviceConnection has no CreatedAt/UpdatedAt.)
	conn.ID = 0

	// AUDIT-184: connection_type is rendered by the badge helpers, so it must
	// come from the allowlist. Empty means "not provided" — apply the GORM
	// column default explicitly so validation has a concrete value.
	if conn.ConnectionType == "" {
		conn.ConnectionType = "ipsec"
	}
	if !validConnectionTypes[conn.ConnectionType] {
		c.JSON(http.StatusBadRequest, response.Error("Invalid connection type"))
		return
	}

	// AUDIT-184 (second vector): match_method is a server-owned field written
	// only by the poller's auto-detection, but ShouldBindJSON let a client set
	// it to arbitrary text that the detail panels render. Reset it so the GORM
	// default applies.
	conn.MatchMethod = ""

	// Validate required FK references
	if conn.SourceDeviceID == 0 || conn.DestDeviceID == 0 {
		c.JSON(http.StatusBadRequest, response.Error("Source and destination device IDs are required"))
		return
	}
	if conn.SourceDeviceID == conn.DestDeviceID {
		c.JSON(http.StatusBadRequest, response.Error("Source and destination cannot be the same device"))
		return
	}
	if _, err := db.GetDevice(conn.SourceDeviceID); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Source device not found"))
		return
	}
	if _, err := db.GetDevice(conn.DestDeviceID); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Destination device not found"))
		return
	}

	conn.Status = "unknown"
	conn.AutoDetected = false
	if err := db.CreateConnection(&conn); err != nil {
		httputil.InternalError(c, "Failed to create connection", err)
		return
	}

	c.JSON(http.StatusCreated, response.Success(conn))
}

func (h *Handler) UpdateDeviceConnection(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var conn models.DeviceConnection
	if err := db.Gorm().First(&conn, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Connection not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":             true,
		"source_device_id": true,
		"dest_device_id":   true,
		"description":      true,
		"connection_type":  true,
		"notes":            true,
		"status":           true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// Validate status enum if provided
	if statusVal, ok := updates["status"]; ok {
		validStatuses := map[string]bool{"unknown": true, "up": true, "down": true}
		if s, isStr := statusVal.(string); !isStr || !validStatuses[s] {
			c.JSON(http.StatusBadRequest, response.Error("Invalid status value"))
			return
		}
	}

	// AUDIT-184: validate connection_type against the allowlist if provided —
	// the badge renderers interpolate it into innerHTML, so an arbitrary string
	// here was a stored-XSS vector.
	if ctVal, ok := updates["connection_type"]; ok {
		if s, isStr := ctVal.(string); !isStr || !validConnectionTypes[s] {
			c.JSON(http.StatusBadRequest, response.Error("Invalid connection type"))
			return
		}
	}

	// Validate FK references if being updated
	if srcVal, ok := updates["source_device_id"]; ok {
		srcID, isNum := srcVal.(float64)
		if !isNum || srcID < 1 {
			c.JSON(http.StatusBadRequest, response.Error("Invalid source device ID"))
			return
		}
		if _, err := db.GetDevice(uint(srcID)); err != nil {
			c.JSON(http.StatusBadRequest, response.Error("Source device not found"))
			return
		}
	}
	if dstVal, ok := updates["dest_device_id"]; ok {
		dstID, isNum := dstVal.(float64)
		if !isNum || dstID < 1 {
			c.JSON(http.StatusBadRequest, response.Error("Invalid destination device ID"))
			return
		}
		if _, err := db.GetDevice(uint(dstID)); err != nil {
			c.JSON(http.StatusBadRequest, response.Error("Destination device not found"))
			return
		}
	}

	filteredUpdates := httputil.FilterAllowedFields(updates, allowedFields)

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("No valid fields to update"))
		return
	}

	// Validate source and dest won't be the same after update
	effectiveSrc := conn.SourceDeviceID
	effectiveDst := conn.DestDeviceID
	if srcVal, ok := filteredUpdates["source_device_id"]; ok {
		if srcID, isNum := srcVal.(float64); isNum {
			effectiveSrc = uint(srcID)
		}
	}
	if dstVal, ok := filteredUpdates["dest_device_id"]; ok {
		if dstID, isNum := dstVal.(float64); isNum {
			effectiveDst = uint(dstID)
		}
	}
	if effectiveSrc == effectiveDst {
		c.JSON(http.StatusBadRequest, response.Error("Source and destination cannot be the same device"))
		return
	}

	if err := db.Gorm().Model(&conn).Updates(filteredUpdates).Error; err != nil {
		httputil.InternalError(c, "Failed to update connection", err)
		return
	}

	// Re-fetch to return fresh data with preloaded relations
	var updated models.DeviceConnection
	if err := db.Gorm().Preload("SourceDevice").Preload("DestDevice").First(&updated, id).Error; err != nil {
		c.JSON(http.StatusOK, response.Success(conn))
		return
	}
	httputil.RedactConnection(&updated)
	c.JSON(http.StatusOK, response.Success(updated))
}

func (h *Handler) DeleteDeviceConnection(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	result := db.Gorm().Delete(&models.DeviceConnection{}, id)
	if result.Error != nil {
		httputil.InternalError(c, "Failed to delete connection", result.Error)
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, response.Error("Connection not found"))
		return
	}

	c.JSON(http.StatusOK, response.Message("Connection deleted"))
}

func (h *Handler) GetConnectionDetail(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	detail, err := db.GetConnectionDetail(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Connection not found"))
		return
	}
	httputil.RedactConnection(&detail.Connection)
	c.JSON(http.StatusOK, response.Success(detail))
}

func (h *Handler) GetConnectionTraffic(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	hours := parseTrafficRangeHours(c.DefaultQuery("range", "24"))
	data, err := db.GetConnectionTraffic(id, hours)
	if err != nil {
		// Log the parsed hours, not the raw query param (log-injection hygiene).
		log.Printf("GetConnectionTraffic(%d, %gh) error: %v", id, hours, err)
		httputil.InternalError(c, "Failed to get traffic data", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(data))
}

// parseTrafficRangeHours converts the connection-traffic range param to a
// lookback in hours. Accepts the legacy launch tokens and numeric hours — the
// values the detail page's range dropdown actually sends (0.25 … 8760); the
// pre-fix whitelist recognized neither form the dropdown used, so every
// selection silently served the 24h window. Invalid or non-positive input
// falls back to 24; the DB layer clamps the ceiling to its maxChartWindow.
func parseTrafficRangeHours(s string) float64 {
	switch s {
	case "1h":
		return 1
	case "24h":
		return 24
	case "7d":
		return 168
	case "30d":
		return 720
	}
	if h, err := strconv.ParseFloat(s, 64); err == nil && h > 0 {
		return h
	}
	return 24
}

// GetVPNGroupChart returns one series for a whole LOGICAL tunnel on one device.
//
// A tunnel is reported as several vpn_status rows under unrelated names — a
// FortiGate's SSH row carries the provisioned name but no counters, its SNMP
// sibling carries the counters under a synthesized name — so charting per name
// shows a fraction of the traffic, or an empty series. This resolves the group's
// member names server-side and sums their per-bucket deltas.
//
// The group is a QUERY parameter, deliberately, not a path segment. Tunnel
// names are device-supplied text and child names embed selectors; gin routes on
// the DECODED path, so an escaped "/" becomes a real separator and the request
// 404s. Keeping it out of the path removes that whole failure class rather than
// relying on every future name being path-safe.
func (h *Handler) GetVPNGroupChart(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	group := c.Query("group")
	if group == "" {
		c.JSON(http.StatusBadRequest, response.Error("Tunnel group required"))
		return
	}
	// Resolve the group's member names from the device's own rows, so the client
	// never has to know (or URL-encode) them.
	statuses, err := db.GetLatestVPNStatuses(id)
	if err != nil {
		httputil.InternalError(c, "Failed to get VPN statuses", err)
		return
	}
	var names []string
	seen := map[string]bool{}
	for _, s := range statuses {
		if s.TunnelGroup == group && !seen[s.TunnelName] {
			seen[s.TunnelName] = true
			names = append(names, s.TunnelName)
		}
	}
	if len(names) == 0 {
		c.JSON(http.StatusOK, response.Success([]database.VPNChartBucket{}))
		return
	}
	from, to := httputil.ParseChartWindow(c, "24h")
	data, err := db.GetVPNChartGroupWindow(id, names, from, to)
	if err != nil {
		log.Printf("GetVPNChartGroupWindow(%d, %v, %v, %v) error: %v", id, names, from, to, err)
		httputil.InternalError(c, "Failed to get VPN chart data", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(data))
}

func (h *Handler) GetVPNTunnelChart(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	tunnel := c.Param("tunnel")
	if tunnel == "" {
		c.JSON(http.StatusBadRequest, response.Error("Tunnel name required"))
		return
	}
	// Window resolution (v0.10.410): explicit from/to (epoch ms, drag-to-zoom)
	// re-queries that sub-window at finer resolution; otherwise the range preset
	// maps to [now-dur, now]. Adaptive bucketing keeps the chart readable.
	from, to := httputil.ParseChartWindow(c, "24h")
	data, err := db.GetVPNChartWindow(id, tunnel, from, to)
	if err != nil {
		log.Printf("GetVPNChartWindow(%d, %s, %v, %v) error: %v", id, tunnel, from, to, err)
		httputil.InternalError(c, "Failed to get VPN chart data", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(data))
}

func (h *Handler) GetConnectionFlows(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	// Unified parsing (v0.10.217, bundle D2). 720h cap retained for this
	// endpoint — flow-stats over multi-month ranges aren't useful for the
	// connection-detail view.
	hours := httputil.ParseHours(c)
	if hours > 720 {
		hours = 720
	}
	data, err := db.GetConnectionFlowStats(id, hours)
	if err != nil {
		httputil.InternalError(c, "Failed to get flow stats", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(data))
}

// GetVPNMapData returns per-device VPN tunnel summaries with remote IP matching.
func (h *Handler) GetVPNMapData(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(map[string]interface{}{}))
		return
	}

	devices, err := db.GetAllDevices()
	if err != nil {
		httputil.InternalError(c, "Failed to get devices", err)
		return
	}

	// Build IP → device map (same pattern as detectVPNConnections)
	type deviceRef struct {
		ID   uint
		Name string
	}
	ipToDevice := make(map[string]deviceRef, len(devices)*2)
	deviceByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		deviceByID[devices[i].ID] = &devices[i]
	}
	for _, d := range devices {
		ipToDevice[d.IPAddress] = deviceRef{ID: d.ID, Name: d.Name}
	}
	// Tunnels this system deployed carry their endpoints as recorded fact; a
	// failed read only costs the override, so it is non-fatal.
	provPairs, perr := db.GetProvisionedTunnelPairs()
	if perr != nil {
		provPairs = nil
	}
	ifAddrs, err := db.GetLatestInterfaceAddresses()
	if err == nil {
		for _, addr := range ifAddrs {
			if _, exists := ipToDevice[addr.IPAddress]; exists {
				continue
			}
			if dev, ok := deviceByID[addr.DeviceID]; ok {
				ipToDevice[addr.IPAddress] = deviceRef{ID: dev.ID, Name: dev.Name}
			}
		}
	}

	vpnStatuses, err := db.GetAllLatestVPNStatuses()
	if err != nil {
		httputil.InternalError(c, "Failed to get VPN statuses", err)
		return
	}
	// Unlike GetLatestVPNStatuses, this fetch does not resolve tunnel groups —
	// and the panel's chart is keyed by GROUP, not by row name. Without this the
	// counter-bearing rows (FortiGate dialup, every OPNsense child) ask for a
	// group that matches no member and chart blank.
	db.ResolveTunnelGroups(vpnStatuses)

	type tunnelInfo struct {
		TunnelName    string `json:"tunnel_name"`
		TunnelType    string `json:"tunnel_type"`
		Status        string `json:"status"`
		RemoteIP      string `json:"remote_ip"`
		MatchedDevID  uint   `json:"matched_device_id"`
		MatchedName   string `json:"matched_name"`
		Phase1Name    string `json:"phase1_name"`
		TunnelGroup   string `json:"tunnel_group"`
		LocalSubnet   string `json:"local_subnet"`
		RemoteSubnet  string `json:"remote_subnet"`
		TunnelUptime  uint64 `json:"tunnel_uptime"`
		BytesIn       uint64 `json:"bytes_in"`
		BytesOut      uint64 `json:"bytes_out"`
		InterfaceName string `json:"interface_name"`
		Mode          string `json:"mode"`
	}
	type deviceVPN struct {
		Total   int          `json:"total"`
		Up      int          `json:"up"`
		Down    int          `json:"down"`
		Tunnels []tunnelInfo `json:"tunnels"`
	}

	result := make(map[string]*deviceVPN)

	for _, vpn := range vpnStatuses {
		key := fmt.Sprintf("%d", vpn.DeviceID)
		dv, ok := result[key]
		if !ok {
			dv = &deviceVPN{}
			result[key] = dv
		}

		// Peer attribution must agree with the edge the connection map draws, so
		// this applies the same precedence as detectVPNConnections: a recorded
		// deployment wins, and a dialup row's remote IP is not evidence of
		// anything (for a peer behind NAT it is the gateway's address, which
		// legitimately belongs to a different monitored device). Without this the
		// panel would keep naming the NAT gateway while the edge named the real
		// peer — two answers to the same question on one screen.
		var matchID uint
		var matchName string
		if peer, found := provisionedPeer(provPairs, vpn); found {
			matchID = peer
			if d, ok := deviceByID[peer]; ok {
				matchName = d.Name
			}
		} else if vpn.TunnelType != "ipsec-dialup" {
			if ref, found := ipToDevice[vpn.RemoteIP]; found && ref.ID != vpn.DeviceID {
				matchID = ref.ID
				matchName = ref.Name
			}
		}

		dv.Total++
		if vpn.Status == "up" {
			dv.Up++
		} else {
			dv.Down++
		}
		dv.Tunnels = append(dv.Tunnels, tunnelInfo{
			TunnelName:    vpn.TunnelName,
			TunnelType:    vpn.TunnelType,
			Status:        vpn.Status,
			RemoteIP:      vpn.RemoteIP,
			MatchedDevID:  matchID,
			MatchedName:   matchName,
			Phase1Name:    vpn.Phase1Name,
			TunnelGroup:   vpn.TunnelGroup,
			LocalSubnet:   vpn.LocalSubnet,
			RemoteSubnet:  vpn.RemoteSubnet,
			TunnelUptime:  vpn.TunnelUptime,
			BytesIn:       vpn.BytesIn,
			BytesOut:      vpn.BytesOut,
			InterfaceName: vpn.InterfaceName,
			Mode:          vpn.Mode,
		})
	}

	c.JSON(http.StatusOK, response.Success(result))
}

// provisionedPeer returns the far-end device of the tunnel this row belongs to,
// when the row names a tunnel THIS system deployed.
//
// It mirrors the precedence detectVPNConnections applies, so the map's per-device
// panel and the edges it draws cannot give two different answers about who a
// tunnel connects. Peer attribution from the remote IP is structurally wrong for
// a dialup peer behind NAT — the responder observes the gateway's address, which
// legitimately belongs to a different monitored device — and for a tunnel we
// provisioned the endpoints are recorded fact rather than inference.
//
// The reporting device must be one of the recorded endpoints: vpn_status
// tunnel names are free text read off a device, and only ipsec_tunnels.name is
// unique, so an unrelated device reporting a same-named tunnel must not be able
// to claim the pair.
func provisionedPeer(provPairs map[string]database.ProvisionedTunnelPair, vpn models.VPNStatus) (uint, bool) {
	for _, n := range []string{vpn.TunnelName, vpn.Phase1Name} {
		if n == "" {
			continue
		}
		pp, ok := provPairs[strings.ToLower(n)]
		if !ok {
			continue
		}
		switch vpn.DeviceID {
		case pp.A:
			return pp.B, true
		case pp.B:
			return pp.A, true
		}
	}
	return 0, false
}
