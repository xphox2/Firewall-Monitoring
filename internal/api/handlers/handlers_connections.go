package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

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
	rangeStr := c.DefaultQuery("range", "24")
	hours := parseTrafficRangeHours(rangeStr)
	data, err := db.GetConnectionTraffic(id, hours)
	if err != nil {
		log.Printf("GetConnectionTraffic(%d, %s) error: %v", id, rangeStr, err)
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
	for _, d := range devices {
		ipToDevice[d.IPAddress] = deviceRef{ID: d.ID, Name: d.Name}
	}
	ifAddrs, err := db.GetLatestInterfaceAddresses()
	if err == nil {
		deviceByID := make(map[uint]*models.Device, len(devices))
		for i := range devices {
			deviceByID[devices[i].ID] = &devices[i]
		}
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

	type tunnelInfo struct {
		TunnelName    string `json:"tunnel_name"`
		TunnelType    string `json:"tunnel_type"`
		Status        string `json:"status"`
		RemoteIP      string `json:"remote_ip"`
		MatchedDevID  uint   `json:"matched_device_id"`
		MatchedName   string `json:"matched_name"`
		Phase1Name    string `json:"phase1_name"`
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

		var matchID uint
		var matchName string
		if ref, found := ipToDevice[vpn.RemoteIP]; found && ref.ID != vpn.DeviceID {
			matchID = ref.ID
			matchName = ref.Name
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
