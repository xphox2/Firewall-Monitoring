package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetDeviceConnections(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.DeviceConnection{}))
		return
	}

	connections, err := h.db.GetAllConnections()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get connections"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(connections))
}

func (h *Handler) CreateDeviceConnection(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var conn models.DeviceConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Validate required FK references
	if conn.SourceDeviceID == 0 || conn.DestDeviceID == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source and destination device IDs are required"))
		return
	}
	if conn.SourceDeviceID == conn.DestDeviceID {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source and destination cannot be the same device"))
		return
	}
	if _, err := h.db.GetDevice(conn.SourceDeviceID); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source device not found"))
		return
	}
	if _, err := h.db.GetDevice(conn.DestDeviceID); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Destination device not found"))
		return
	}

	conn.Status = "unknown"
	conn.AutoDetected = false
	if err := h.db.CreateConnection(&conn); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create connection"))
		return
	}

	c.JSON(http.StatusCreated, models.SuccessResponse(conn))
}

func (h *Handler) UpdateDeviceConnection(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var conn models.DeviceConnection
	if err := h.db.Gorm().First(&conn, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Connection not found"))
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Validate status enum if provided
	if statusVal, ok := updates["status"]; ok {
		validStatuses := map[string]bool{"unknown": true, "up": true, "down": true}
		if s, isStr := statusVal.(string); !isStr || !validStatuses[s] {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid status value"))
			return
		}
	}

	// Validate FK references if being updated
	if srcVal, ok := updates["source_device_id"]; ok {
		srcID, isNum := srcVal.(float64)
		if !isNum || srcID < 1 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid source device ID"))
			return
		}
		if _, err := h.db.GetDevice(uint(srcID)); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Source device not found"))
			return
		}
	}
	if dstVal, ok := updates["dest_device_id"]; ok {
		dstID, isNum := dstVal.(float64)
		if !isNum || dstID < 1 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid destination device ID"))
			return
		}
		if _, err := h.db.GetDevice(uint(dstID)); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Destination device not found"))
			return
		}
	}

	filteredUpdates := httputil.FilterAllowedFields(updates, allowedFields)

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No valid fields to update"))
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source and destination cannot be the same device"))
		return
	}

	if err := h.db.Gorm().Model(&conn).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update connection"))
		return
	}

	// Re-fetch to return fresh data with preloaded relations
	var updated models.DeviceConnection
	if err := h.db.Gorm().Preload("SourceDevice").Preload("DestDevice").First(&updated, id).Error; err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(conn))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
}

func (h *Handler) DeleteDeviceConnection(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	result := h.db.Gorm().Delete(&models.DeviceConnection{}, id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete connection"))
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Connection not found"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Connection deleted"))
}

func (h *Handler) GetConnectionDetail(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	detail, err := h.db.GetConnectionDetail(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Connection not found"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(detail))
}

func (h *Handler) GetConnectionTraffic(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	rangeStr := c.DefaultQuery("range", "24h")
	validRanges := map[string]bool{"1h": true, "24h": true, "7d": true, "30d": true}
	if !validRanges[rangeStr] {
		rangeStr = "24h"
	}
	data, err := h.db.GetConnectionTraffic(id, rangeStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get traffic data"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(data))
}

func (h *Handler) GetVPNTunnelChart(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	tunnel := c.Param("tunnel")
	if tunnel == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Tunnel name required"))
		return
	}
	rangeStr := c.DefaultQuery("range", "24h")
	validRanges := map[string]bool{"1h": true, "24h": true, "7d": true, "30d": true}
	if !validRanges[rangeStr] {
		rangeStr = "24h"
	}
	data, err := h.db.GetVPNChartData(id, tunnel, rangeStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get VPN chart data"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(data))
}

func (h *Handler) GetConnectionFlows(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	hoursStr := c.DefaultQuery("hours", "24")
	hours, err := strconv.Atoi(hoursStr)
	if err != nil || hours < 1 {
		hours = 24
	}
	if hours > 720 {
		hours = 720
	}
	data, err := h.db.GetConnectionFlowStats(id, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get flow stats"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(data))
}

// GetVPNMapData returns per-device VPN tunnel summaries with remote IP matching.
func (h *Handler) GetVPNMapData(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(map[string]interface{}{}))
		return
	}

	devices, err := h.db.GetAllDevices()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get devices"))
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
	ifAddrs, err := h.db.GetLatestInterfaceAddresses()
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

	vpnStatuses, err := h.db.GetAllLatestVPNStatuses()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get VPN statuses"))
		return
	}

	type tunnelInfo struct {
		TunnelName     string `json:"tunnel_name"`
		TunnelType     string `json:"tunnel_type"`
		Status         string `json:"status"`
		RemoteIP       string `json:"remote_ip"`
		MatchedDevID   uint   `json:"matched_device_id"`
		MatchedName    string `json:"matched_name"`
		Phase1Name     string `json:"phase1_name"`
		LocalSubnet    string `json:"local_subnet"`
		RemoteSubnet   string `json:"remote_subnet"`
		TunnelUptime   uint64 `json:"tunnel_uptime"`
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
			TunnelName:   vpn.TunnelName,
			TunnelType:   vpn.TunnelType,
			Status:       vpn.Status,
			RemoteIP:     vpn.RemoteIP,
			MatchedDevID: matchID,
			MatchedName:  matchName,
			Phase1Name:   vpn.Phase1Name,
			LocalSubnet:  vpn.LocalSubnet,
			RemoteSubnet: vpn.RemoteSubnet,
			TunnelUptime: vpn.TunnelUptime,
		})
	}

	c.JSON(http.StatusOK, models.SuccessResponse(result))
}
