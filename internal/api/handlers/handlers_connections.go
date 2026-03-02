package handlers

import (
	"net/http"

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
