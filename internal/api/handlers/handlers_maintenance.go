package handlers

import (
	"net/http"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) ListMaintenanceWindows(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	windows, err := db.GetMaintenanceWindows()
	if err != nil {
		httputil.InternalError(c, "Failed to get maintenance windows", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(windows))
}

func (h *Handler) GetActiveMaintenanceWindows(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	windows, err := db.GetActiveMaintenanceWindows()
	if err != nil {
		httputil.InternalError(c, "Failed to get active maintenance windows", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(windows))
}

func (h *Handler) CreateMaintenanceWindow(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var window models.MaintenanceWindow
	if err := c.ShouldBindJSON(&window); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if window.Name == "" {
		c.JSON(http.StatusBadRequest, response.Error("Name is required"))
		return
	}
	if window.StartTime.IsZero() || window.EndTime.IsZero() {
		c.JSON(http.StatusBadRequest, response.Error("Start time and end time are required"))
		return
	}
	if window.EndTime.Before(window.StartTime) {
		c.JSON(http.StatusBadRequest, response.Error("End time must be after start time"))
		return
	}

	window.ID = 0
	if err := db.CreateMaintenanceWindow(&window); err != nil {
		httputil.InternalError(c, "Failed to create maintenance window", err)
		return
	}

	c.JSON(http.StatusCreated, response.Success(window))
}

func (h *Handler) UpdateMaintenanceWindow(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	// v0.10.234: was loading `existing` only as an exists-check, then
	// binding the request into a FRESH struct and calling Save. Any field
	// absent from the PUT body (recur_rule, recur_days, alert_types,
	// notes, suppress_all, recurring) landed as Go zero-value and wiped
	// the row's recurring schedule on every partial edit.
	// Fix: bind directly onto the loaded struct. encoding/json only writes
	// fields present in the body, so absent fields stay as their DB values.
	var window models.MaintenanceWindow
	if err := db.Gorm().First(&window, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Maintenance window not found"))
		return
	}

	if err := c.ShouldBindJSON(&window); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	window.ID = id // prevent client from rewriting the PK

	if window.Name == "" {
		c.JSON(http.StatusBadRequest, response.Error("Name is required"))
		return
	}
	if window.StartTime.IsZero() || window.EndTime.IsZero() {
		c.JSON(http.StatusBadRequest, response.Error("Start time and end time are required"))
		return
	}
	if window.EndTime.Before(window.StartTime) {
		c.JSON(http.StatusBadRequest, response.Error("End time must be after start time"))
		return
	}

	if err := db.UpdateMaintenanceWindow(&window); err != nil {
		httputil.InternalError(c, "Failed to update maintenance window", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(window))
}

func (h *Handler) DeleteMaintenanceWindow(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := db.DeleteMaintenanceWindow(id); err != nil {
		httputil.InternalError(c, "Failed to delete maintenance window", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Maintenance window deleted"))
}
