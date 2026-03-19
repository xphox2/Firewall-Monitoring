package handlers

import (
	"net/http"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) ListMaintenanceWindows(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	windows, err := h.db.GetMaintenanceWindows()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get maintenance windows"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(windows))
}

func (h *Handler) GetActiveMaintenanceWindows(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	windows, err := h.db.GetActiveMaintenanceWindows()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get active maintenance windows"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(windows))
}

func (h *Handler) CreateMaintenanceWindow(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var window models.MaintenanceWindow
	if err := c.ShouldBindJSON(&window); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if window.Name == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name is required"))
		return
	}
	if window.StartTime.IsZero() || window.EndTime.IsZero() {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Start time and end time are required"))
		return
	}
	if window.EndTime.Before(window.StartTime) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("End time must be after start time"))
		return
	}

	window.ID = 0
	if err := h.db.CreateMaintenanceWindow(&window); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create maintenance window"))
		return
	}

	c.JSON(http.StatusCreated, models.SuccessResponse(window))
}

func (h *Handler) UpdateMaintenanceWindow(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var window models.MaintenanceWindow
	if err := c.ShouldBindJSON(&window); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	window.ID = id
	if err := h.db.UpdateMaintenanceWindow(&window); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update maintenance window"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(window))
}

func (h *Handler) DeleteMaintenanceWindow(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := h.db.DeleteMaintenanceWindow(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete maintenance window"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Maintenance window deleted"))
}
