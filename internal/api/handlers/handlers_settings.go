package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetSettings(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.SystemSetting{}))
		return
	}

	var settings []models.SystemSetting
	if err := h.db.Gorm().Find(&settings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get settings"))
		return
	}

	// Mask secret values
	for i := range settings {
		if settings[i].IsSecret {
			settings[i].Value = "********"
		}
	}

	c.JSON(http.StatusOK, models.SuccessResponse(settings))
}

func (h *Handler) UpdateSettings(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	var settings []models.SystemSetting
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	allowedKeys := map[string]bool{
		"cpu_threshold":           true,
		"memory_threshold":        true,
		"disk_threshold":          true,
		"session_threshold":       true,
		"email_enabled":           true,
		"slack_webhook":           true,
		"discord_webhook":         true,
		"webhook_url":             true,
		"public_show_hostname":    true,
		"public_show_uptime":      true,
		"public_show_cpu":         true,
		"public_show_memory":      true,
		"public_show_sessions":    true,
		"public_show_interfaces":  true,
		"public_refresh_interval": true,
	}

	var validSettings []models.SystemSetting
	for _, s := range settings {
		if !allowedKeys[s.Key] {
			continue
		}
		// Validate values by key type
		switch s.Key {
		case "cpu_threshold", "memory_threshold", "disk_threshold":
			v, err := strconv.ParseFloat(s.Value, 64)
			if err != nil || v < 0 || v > 100 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Invalid value for %s: must be 0-100", s.Key)))
				return
			}
		case "session_threshold":
			v, err := strconv.Atoi(s.Value)
			if err != nil || v < 1 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid value for session_threshold: must be a positive integer"))
				return
			}
		case "public_refresh_interval":
			v, err := strconv.Atoi(s.Value)
			if err != nil || v < 5 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid value for public_refresh_interval: must be at least 5"))
				return
			}
		case "email_enabled", "public_show_hostname", "public_show_uptime",
			"public_show_cpu", "public_show_memory", "public_show_sessions", "public_show_interfaces":
			if s.Value != "true" && s.Value != "false" {
				c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Invalid value for %s: must be true or false", s.Key)))
				return
			}
		}
		validSettings = append(validSettings, s)
	}

	var failedKeys []string
	for _, s := range validSettings {
		existing := models.SystemSetting{Key: s.Key}
		if err := h.db.Gorm().FirstOrCreate(&existing, models.SystemSetting{Key: s.Key}).Error; err != nil {
			log.Printf("Failed to find/create setting %s: %v", s.Key, err)
			failedKeys = append(failedKeys, s.Key)
			continue
		}
		if !s.IsSecret || s.Value != "" {
			existing.Value = s.Value
			existing.Label = s.Label
			existing.Category = s.Category
			if err := h.db.Gorm().Save(&existing).Error; err != nil {
				log.Printf("Failed to save setting %s: %v", s.Key, err)
				failedKeys = append(failedKeys, s.Key)
				continue
			}
		}
	}

	if len(failedKeys) > 0 {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(fmt.Sprintf("Failed to save %d setting(s)", len(failedKeys))))
		return
	}
	c.JSON(http.StatusOK, models.MessageResponse("Settings updated"))
}

func (h *Handler) GetPublicDisplaySettings(c *gin.Context) {
	defaults := map[string]string{
		"public_show_hostname":    "true",
		"public_show_uptime":      "true",
		"public_show_cpu":         "true",
		"public_show_memory":      "true",
		"public_show_sessions":    "true",
		"public_show_interfaces":  "true",
		"public_refresh_interval": "30",
	}

	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(defaults))
		return
	}

	var settings []models.SystemSetting
	h.db.Gorm().Where("`key` LIKE ?", "public_%").Find(&settings)

	result := make(map[string]string)
	for k, v := range defaults {
		result[k] = v
	}
	for _, s := range settings {
		result[s.Key] = s.Value
	}

	c.JSON(http.StatusOK, models.SuccessResponse(result))
}
