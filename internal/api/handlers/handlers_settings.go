package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

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
		"cpu_threshold":                true,
		"memory_threshold":             true,
		"disk_threshold":               true,
		"session_threshold":            true,
		"email_enabled":                true,
		"smtp_host":                    true,
		"smtp_port":                    true,
		"smtp_username":                true,
		"smtp_password":                true,
		"smtp_from":                    true,
		"smtp_to":                      true,
		"slack_webhook":                true,
		"discord_webhook":              true,
		"webhook_url":                  true,
		"public_show_hostname":         true,
		"public_show_uptime":           true,
		"public_show_cpu":              true,
		"public_show_memory":           true,
		"public_show_sessions":         true,
		"public_show_interfaces":       true,
		"public_refresh_interval":      true,
		"public_show_bandwidth":        true,
		"public_bandwidth_interfaces":  true,
		"public_show_vpn":              true,
		"public_vpn_tunnels":           true,
		"public_show_connections":      true,
		"public_interfaces":            true,
		"public_vpn_tunnels_by_device": true,
	}

	secretKeys := map[string]bool{
		"smtp_password": true,
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
			"public_show_cpu", "public_show_memory", "public_show_sessions", "public_show_interfaces",
			"public_show_bandwidth", "public_show_vpn", "public_show_connections":
			if s.Value != "true" && s.Value != "false" {
				c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Invalid value for %s: must be true or false", s.Key)))
				return
			}
		case "smtp_port":
			if s.Value != "" {
				v, err := strconv.Atoi(s.Value)
				if err != nil || v < 1 || v > 65535 {
					c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid SMTP port: must be 1-65535"))
					return
				}
			}
		case "smtp_host", "smtp_username", "smtp_from", "smtp_to":
			if len(s.Value) > 255 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Value for %s is too long (max 255)", s.Key)))
				return
			}
		case "smtp_password":
			// Skip masked passwords
			if s.Value == "********" {
				continue
			}
		}
		if secretKeys[s.Key] {
			s.IsSecret = true
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

// getNotificationSetting reads a key from system_settings, falling back to config.
func (h *Handler) getNotificationSetting(key string) string {
	if h.db != nil {
		var s models.SystemSetting
		if err := h.db.Gorm().Where("`key` = ?", key).First(&s).Error; err == nil && s.Value != "" {
			return s.Value
		}
	}
	// Fall back to env/config values
	switch key {
	case "smtp_host":
		return h.config.Alerts.SMTPHost
	case "smtp_port":
		return strconv.Itoa(h.config.Alerts.SMTPPort)
	case "smtp_username":
		return h.config.Alerts.SMTPUsername
	case "smtp_password":
		return h.config.Alerts.SMTPPassword
	case "smtp_from":
		return h.config.Alerts.SMTPFrom
	case "smtp_to":
		return h.config.Alerts.SMTPTo
	case "slack_webhook":
		return h.config.Alerts.SlackWebhookURL
	case "discord_webhook":
		return h.config.Alerts.DiscordWebhookURL
	case "webhook_url":
		return h.config.Alerts.WebHookURL
	}
	return ""
}

func (h *Handler) TestEmail(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return
	}

	smtpHost := h.getNotificationSetting("smtp_host")
	smtpPortStr := h.getNotificationSetting("smtp_port")
	smtpUsername := h.getNotificationSetting("smtp_username")
	smtpPassword := h.getNotificationSetting("smtp_password")
	smtpFrom := h.getNotificationSetting("smtp_from")
	smtpTo := h.getNotificationSetting("smtp_to")

	if smtpHost == "" || smtpFrom == "" || smtpTo == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("SMTP host, sender, and recipient address are required"))
		return
	}

	// Validate SMTP host to prevent SSRF / internal port scanning
	if !isValidExternalIP(smtpHost) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("SMTP host resolves to a blocked address"))
		return
	}

	smtpPort := 587
	if smtpPortStr != "" {
		if v, err := strconv.Atoi(smtpPortStr); err == nil {
			smtpPort = v
		}
	}

	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)

	var auth smtp.Auth
	if smtpUsername != "" {
		auth = smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
	}

	subject := "Firewall Monitor - Test Email"
	body := fmt.Sprintf("This is a test email from Firewall Monitor.\n\nSent at: %s\n\nIf you received this email, your SMTP settings are configured correctly.",
		time.Now().Format(time.RFC3339))

	// Sanitize header values
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\n", "")
		return s
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		sanitize(smtpFrom), sanitize(smtpTo), sanitize(subject), body)

	if err := smtp.SendMail(addr, auth, smtpFrom, []string{smtpTo}, []byte(msg)); err != nil {
		log.Printf("Test email failed: %v", err)
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": fmt.Sprintf("Failed to send test email: %v", err),
		}))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"success": true,
		"message": fmt.Sprintf("Test email sent to %s", smtpTo),
	}))
}

func (h *Handler) TestWebhook(c *gin.Context) {
	var req struct {
		Type string `json:"type" binding:"required"`
		URL  string `json:"url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request: type is required"))
		return
	}

	webhookURL := req.URL
	if webhookURL == "" {
		// Fall back to DB/config
		webhookURL = h.getNotificationSetting(req.Type)
	}

	if webhookURL == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No webhook URL configured"))
		return
	}

	// Validate URL scheme and host to prevent SSRF
	parsed, err := url.Parse(webhookURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid webhook URL: must be http or https"))
		return
	}
	hostname := parsed.Hostname()
	if !isValidExternalIP(hostname) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Webhook URL resolves to a blocked address"))
		return
	}

	// Build test payload based on type
	var payload interface{}
	switch req.Type {
	case "slack_webhook":
		payload = map[string]interface{}{
			"text": "Firewall Monitor - Test notification. Your Slack webhook is working!",
		}
	case "discord_webhook":
		payload = map[string]interface{}{
			"content": "Firewall Monitor - Test notification. Your Discord webhook is working!",
		}
	default:
		payload = map[string]interface{}{
			"type":      "test",
			"message":   "Firewall Monitor - Test notification. Your webhook is working!",
			"timestamp": time.Now().Format(time.RFC3339),
		}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to build payload"))
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	httpReq, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(fmt.Sprintf("Invalid URL: %v", err)))
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": fmt.Sprintf("Failed to reach webhook: %v", err),
		}))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": fmt.Sprintf("Webhook returned status %d", resp.StatusCode),
		}))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"success": true,
		"message": "Test notification sent successfully",
	}))
}

func (h *Handler) GetPublicDisplaySettings(c *gin.Context) {
	defaults := map[string]string{
		"public_show_hostname":         "true",
		"public_show_uptime":           "true",
		"public_show_cpu":              "true",
		"public_show_memory":           "true",
		"public_show_sessions":         "true",
		"public_show_interfaces":       "true",
		"public_show_bandwidth":        "false",
		"public_bandwidth_interfaces":  "",
		"public_show_vpn":              "false",
		"public_vpn_tunnels":           "",
		"public_show_connections":      "false",
		"public_refresh_interval":      "30",
		"public_interfaces":            "{}", // JSON: {"1":["wan1"],"2":["dmz"]}
		"public_vpn_tunnels_by_device": "{}", // JSON: {"1":["tunnel1"],"2":["tunnel2"]}
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
