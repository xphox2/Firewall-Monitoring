package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
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

	// Defensive cap (v0.10.217, bundle D3). System settings are a fixed
	// list of operator-tunable knobs — 1000 is well above any realistic
	// schema.
	var settings []models.SystemSetting
	if err := h.db.Gorm().Limit(1000).Find(&settings).Error; err != nil {
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
		"smtp_host":               true,
		"smtp_port":               true,
		"smtp_username":           true,
		"smtp_password":           true,
		"smtp_from":               true,
		"smtp_to":                 true,
		"slack_webhook":           true,
		"discord_webhook":         true,
		"webhook_url":             true,
		"public_refresh_interval": true,
		"public_show_vpn":         true,
		"public_show_connections": true,
		"public_interfaces":       true,
		"display_timezone":        true,
		"report_daily_enabled":    true,
		"report_daily_time":       true,
		"report_weekly_enabled":   true,
		"report_weekly_day":       true,
		"report_recipients":       true,
		"report_timezone":         true,
		"spike_stddev_threshold":  true,
		"spike_alert_enabled":     true,
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
		case "spike_stddev_threshold":
			v, err := strconv.ParseFloat(s.Value, 64)
			if err != nil || v < 1.0 || v > 10.0 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid value for spike_stddev_threshold: must be 1.0-10.0"))
				return
			}
		case "report_daily_time":
			if len(s.Value) > 0 && (len(s.Value) != 5 || s.Value[2] != ':') {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid report_daily_time: must be HH:MM format"))
				return
			}
		case "report_weekly_day":
			if len(s.Value) > 0 {
				validDays := map[string]bool{"monday": true, "tuesday": true, "wednesday": true, "thursday": true, "friday": true, "saturday": true, "sunday": true}
				if !validDays[strings.ToLower(s.Value)] {
					c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid report_weekly_day: must be a day of the week"))
					return
				}
			}
		case "report_timezone":
			if len(s.Value) > 64 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid timezone value"))
				return
			}
		case "report_recipients":
			if len(s.Value) > 500 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Value for report_recipients is too long (max 500)"))
				return
			}
		case "email_enabled", "report_daily_enabled", "report_weekly_enabled", "spike_alert_enabled",
			"public_show_vpn", "public_show_connections":
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
		case "display_timezone":
			if len(s.Value) > 64 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid timezone value"))
				return
			}
		case "public_interfaces":
			// No validation needed for JSON string settings
		case "smtp_password":
			// Skip masked passwords
			if s.Value == "********" {
				continue
			}
			// Encrypt secret values before storage
			if s.Value != "" && h.db != nil {
				s.Value = h.db.EncryptField(s.Value)
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
		if err := h.db.Gorm().Where("\"key\" = ?", key).First(&s).Error; err == nil && s.Value != "" {
			if s.IsSecret {
				return h.db.DecryptField(s.Value)
			}
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

// smtpTraceStep is one entry in the verbose SMTP test transcript
// (v0.10.220, bundle I). Each step corresponds to one SMTP verb or
// transition (CONNECT, EHLO, STARTTLS, AUTH, MAIL FROM, ...).
type smtpTraceStep struct {
	Step     string `json:"step"`               // "connect", "ehlo", "starttls", "auth", "mail-from", "rcpt-to", "data", "quit"
	Detail   string `json:"detail,omitempty"`   // human-readable description of what was tried
	Response string `json:"response,omitempty"` // server response (or summary like cipher / cert subject for non-textual steps)
	Status   string `json:"status"`             // "ok" | "skipped" | "fail"
	Error    string `json:"error,omitempty"`    // populated when Status == "fail"
	DurMs    int64  `json:"duration_ms"`        // wall time for this step
}

// runSMTPDiagnostic executes the standard SMTP test flow against the
// configured server while recording each protocol step. Returns the
// trace plus a boolean for overall success and a high-level error
// suitable for top-of-card display (v0.10.220, bundle I).
//
// The flow mirrors what smtp.SendMail does internally, but stepped out
// so we can show the operator which verb failed and what the server
// said. Operator-supplied to allows overriding the recipient without
// changing the saved setting (handy for one-off test sends).
func runSMTPDiagnostic(host string, port int, username, password, from, to string) (trace []smtpTraceStep, ok bool, summary string) {
	record := func(step, detail, response, status, errStr string, start time.Time) {
		trace = append(trace, smtpTraceStep{
			Step:     step,
			Detail:   detail,
			Response: response,
			Status:   status,
			Error:    errStr,
			DurMs:    time.Since(start).Milliseconds(),
		})
	}
	fail := func(step, detail string, start time.Time, err error) (string, error) {
		record(step, detail, "", "fail", err.Error(), start)
		return fmt.Sprintf("%s failed: %v", step, err), err
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// ----- CONNECT -----
	cStart := time.Now()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	netConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		summary, _ = fail("connect", "tcp dial "+addr, cStart, err)
		return trace, false, summary
	}
	defer netConn.Close()
	record("connect", "tcp dial "+addr, "established", "ok", "", cStart)

	// Implicit TLS on 465 (smtps). For 587 / 25 we STARTTLS later.
	usingImplicitTLS := port == 465
	if usingImplicitTLS {
		tStart := time.Now()
		tlsConn := tls.Client(netConn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			summary, _ = fail("tls", "implicit TLS handshake (port 465)", tStart, err)
			return trace, false, summary
		}
		st := tlsConn.ConnectionState()
		record("tls", "implicit TLS handshake (port 465)",
			fmt.Sprintf("%s, %s, cert CN=%s", tlsVersionName(st.Version), tlsCipherName(st.CipherSuite), tlsLeafSubject(st)),
			"ok", "", tStart)
		netConn = tlsConn
	}

	// ----- SMTP CLIENT WRAPPER -----
	hStart := time.Now()
	client, err := smtp.NewClient(netConn, host)
	if err != nil {
		summary, _ = fail("greeting", "read 220 banner", hStart, err)
		return trace, false, summary
	}
	defer client.Close()
	record("greeting", "read 220 banner", "ok", "ok", "", hStart)

	// ----- EHLO -----
	eStart := time.Now()
	if err := client.Hello("firewall-mon-test"); err != nil {
		summary, _ = fail("ehlo", "EHLO firewall-mon-test", eStart, err)
		return trace, false, summary
	}
	record("ehlo", "EHLO firewall-mon-test", "accepted", "ok", "", eStart)

	// ----- STARTTLS (only if not already wrapped) -----
	if !usingImplicitTLS {
		tStart := time.Now()
		if hasStartTLS, _ := client.Extension("STARTTLS"); hasStartTLS {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				summary, _ = fail("starttls", "STARTTLS upgrade", tStart, err)
				return trace, false, summary
			}
			// Re-issue EHLO over the encrypted channel — STARTTLS
			// invalidates the previous capability list.
			if err := client.Hello("firewall-mon-test"); err != nil {
				summary, _ = fail("starttls", "EHLO after STARTTLS", tStart, err)
				return trace, false, summary
			}
			// Pull TLS state for the trace via the stdlib accessor
			// (Go 1.20+); the smtp.Client owns the wrapped conn so
			// we can't reach for it through our netConn handle.
			var tlsDetail string
			if st, ok := client.TLSConnectionState(); ok {
				tlsDetail = fmt.Sprintf("%s, %s, cert CN=%s",
					tlsVersionName(st.Version), tlsCipherName(st.CipherSuite), tlsLeafSubject(st))
			} else {
				tlsDetail = "established"
			}
			record("starttls", "STARTTLS upgrade + EHLO", tlsDetail, "ok", "", tStart)
		} else {
			record("starttls", "STARTTLS not advertised by server", "skipped", "skipped", "", tStart)
		}
	}

	// ----- AUTH -----
	aStart := time.Now()
	authMechs := ""
	if supported, mechs := client.Extension("AUTH"); supported {
		authMechs = mechs
	}
	if username != "" {
		// PlainAuth requires TLS or localhost. If we didn't TLS-up
		// successfully (server didn't advertise STARTTLS and we're not
		// on 465), surface that as the AUTH failure mode it would
		// produce — clearer for the operator than the generic stdlib
		// "unencrypted connection" error.
		if !usingImplicitTLS {
			if hasStartTLS, _ := client.Extension("STARTTLS"); !hasStartTLS {
				summary, _ = fail("auth", "PLAIN auth refused: connection is not encrypted (server didn't advertise STARTTLS)", aStart, errors.New("unencrypted connection"))
				return trace, false, summary
			}
		}
		auth := smtp.PlainAuth("", username, password, host)
		if err := client.Auth(auth); err != nil {
			detail := fmt.Sprintf("PLAIN auth as %s (server advertised mechs: %s)", username, authMechs)
			summary, _ = fail("auth", detail, aStart, err)
			return trace, false, summary
		}
		record("auth", fmt.Sprintf("PLAIN auth as %s", username), "accepted (mechs offered: "+authMechs+")", "ok", "", aStart)
	} else {
		record("auth", "skipped — no smtp_username configured", "skipped", "skipped", "", aStart)
	}

	// ----- MAIL FROM -----
	mStart := time.Now()
	if err := client.Mail(from); err != nil {
		summary, _ = fail("mail-from", "MAIL FROM:<"+from+">", mStart, err)
		return trace, false, summary
	}
	record("mail-from", "MAIL FROM:<"+from+">", "accepted", "ok", "", mStart)

	// ----- RCPT TO -----
	rStart := time.Now()
	if err := client.Rcpt(to); err != nil {
		summary, _ = fail("rcpt-to", "RCPT TO:<"+to+">", rStart, err)
		return trace, false, summary
	}
	record("rcpt-to", "RCPT TO:<"+to+">", "accepted", "ok", "", rStart)

	// ----- DATA -----
	dStart := time.Now()
	w, err := client.Data()
	if err != nil {
		summary, _ = fail("data", "DATA", dStart, err)
		return trace, false, summary
	}
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\n", "")
		return s
	}
	subject := "Firewall Monitor - Test Email"
	body := fmt.Sprintf("This is a test email from Firewall Monitor.\n\nSent at: %s\n\nIf you received this email, your SMTP settings are configured correctly.",
		time.Now().Format(time.RFC3339))
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		sanitize(from), sanitize(to), sanitize(subject), body)
	if _, err := w.Write([]byte(msg)); err != nil {
		summary, _ = fail("data", "write message body", dStart, err)
		return trace, false, summary
	}
	if err := w.Close(); err != nil {
		summary, _ = fail("data", "close DATA (server final response)", dStart, err)
		return trace, false, summary
	}
	record("data", "DATA + body + final dot", fmt.Sprintf("accepted (%d bytes)", len(msg)), "ok", "", dStart)

	// ----- QUIT -----
	qStart := time.Now()
	if err := client.Quit(); err != nil {
		record("quit", "QUIT", "", "fail", err.Error(), qStart)
		// Don't treat QUIT failure as overall failure — the message
		// already went through. Server-side post-DATA log will show
		// the message id.
	} else {
		record("quit", "QUIT", "accepted", "ok", "", qStart)
	}

	return trace, true, "Test email accepted by " + addr
}

// tlsVersionName turns a tls.VersionTLSxx constant into a human label.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return fmt.Sprintf("TLS-0x%04x", v)
}

// tlsCipherName uses tls.CipherSuiteName which is the stdlib helper.
func tlsCipherName(c uint16) string { return tls.CipherSuiteName(c) }

// tlsLeafSubject returns the CN of the leaf server certificate, or "?"
// if the chain is empty (it shouldn't be on a successful handshake).
func tlsLeafSubject(st tls.ConnectionState) string {
	if len(st.PeerCertificates) == 0 {
		return "?"
	}
	return st.PeerCertificates[0].Subject.CommonName
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

	// Allow the operator to override the recipient for a one-off test
	// without rewriting the saved smtp_to setting (v0.10.220, bundle I).
	var req struct {
		ToOverride string `json:"to"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.ToOverride != "" {
		smtpTo = req.ToOverride
	}

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

	startedAt := time.Now()
	trace, ok, summary := runSMTPDiagnostic(smtpHost, smtpPort, smtpUsername, smtpPassword, smtpFrom, smtpTo)
	totalMs := time.Since(startedAt).Milliseconds()

	if !ok {
		log.Printf("Test email failed: %s", summary)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"success":     ok,
		"message":     summary,
		"trace":       trace,
		"total_ms":    totalMs,
		"host":        smtpHost,
		"port":        smtpPort,
		"auth_method": authMethodLabel(smtpUsername),
		"from":        smtpFrom,
		"to":          smtpTo,
	}))
}

func authMethodLabel(username string) string {
	if username == "" {
		return "none"
	}
	return "PLAIN"
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
	isAdmin := c.GetBool("is_admin")
	defaults := map[string]string{
		"public_show_vpn":         "false",
		"public_show_connections": "false",
		"public_refresh_interval": "30",
		"public_interfaces":       "{}", // JSON: {"1":["wan1"],"2":["dmz"]}
		"display_timezone":        "America/New_York",
	}

	if h.db == nil {
		resp := gin.H{"success": true, "data": defaults, "is_admin": isAdmin}
		c.JSON(http.StatusOK, resp)
		return
	}

	// One-time cleanup: remove unused public settings from database
	unusedKeys := []string{
		"public_show_hostname", "public_show_uptime", "public_show_cpu",
		"public_show_memory", "public_show_sessions", "public_show_interfaces",
		"public_show_bandwidth", "public_vpn_tunnels_by_device",
	}
	if err := h.db.Gorm().Where("\"key\" IN ?", unusedKeys).Delete(&models.SystemSetting{}).Error; err != nil {
		log.Printf("Failed to cleanup unused public settings: %v", err)
	}

	var settings []models.SystemSetting
	if err := h.db.Gorm().Where("\"key\" LIKE ? OR \"key\" = ?", "public_%", "display_timezone").Find(&settings).Error; err != nil {
		log.Printf("Failed to get public settings: %v", err)
	}

	result := make(map[string]string)
	for k, v := range defaults {
		result[k] = v
	}
	for _, s := range settings {
		result[s.Key] = s.Value
	}

	resp := gin.H{"success": true, "data": result, "is_admin": isAdmin}
	c.JSON(http.StatusOK, resp)
}
