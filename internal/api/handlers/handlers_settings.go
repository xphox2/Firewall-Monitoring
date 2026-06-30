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

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"

	"github.com/gin-gonic/gin"
)

// settingsSecretKeys is the source of truth for which system_settings rows
// hold secret values that must be encrypted at rest and masked in API
// responses. Defined at package scope so GetSettings, UpdateSettings, and
// the startup backfill share one list. v0.10.226 (see CHANGELOG).
var settingsSecretKeys = map[string]bool{
	"smtp_password": true,
}

func (h *Handler) GetSettings(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, response.Success([]models.SystemSetting{}))
		return
	}

	// Defensive cap (v0.10.217, bundle D3). System settings are a fixed
	// list of operator-tunable knobs — 1000 is well above any realistic
	// schema.
	var settings []models.SystemSetting
	if err := h.db.Gorm().Limit(1000).Find(&settings).Error; err != nil {
		httputil.InternalError(c, "Failed to get settings", err)
		return
	}

	// Mask secret values. v0.10.226: key off the settingsSecretKeys map
	// rather than the row's is_secret column. The column was being
	// silently corrupted by UpdateSettings (it never copied is_secret
	// onto the existing row before Save) — relying on it meant raw
	// {enc}<base64> ciphertext was being leaked back to the settings UI
	// any time a row got out of sync. The key list is the static source
	// of truth here.
	for i := range settings {
		if settingsSecretKeys[settings[i].Key] {
			settings[i].Value = "********"
		}
	}

	c.JSON(http.StatusOK, response.Success(settings))
}

func (h *Handler) UpdateSettings(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}

	var settings []models.SystemSetting
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	allowedKeys := map[string]bool{
		"cpu_threshold":              true,
		"memory_threshold":           true,
		"disk_threshold":             true,
		"session_threshold":          true,
		"email_enabled":              true,
		"smtp_host":                  true,
		"smtp_port":                  true,
		"smtp_username":              true,
		"smtp_password":              true,
		"smtp_from":                  true,
		"smtp_to":                    true,
		"slack_webhook":              true,
		"discord_webhook":            true,
		"webhook_url":                true,
		"public_refresh_interval":    true,
		"public_show_vpn":            true,
		"public_show_connections":    true,
		"public_interfaces":          true,
		"display_timezone":           true,
		"report_daily_enabled":       true,
		"report_daily_time":          true,
		"report_weekly_enabled":      true,
		"report_weekly_day":          true,
		"report_recipients":          true,
		"report_timezone":            true,
		"spike_stddev_threshold":     true,
		"spike_alert_enabled":        true,
		"spike_min_duration_minutes": true,
		// sFlow detection-engine thresholds (DB overrides the DETECT_* env;
		// blank = fall back to env/built-in default). Read live by the poller.
		"detect_port_scan_ports":      true,
		"detect_super_spreader_hosts": true,
		"detect_data_exfil_bytes":     true,
		"detect_beacon_min_samples":   true,
		"detect_beacon_max_avg_bytes": true,
		"detect_beacon_max_cv":        true,
		"detect_capacity_threshold":   true,
	}

	secretKeys := settingsSecretKeys // v0.10.226: shared with GetSettings

	var validSettings []models.SystemSetting
	// v0.10.224: collect non-fatal warnings (e.g. whitespace trimmed from
	// a secret) so the operator can see, at SAVE time, what the server
	// actually persisted vs what they typed. This replaces the
	// password_len leak in v0.10.223 — same signal ("did your password
	// get mutated?"), surfaced at the moment it's actionable.
	var warnings []string
	for _, s := range settings {
		if !allowedKeys[s.Key] {
			continue
		}
		// Validate values by key type
		switch s.Key {
		case "cpu_threshold", "memory_threshold", "disk_threshold":
			v, err := strconv.ParseFloat(s.Value, 64)
			if err != nil || v < 0 || v > 100 {
				c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Invalid value for %s: must be 0-100", s.Key)))
				return
			}
		case "session_threshold":
			v, err := strconv.Atoi(s.Value)
			if err != nil || v < 1 {
				c.JSON(http.StatusBadRequest, response.Error("Invalid value for session_threshold: must be a positive integer"))
				return
			}
		case "public_refresh_interval":
			v, err := strconv.Atoi(s.Value)
			if err != nil || v < 5 {
				c.JSON(http.StatusBadRequest, response.Error("Invalid value for public_refresh_interval: must be at least 5"))
				return
			}
		case "spike_stddev_threshold":
			v, err := strconv.ParseFloat(s.Value, 64)
			if err != nil || v < 1.0 || v > 10.0 {
				c.JSON(http.StatusBadRequest, response.Error("Invalid value for spike_stddev_threshold: must be 1.0-10.0"))
				return
			}
		case "spike_min_duration_minutes":
			v, err := strconv.Atoi(s.Value)
			if err != nil || v < 1 || v > 1440 {
				c.JSON(http.StatusBadRequest, response.Error("Invalid value for spike_min_duration_minutes: must be 1-1440"))
				return
			}
		case "detect_port_scan_ports", "detect_super_spreader_hosts",
			"detect_beacon_min_samples", "detect_beacon_max_avg_bytes",
			"detect_data_exfil_bytes":
			// Blank = unset (poller falls back to env/default). Otherwise a
			// positive integer.
			if s.Value != "" {
				v, err := strconv.ParseInt(s.Value, 10, 64)
				if err != nil || v < 1 {
					c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Invalid value for %s: must be a positive integer (or blank for default)", s.Key)))
					return
				}
			}
		case "detect_beacon_max_cv":
			if s.Value != "" {
				v, err := strconv.ParseFloat(s.Value, 64)
				if err != nil || v <= 0 || v > 5 {
					c.JSON(http.StatusBadRequest, response.Error("Invalid value for detect_beacon_max_cv: must be >0 and <=5 (or blank for default)"))
					return
				}
			}
		case "detect_capacity_threshold":
			if s.Value != "" {
				v, err := strconv.ParseFloat(s.Value, 64)
				if err != nil || v <= 0 || v > 1 {
					c.JSON(http.StatusBadRequest, response.Error("Invalid value for detect_capacity_threshold: must be >0 and <=1 (e.g. 0.80) (or blank for default)"))
					return
				}
			}
		case "report_daily_time":
			if len(s.Value) > 0 && (len(s.Value) != 5 || s.Value[2] != ':') {
				c.JSON(http.StatusBadRequest, response.Error("Invalid report_daily_time: must be HH:MM format"))
				return
			}
		case "report_weekly_day":
			if len(s.Value) > 0 {
				validDays := map[string]bool{"monday": true, "tuesday": true, "wednesday": true, "thursday": true, "friday": true, "saturday": true, "sunday": true}
				if !validDays[strings.ToLower(s.Value)] {
					c.JSON(http.StatusBadRequest, response.Error("Invalid report_weekly_day: must be a day of the week"))
					return
				}
			}
		case "report_timezone":
			if len(s.Value) > 64 {
				c.JSON(http.StatusBadRequest, response.Error("Invalid timezone value"))
				return
			}
		case "report_recipients":
			if len(s.Value) > 500 {
				c.JSON(http.StatusBadRequest, response.Error("Value for report_recipients is too long (max 500)"))
				return
			}
		case "email_enabled", "report_daily_enabled", "report_weekly_enabled", "spike_alert_enabled",
			"public_show_vpn", "public_show_connections":
			if s.Value != "true" && s.Value != "false" {
				c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Invalid value for %s: must be true or false", s.Key)))
				return
			}
		case "smtp_port":
			if s.Value != "" {
				v, err := strconv.Atoi(s.Value)
				if err != nil || v < 1 || v > 65535 {
					c.JSON(http.StatusBadRequest, response.Error("Invalid SMTP port: must be 1-65535"))
					return
				}
			}
		case "smtp_host", "smtp_username", "smtp_from", "smtp_to":
			// v0.10.223: trim whitespace defensively — copy-paste from webmail
			// settings pages commonly drags a trailing space on host/username.
			// These are non-secret so a silent trim is acceptable; the secret
			// case (smtp_password) is handled separately below with an
			// operator-visible warning so the operator can confirm whether
			// their stored password got mutated.
			if trimmed := strings.TrimSpace(s.Value); trimmed != s.Value {
				warnings = append(warnings, fmt.Sprintf("Trimmed leading/trailing whitespace from %s", s.Key))
				s.Value = trimmed
			}
			if len(s.Value) > 255 {
				c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Value for %s is too long (max 255)", s.Key)))
				return
			}
		case "display_timezone":
			if len(s.Value) > 64 {
				c.JSON(http.StatusBadRequest, response.Error("Invalid timezone value"))
				return
			}
		case "public_interfaces":
			// No validation needed for JSON string settings
		case "smtp_password":
			// Skip masked passwords
			if s.Value == "********" {
				continue
			}
			// v0.10.224: trim and SURFACE the mutation. Silently mutating
			// a secret is a footgun — if it didn't actually fix the
			// auth problem, the operator now also has to debug why their
			// password "isn't what they typed" without any signal that
			// the server modified it. So we report it as a warning in
			// the response. Length of trimmed bytes is NOT exposed
			// (information disclosure even authenticated — see swaks'
			// --auth-hide-password convention).
			if trimmed := strings.TrimSpace(s.Value); trimmed != s.Value {
				warnings = append(warnings, "Trimmed leading/trailing whitespace from smtp_password before encrypting — re-run the SMTP test to confirm the trim fixed the auth failure")
				s.Value = trimmed
			}
			// Encrypt secret values before storage. AUDIT-026: gate on
			// the secretKeys membership (the same source of truth that
			// drives `s.IsSecret = true` below) rather than running
			// the encryption unconditionally. The pre-fix behavior
			// encrypted EVERY system_setting row on save, including
			// non-secret thresholds / display preferences / boolean
			// toggles. That was:
			//   (a) wasteful — every write paid the AES-GCM cost
			//       (CPU on the API path), and
			//   (b) a footgun — it invited the v0.10.226 class of bug
			//       where a non-secret row would surface as
			//       `{enc}<base64>` from a consumer that didn't expect
			//       it. With this gate, a future field added to
			//       allowedKeys but NOT to secretKeys is stored as
			//       plaintext (the right default) and a future field
			//       added to BOTH is encrypted.
			// The empty-value short-circuit is preserved: encrypting ""
			// would round-trip a fixed `{enc}...` blob for every blank
			// input, which is noise.
			if secretKeys[s.Key] && s.Value != "" && h.db != nil {
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
			// v0.10.226 — THE bug. This line was missing. Without it,
			// FirstOrCreate populates `existing` from the DB row (or
			// zero-value defaults if the row is new), but is_secret was
			// never copied across from the incoming request, so the
			// row got persisted with is_secret=false even when the value
			// was encrypted ciphertext. getNotificationSetting then
			// gated decryption on is_secret and returned the raw
			// {enc}<base64> string as the "password" to SMTP AUTH —
			// causing Dovecot to log "Password mismatch" while IMAP
			// auth with the same credentials worked fine. See the
			// v0.10.226 CHANGELOG entry for the full forensic trail.
			existing.IsSecret = s.IsSecret
			if err := h.db.Gorm().Save(&existing).Error; err != nil {
				log.Printf("Failed to save setting %s: %v", s.Key, err)
				failedKeys = append(failedKeys, s.Key)
				continue
			}
		}
	}

	if len(failedKeys) > 0 {
		httputil.InternalError(c, fmt.Sprintf("Failed to save %d setting(s)", len(failedKeys)), nil)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"message":  "Settings updated",
		"warnings": warnings,
	}))
}

// getNotificationSetting reads a key from system_settings, falling back to config.
//
// v0.10.226: drop the s.IsSecret gate — DecryptField is idempotent for
// values that don't carry the "{enc}" prefix (see internal/database/crypto.go),
// so calling it unconditionally is safe for both encrypted secrets AND
// plaintext settings. The old gate was load-bearing on UpdateSettings
// correctly persisting is_secret, which it didn't — every SMTP test was
// shipping the raw "{enc}<base64>" ciphertext to the mail server as the
// password. Keying off the value's actual prefix (inside DecryptField)
// instead of an out-of-band flag makes the read path robust to any
// existing DB rows where is_secret is wrong.
func (h *Handler) getNotificationSetting(key string) string {
	if h.db != nil {
		var s models.SystemSetting
		if err := h.db.Gorm().Where("\"key\" = ?", key).First(&s).Error; err == nil && s.Value != "" {
			return h.db.DecryptField(s.Value)
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
	Hint     string `json:"hint,omitempty"`     // optional operator-facing remediation hint (v0.10.224)
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
		// v0.10.224: attach an operator-facing remediation hint to the
		// failed step when the error matches a known pattern (Postfix
		// (reason unavailable), 504 unrecognized auth, etc.). The hint
		// is what the operator should *do next*, not a restatement of
		// the error — see authFailureHint().
		errStr := err.Error()
		hint := ""
		if step == "auth" {
			hint = authFailureHint(errStr)
		}
		trace = append(trace, smtpTraceStep{
			Step:   step,
			Detail: detail,
			Status: "fail",
			Error:  errStr,
			Hint:   hint,
			DurMs:  time.Since(start).Milliseconds(),
		})
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
	// negotiatedTLS tracks whether the connection is currently encrypted.
	// v0.10.222 (bundle J): the previous AUTH pre-check re-queried
	// Extension("STARTTLS") to decide if we were on TLS, but RFC 3207 §2
	// is explicit that a server MUST NOT advertise STARTTLS over an
	// already-secured connection. So Extension("STARTTLS") is false after
	// a successful STARTTLS upgrade, and the pre-check was misreading that
	// as "no TLS". This flag is the authoritative source.
	negotiatedTLS := false
	if usingImplicitTLS {
		tStart := time.Now()
		tlsConn := tls.Client(netConn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			summary, _ = fail("tls", "implicit TLS handshake (port 465)", tStart, err)
			return trace, false, summary
		}
		st := tlsConn.ConnectionState()
		record("tls", "implicit TLS handshake (port 465)",
			tlsLeafSummary(st),
			"ok", "", tStart)
		netConn = tlsConn
		negotiatedTLS = true
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
	// v0.10.221 fix: the stdlib smtp.Client allows Hello() to be called
	// at most once. StartTLS internally re-issues EHLO over the encrypted
	// channel using the localName saved by the first Hello() call. The
	// earlier code called Hello() a second time after StartTLS, which the
	// stdlib rejects with "Hello called after other methods" — masking
	// every downstream step (including the AUTH step the operator was
	// actually trying to debug).
	if !usingImplicitTLS {
		tStart := time.Now()
		if hasStartTLS, _ := client.Extension("STARTTLS"); hasStartTLS {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				summary, _ = fail("starttls", "STARTTLS upgrade", tStart, err)
				return trace, false, summary
			}
			// Pull TLS state for the trace via the stdlib accessor
			// (Go 1.20+). The implicit post-StartTLS EHLO has already
			// run by the time we get here.
			var tlsDetail string
			if st, ok := client.TLSConnectionState(); ok {
				tlsDetail = tlsLeafSummary(st)
			} else {
				tlsDetail = "established"
			}
			record("starttls", "STARTTLS upgrade (EHLO re-issued internally)", tlsDetail, "ok", "", tStart)
			negotiatedTLS = true
		} else {
			record("starttls", "STARTTLS not advertised by server", "skipped", "skipped", "", tStart)
		}
	}

	// ----- AUTH -----
	// v0.10.222 (bundle J):
	//   1. Refuse to send credentials over a still-cleartext connection.
	//      Use the negotiatedTLS flag rather than Extension("STARTTLS")
	//      because the latter is intentionally false post-upgrade.
	//   2. Use CompoundAuth to pick PLAIN (preferred) or LOGIN based on
	//      what the server advertises. Earlier versions only did PLAIN,
	//      which fails on LOGIN-only Postfix/Cyrus/Dovecot submission
	//      servers with a confusing "unrecognized authentication type"
	//      error.
	aStart := time.Now()
	authMechs := ""
	if supported, mechs := client.Extension("AUTH"); supported {
		authMechs = mechs
	}
	if username != "" {
		if !negotiatedTLS {
			summary, _ = fail("auth",
				"auth refused: connection is not encrypted (no implicit TLS on this port and STARTTLS was not advertised by the server)",
				aStart, errors.New("unencrypted connection"))
			return trace, false, summary
		}
		compound := notifier.CompoundAuth(username, password, host).(interface {
			smtp.Auth
			ChosenMechanism() string
		})
		if err := client.Auth(compound); err != nil {
			detail := fmt.Sprintf("auth as %s (server advertised mechs: %s; selected: %s)",
				username, authMechs, compound.ChosenMechanism())
			summary, _ = fail("auth", detail, aStart, err)
			return trace, false, summary
		}
		record("auth",
			fmt.Sprintf("%s auth as %s", compound.ChosenMechanism(), username),
			"accepted (mechs offered: "+authMechs+"; selected: "+compound.ChosenMechanism()+")",
			"ok", "", aStart)
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

// tlsLeafSummary returns "TLS-VERSION, CIPHER, CN=…, expires YYYY-MM-DD"
// for the trace TLS step. NotAfter is included because cert expiry is
// a top-3 operator-debuggable cause of "test send works fine in the
// staging UI but fails in prod 24h later" — every reputable mail
// admin UI (Mailcow, Mail-in-a-Box, Mailu) surfaces it; v0.10.220-223
// didn't (v0.10.224).
func tlsLeafSummary(st tls.ConnectionState) string {
	base := fmt.Sprintf("%s, %s, cert CN=%s",
		tlsVersionName(st.Version), tlsCipherName(st.CipherSuite), tlsLeafSubject(st))
	if len(st.PeerCertificates) > 0 {
		base += ", expires " + st.PeerCertificates[0].NotAfter.UTC().Format("2006-01-02")
	}
	return base
}

// authFailureHint inspects the AUTH error string from the stdlib smtp
// client and returns an operator-facing remediation hint, or "" if the
// failure doesn't match any pattern we recognise.
//
// The current target is Postfix's "535 5.7.8 ... (reason unavailable)"
// reply. Per the Postfix source (src/smtpd/smtpd_sasl_glue.c), that
// literal placeholder is emitted when Postfix's SASL plugin returned
// FAIL with an empty reason — and per the Dovecot auth-protocol docs
// (doc.dovecot.org/main/developers/design/auth_protocol.html), Dovecot
// DELIBERATELY omits the `reason=` field for the most common failure
// modes ("MUST NOT reveal exact failure reasons like user not found vs
// password mismatch"). So the real diagnostic the operator needs is
// always in Dovecot's own auth log on the mail server — Postfix /
// SMTP cannot surface it on the wire.
//
// Sources researched in v0.10.224:
//   - https://github.com/vdukhovni/postfix/blob/master/postfix/src/smtpd/smtpd_sasl_glue.c
//   - https://doc.dovecot.org/main/developers/design/auth_protocol.html
//   - https://doc.dovecot.org/main/howto/sasl/postfix.html
func authFailureHint(errStr string) string {
	lc := strings.ToLower(errStr)
	if strings.Contains(lc, "535") && strings.Contains(lc, "reason unavailable") {
		return "Postfix emits '(reason unavailable)' when its SASL plugin returned FAIL without a reason — most commonly Dovecot, which intentionally suppresses the per-failure reason on the wire (auth_protocol design). The actual cause is logged on the MAIL SERVER side. SSH to the mail host and run: `journalctl -u dovecot --since '5 min ago'` (or `tail /var/log/dovecot.log`). Look for an auth-worker line keyed to your username with `reason=…` — that line contains the real failure (wrong password, unknown user, mech mismatch, passdb error, etc.). If Dovecot logs nothing for this attempt, the auth never reached Dovecot → check the `private/auth` socket permissions on the Postfix side."
	}
	if strings.Contains(lc, "535") {
		return "535 from the mail server: credentials were rejected. Try testing the same username/password against the server's webmail or IMAP service to isolate whether the credentials themselves are valid before debugging SMTP-specific config. If the SMTP submission service uses Dovecot SASL, check Dovecot's auth log on the mail host for the underlying reason — Postfix passes through whatever Dovecot returns."
	}
	if strings.Contains(lc, "504") && strings.Contains(lc, "unrecognized authentication") {
		return "Server rejected the auth mechanism. Re-check the EHLO row above for the AUTH mechs the server advertises; if the list is empty the server doesn't accept SMTP AUTH on this port — Postfix typically only enables auth on the submission port (587) and SMTPS (465), not the public MX port (25)."
	}
	return ""
}

func (h *Handler) TestEmail(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}

	smtpHost := h.getNotificationSetting("smtp_host")
	smtpPortStr := h.getNotificationSetting("smtp_port")
	smtpUsername := h.getNotificationSetting("smtp_username")
	smtpPassword := h.getNotificationSetting("smtp_password")
	smtpFrom := h.getNotificationSetting("smtp_from")
	smtpTo := h.getNotificationSetting("smtp_to")

	// Allow a per-test recipient override without rewriting saved
	// settings (v0.10.220, bundle I). The v0.10.223 username override
	// was removed in v0.10.224 — no reputable mail admin tool (Mailcow,
	// Mailu, Postal, swaks-the-CLI) exposes a username-only test field,
	// and it turns this endpoint into a free credential-stuffing oracle
	// against an arbitrary external SMTP server for any authenticated
	// admin (or anyone who phishes/CSRFs an admin session). If we ever
	// need to test alternate credentials, the right shape is an
	// explicit ad-hoc-credentials test that takes BOTH username and
	// password and is rate-limited + audit-logged — not a half-override
	// that pairs typed-in usernames with the saved password.
	var req struct {
		ToOverride string `json:"to"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.ToOverride != "" {
		smtpTo = req.ToOverride
	}

	if smtpHost == "" || smtpFrom == "" || smtpTo == "" {
		c.JSON(http.StatusBadRequest, response.Error("SMTP host, sender, and recipient address are required"))
		return
	}

	// Validate SMTP host to prevent SSRF / internal port scanning
	if !isValidExternalIP(smtpHost) {
		c.JSON(http.StatusBadRequest, response.Error("SMTP host resolves to a blocked address"))
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

	// v0.10.224: dropped username_len / password_len fields shipped in
	// v0.10.223. swaks (the de-facto SMTP test CLI) goes the opposite
	// direction with --auth-hide-password — its documented stance is to
	// keep credential data out of transcripts entirely. Even for an
	// authenticated admin session, password byte length is information
	// disclosure that narrows the search space for anyone who later
	// scrapes the response from browser history / a proxy log / a
	// forwarded screenshot. The "did trim change the password?" signal
	// that password_len was supposed to provide is now surfaced at SAVE
	// time instead (see UpdateSettings — passwords are no longer
	// silently trimmed).
	c.JSON(http.StatusOK, response.Success(gin.H{
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

// authMethodLabel reports the configured auth posture for the summary
// chip. v0.10.222 (bundle J): the test now auto-selects PLAIN or LOGIN
// at AUTH time, so the label is "auto" rather than a fixed mechanism.
// The trace row reports which mechanism actually got selected.
func authMethodLabel(username string) string {
	if username == "" {
		return "none"
	}
	return "auto (PLAIN→LOGIN fallback)"
}

func (h *Handler) TestWebhook(c *gin.Context) {
	var req struct {
		Type string `json:"type" binding:"required"`
		URL  string `json:"url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request: type is required"))
		return
	}

	webhookURL := req.URL
	if webhookURL == "" {
		// Fall back to DB/config
		webhookURL = h.getNotificationSetting(req.Type)
	}

	if webhookURL == "" {
		c.JSON(http.StatusBadRequest, response.Error("No webhook URL configured"))
		return
	}

	// Validate URL scheme and host to prevent SSRF
	parsed, err := url.Parse(webhookURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		c.JSON(http.StatusBadRequest, response.Error("Invalid webhook URL: must be http or https"))
		return
	}
	hostname := parsed.Hostname()
	if !isValidExternalIP(hostname) {
		c.JSON(http.StatusBadRequest, response.Error("Webhook URL resolves to a blocked address"))
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
		httputil.InternalError(c, "Failed to build payload", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	httpReq, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Invalid URL: %v", err)))
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"success": false,
			"message": fmt.Sprintf("Failed to reach webhook: %v", err),
		}))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"success": false,
			"message": fmt.Sprintf("Webhook returned status %d", resp.StatusCode),
		}))
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
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
