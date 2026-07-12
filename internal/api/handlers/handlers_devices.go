package handlers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/config"
	"firewall-mon/internal/configdiff"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/snmp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (h *Handler) GetDevices(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]models.Device{}))
		return
	}

	devices, err := db.GetAllDevices()
	if err != nil {
		httputil.InternalError(c, "Failed to get devices", err)
		return
	}

	httputil.RedactDevices(devices)

	c.JSON(http.StatusOK, response.Success(devices))
}

func (h *Handler) CreateDevice(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var device models.Device
	if err := c.ShouldBindJSON(&device); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// Validate required fields
	if strings.TrimSpace(device.Name) == "" || strings.TrimSpace(device.IPAddress) == "" {
		c.JSON(http.StatusBadRequest, response.Error("Name and IP address are required"))
		return
	}

	// Length validation
	if len(device.Name) > 255 || len(device.Hostname) > 255 || len(device.IPAddress) > 255 {
		c.JSON(http.StatusBadRequest, response.Error("Name, hostname, and IP address must be 255 characters or less"))
		return
	}
	if len(device.Location) > 500 || len(device.Description) > 1000 {
		c.JSON(http.StatusBadRequest, response.Error("Location (max 500) or description (max 1000) too long"))
		return
	}

	// Default and validate vendor
	if device.Vendor == "" {
		device.Vendor = "fortigate"
	}
	if !isValidVendor(device.Vendor) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid vendor: must be fortigate, paloalto, cisco_asa, sonicwall, firewalla, pfsense, opnsense, or generic"))
		return
	}

	// Validate IP to prevent SSRF - skip for probe-managed devices (they use private IPs)
	if device.ProbeID == nil || *device.ProbeID == 0 {
		if !isValidExternalIP(device.IPAddress) {
			c.JSON(http.StatusBadRequest, response.Error("Invalid or disallowed IP address"))
			return
		}
	}

	// Default and validate SNMP port
	if device.SNMPPort == 0 {
		device.SNMPPort = 161
	}
	if device.SNMPPort < 1 || device.SNMPPort > 65535 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid SNMP port"))
		return
	}

	device.ID = 0
	device.Status = "unknown"
	device.CreatedAt = time.Time{}
	device.UpdatedAt = time.Time{}
	device.LastPolled = time.Time{}
	if err := db.CreateDevice(&device); err != nil {
		httputil.InternalError(c, "Failed to create device", err)
		return
	}

	httputil.RedactDevice(&device)
	c.JSON(http.StatusCreated, response.Success(device))
}

func (h *Handler) UpdateDevice(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	device, err := db.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":              true,
		"hostname":          true,
		"ip_address":        true,
		"snmp_port":         true,
		"snmp_community":    true,
		"snmp_version":      true,
		"snmpv3_username":   true,
		"snmpv3_auth_type":  true,
		"snmpv3_auth_pass":  true,
		"snmpv3_priv_type":  true,
		"snmpv3_priv_pass":  true,
		"location":          true,
		"description":       true,
		"enabled":           true,
		"public_visible":    true,
		"site_id":           true,
		"probe_id":          true,
		"vendor":            true,
		"ssh_username":      true,
		"ssh_password":      true,
		"ssh_port":          true,
		"ssh_poll_enabled":  true,
		"ssh_poll_interval": true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	filteredUpdates := httputil.FilterAllowedFields(updates, allowedFields)

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("No valid fields to update"))
		return
	}

	// Validate string field lengths
	stringLimits := map[string]int{
		"name": 255, "hostname": 255, "ip_address": 255,
		"location": 500, "description": 1000,
		"snmp_community": 255, "snmpv3_username": 255,
	}
	for field, maxLen := range stringLimits {
		if val, ok := filteredUpdates[field]; ok {
			if str, isStr := val.(string); isStr && len(str) > maxLen {
				c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("Field %s exceeds max length of %d", field, maxLen)))
				return
			}
		}
	}

	// Validate snmp_port is a valid number if present
	if portVal, ok := filteredUpdates["snmp_port"]; ok {
		port, isNum := portVal.(float64) // JSON numbers decode as float64
		if !isNum || port < 1 || port > 65535 || port != float64(int(port)) {
			c.JSON(http.StatusBadRequest, response.Error("Invalid SNMP port"))
			return
		}
	}

	// Validate ip_address if present - skip for probe-managed devices (they use private IPs)
	if ipVal, ok := filteredUpdates["ip_address"]; ok {
		if device.ProbeID != nil && *device.ProbeID > 0 {
		} else {
			ipStr, isStr := ipVal.(string)
			if !isStr || !isValidExternalIP(ipStr) {
				c.JSON(http.StatusBadRequest, response.Error("Invalid or disallowed IP address"))
				return
			}
		}
	}

	// Validate enabled is boolean if present
	if enabledVal, ok := filteredUpdates["enabled"]; ok {
		if _, isBool := enabledVal.(bool); !isBool {
			c.JSON(http.StatusBadRequest, response.Error("Invalid value for enabled"))
			return
		}
	}

	// Validate vendor if present
	if vendorVal, ok := filteredUpdates["vendor"]; ok {
		vendorStr, isStr := vendorVal.(string)
		if !isStr || !isValidVendor(vendorStr) {
			c.JSON(http.StatusBadRequest, response.Error("Invalid vendor: must be fortigate, paloalto, cisco_asa, sonicwall, firewalla, pfsense, opnsense, or generic"))
			return
		}
	}

	// Validate the target probe exists when reassigning. Without this, an
	// UPDATE that sets probe_id to a non-existent probe fails with an opaque
	// foreign-key-violation 500 and the WHOLE update rolls back — so the device
	// silently keeps its previous probe, which presents to the operator as
	// "the reassignment saved but reverted on refresh". A nil/0 value is the
	// explicit "unassign" case and is allowed.
	if probeVal, ok := filteredUpdates["probe_id"]; ok && probeVal != nil {
		pf, isNum := probeVal.(float64) // JSON numbers decode as float64
		if !isNum || pf < 0 || pf != float64(int(pf)) {
			c.JSON(http.StatusBadRequest, response.Error("Invalid probe ID"))
			return
		}
		if pf > 0 {
			if _, err := db.GetProbe(uint(pf)); err != nil {
				c.JSON(http.StatusBadRequest, response.Error("Target probe not found"))
				return
			}
		}
	}

	// Encrypt SNMP secrets before database write.
	//
	// CRITICAL: the GET endpoints mask these fields as RedactedMask ("********").
	// A client that loads a device and saves it back resends the mask. We must
	// treat the mask (and an empty string) as "leave unchanged" and drop the
	// field — persisting the mask would overwrite the real secret with
	// "********", which silently breaks SNMP polling for that device (the
	// collector then polls with "********" and every request times out).
	for _, field := range []string{"snmp_community", "snmpv3_auth_pass", "snmpv3_priv_pass"} {
		val, ok := filteredUpdates[field]
		if !ok {
			continue
		}
		str, isStr := val.(string)
		if !isStr || str == "" || str == httputil.RedactedMask {
			delete(filteredUpdates, field)
			continue
		}
		filteredUpdates[field] = db.EncryptField(str)
	}

	// Encrypt SSH password if present. ssh_password is now redacted on GET
	// (v0.11.78), so the client resends the mask on an unchanged save — treat the
	// mask (and empty) as "leave unchanged" exactly like the SNMP secrets above.
	if sshPw, ok := filteredUpdates["ssh_password"]; ok {
		str, isStr := sshPw.(string)
		if !isStr || str == "" || str == httputil.RedactedMask {
			delete(filteredUpdates, "ssh_password")
		} else {
			filteredUpdates["ssh_password"] = db.EncryptField(str)
		}
	}

	// Write via Model(&Device{}).Where(id) rather than Model(device). The
	// `device` here was loaded by GetDevice, which Preload("Probe")/Preload(
	// "Site") — so it carries loaded belongs-to associations. gorm's
	// Model(loadedStruct).Updates(map) re-derives the foreign keys from those
	// loaded associations (the OLD probe/site) and overrides probe_id/site_id in
	// the map, silently reverting any reassignment. Passing a bare model + WHERE
	// makes gorm honor the map values verbatim.
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", id).Updates(filteredUpdates).Error; err != nil {
		httputil.InternalError(c, "Failed to update device", err)
		return
	}

	// Re-fetch to return fresh data
	updated, err := db.GetDevice(id)
	if err != nil {
		httputil.RedactDevice(device)
		c.JSON(http.StatusOK, response.Success(device))
		return
	}
	httputil.RedactDevice(updated)
	c.JSON(http.StatusOK, response.Success(updated))
}

func (h *Handler) DeleteDevice(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	if err := db.DeleteDevice(id); err != nil {
		httputil.InternalError(c, "Failed to delete device", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Device deleted"))
}

// revealableDeviceSecrets is the whitelist of device credential fields the
// reveal endpoint may return in plaintext. Anything not listed is rejected, so
// the endpoint can never be turned into a general field dumper.
var revealableDeviceSecrets = map[string]func(*models.Device) string{
	"ssh_password":     func(d *models.Device) string { return d.SSHPassword },
	"snmp_community":   func(d *models.Device) string { return d.SNMPCommunity },
	"snmpv3_auth_pass": func(d *models.Device) string { return d.SNMPV3AuthPass },
	"snmpv3_priv_pass": func(d *models.Device) string { return d.SNMPV3PrivPass },
}

// RevealDeviceSecret returns ONE decrypted device credential in plaintext, so an
// operator can recover/confirm a stored secret (e.g. an SSH admin password) they
// otherwise only see masked. It is deliberately narrow and defense-in-depth:
//
//   - admin-only (the route is in adminOnlyRoutes) and rate-limited at the route;
//   - re-verifies the CALLER'S OWN password before returning anything, so a
//     hijacked but idle admin session can't harvest credentials;
//   - whitelists the field, so it can't be coerced into dumping arbitrary data;
//   - writes an explicit audit record naming who revealed which field on which
//     device (the audit middleware also records the attempt + status, including
//     a failed password check, independently).
//
// The plaintext is returned in the JSON body only; it is NEVER written to a log.
func (h *Handler) RevealDeviceSecret(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	username, _ := c.Get("username")
	userIDVal, _ := c.Get("user_id")
	usernameStr, _ := username.(string)
	userID, _ := userIDVal.(uint)
	if usernameStr == "" {
		c.JSON(http.StatusUnauthorized, response.Error("Not authenticated"))
		return
	}

	var req struct {
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
		Field    string `json:"field"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	extract, allowed := revealableDeviceSecrets[req.Field]
	if !allowed {
		c.JSON(http.StatusBadRequest, response.Error("Unknown secret field"))
		return
	}
	if req.Password == "" {
		c.JSON(http.StatusForbidden, response.Error("Password is required"))
		return
	}

	// Re-verify the caller's own password. Resolve the admin by the JWT username
	// (never a request-supplied identity) so this can only confirm the caller.
	admin, err := db.GetAdminByUsername(usernameStr)
	if err != nil || admin == nil || !h.authManager.CheckPassword(req.Password, admin.Password) {
		c.JSON(http.StatusForbidden, response.Error("Password is incorrect"))
		return
	}
	// Step-up: if the caller has 2FA enrolled, a valid TOTP code is also
	// required — so a phished password + stolen session (which alone couldn't
	// pass a fresh 2FA login) can't be escalated into bulk credential harvesting.
	if admin.TOTPEnabled {
		if req.TOTPCode == "" {
			c.JSON(http.StatusForbidden, response.Error("Authenticator code required"))
			return
		}
		if !validateTOTPCode(req.TOTPCode, admin.TOTPSecret) {
			c.JSON(http.StatusForbidden, response.Error("Authenticator code is incorrect"))
			return
		}
	}

	device, err := db.GetDevice(id) // secrets decrypted in-place by the store
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}
	secret := extract(device)
	if secret == "" {
		c.JSON(http.StatusNotFound, response.Error("No value is stored for that field"))
		return
	}

	// Explicit forensic record: WHO revealed WHICH field on WHICH device. The
	// value itself is never logged. Best-effort — a log failure must not block
	// the operator's legitimate recovery.
	if err := db.SaveAuditLog(&models.AuditLog{
		CreatedAt: time.Now(),
		Actor:     usernameStr,
		ActorID:   userID,
		Method:    "POST",
		Action:    "reveal_secret",
		Target:    fmt.Sprintf("device_id=%d field=%s", id, req.Field),
		Status:    http.StatusOK,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}); err != nil {
		log.Printf("reveal-secret: audit log write failed for device %d field %s by %s: %v", id, req.Field, usernameStr, err)
	}

	c.JSON(http.StatusOK, response.Success(gin.H{"field": req.Field, "secret": secret}))
}

func (h *Handler) GetDeviceDetail(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	device, err := db.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}

	// Redact secrets
	httputil.RedactDevice(device)

	// Latest system status
	var systemStatus *models.SystemStatus
	var ss models.SystemStatus
	if err := db.Gorm().Where("device_id = ?", id).Order("timestamp DESC").First(&ss).Error; err == nil {
		systemStatus = &ss
	}

	// Helper: get all records at the latest timestamp for a device (single query with subquery)
	gdb := db.Gorm()
	latestSnapshotQuery := func(table string) *gorm.DB {
		return gdb.Where("device_id = ? AND timestamp = (SELECT MAX(timestamp) FROM "+table+" WHERE device_id = ?)", id, id)
	}

	// Latest interface stats
	var interfaces []models.InterfaceStats
	if err := latestSnapshotQuery("interface_stats").Find(&interfaces).Error; err != nil {
		log.Printf("Device %d: failed to get interface stats: %v", id, err)
	}

	// Union with sFlow-only interfaces (audit L18): a device that is SNMP
	// host-restricted but pushes sFlow if_counters has no interface_stats
	// snapshot, so it would render zero interface cards and the sflow-chart
	// endpoint — the whole point of the feature — would never be called. Add a
	// synthetic card for each flow if_index not already present, so the operator
	// sees the interface and clicking it hits loadInterfaceChart → sflow-chart.
	if counters, err := db.GetLatestInterfaceCountersByDevice(id); err != nil {
		log.Printf("Device %d: failed to get sFlow interface counters: %v", id, err)
	} else if len(counters) > 0 {
		haveIdx := make(map[int]struct{}, len(interfaces))
		for _, iface := range interfaces {
			haveIdx[iface.Index] = struct{}{}
		}
		for _, ctr := range counters {
			idx := int(ctr.IfIndex)
			if _, ok := haveIdx[idx]; ok {
				continue
			}
			haveIdx[idx] = struct{}{}
			status := "up"
			if ctr.IfStatus == 0 {
				status = "unknown"
			}
			interfaces = append(interfaces, models.InterfaceStats{
				DeviceID:  id,
				Timestamp: ctr.Timestamp,
				Name:      fmt.Sprintf("if%d", idx), // sFlow counters carry no ifName
				Index:     idx,
				Type:      int(ctr.IfType),
				Speed:     ctr.IfSpeed,
				Status:    status,
				InBytes:   ctr.InOctets,
				InErrors:  ctr.InErrors,
				OutBytes:  ctr.OutOctets,
				OutErrors: ctr.OutErrors,
			})
		}
	}

	// Latest VPN statuses
	vpnStatuses, err := db.GetLatestVPNStatuses(id)
	if err != nil {
		log.Printf("Device %d: failed to get VPN statuses: %v", id, err)
	}

	// Latest hardware sensors
	var sensors []models.HardwareSensor
	if err := latestSnapshotQuery("hardware_sensors").Find(&sensors).Error; err != nil {
		log.Printf("Device %d: failed to get hardware sensors: %v", id, err)
	} else {
		log.Printf("Device %d: got %d hardware sensors", id, len(sensors))
		for i, s := range sensors {
			log.Printf("Device %d: sensor[%d] name=%q value=%.1f unit=%q status=%q", id, i, s.Name, s.Value, s.Unit, s.Status)
		}
	}

	// Latest processor stats
	processorStats, err := db.GetLatestProcessorStats(id)
	if err != nil {
		log.Printf("Device %d: failed to get processor stats: %v", id, err)
	}

	// Recent alerts
	var recentAlerts []models.Alert
	if err := gdb.Where("device_id = ?", id).Order("timestamp DESC").Limit(20).Find(&recentAlerts).Error; err != nil {
		log.Printf("Device %d: failed to get recent alerts: %v", id, err)
	}

	// Ping stats
	var pingStats []models.PingStats
	if err := gdb.Where("device_id = ?", id).Order("updated_at DESC").Limit(100).Find(&pingStats).Error; err != nil {
		log.Printf("Device %d: failed to get ping stats: %v", id, err)
	}

	// Latest HA status
	var haStatus []models.HAStatus
	if err := latestSnapshotQuery("ha_status").Find(&haStatus).Error; err != nil {
		log.Printf("Device %d: failed to get HA status: %v", id, err)
	}

	// Latest security stats
	var securityStats *models.SecurityStats
	var secStats models.SecurityStats
	if err := gdb.Where("device_id = ?", id).Order("timestamp DESC").First(&secStats).Error; err == nil {
		securityStats = &secStats
	}

	// Latest SD-WAN health
	var sdwanHealth []models.SDWANHealth
	if err := latestSnapshotQuery("sdwan_health").Find(&sdwanHealth).Error; err != nil {
		log.Printf("Device %d: failed to get SD-WAN health: %v", id, err)
	}

	// Latest license info
	var licenseInfo []models.LicenseInfo
	if err := latestSnapshotQuery("license_info").Find(&licenseInfo).Error; err != nil {
		log.Printf("Device %d: failed to get license info: %v", id, err)
	}

	// Latest disk usage (one row per mount, shared timestamp)
	var diskUsage []models.DiskUsage
	if err := latestSnapshotQuery("disk_usage").Find(&diskUsage).Error; err != nil {
		log.Printf("Device %d: failed to get disk usage: %v", id, err)
	}

	// Latest load average (single row)
	var loadAverage *models.LoadAverage
	var la models.LoadAverage
	if err := gdb.Where("device_id = ?", id).Order("timestamp DESC").First(&la).Error; err == nil {
		loadAverage = &la
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Printf("Device %d: failed to get load average: %v", id, err)
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"device":           device,
		"system_status":    systemStatus,
		"interfaces":       interfaces,
		"vpn_status":       vpnStatuses,
		"hardware_sensors": sensors,
		"processor_stats":  processorStats,
		"disk_usage":       diskUsage,
		"load_average":     loadAverage,
		"recent_alerts":    recentAlerts,
		"ping_stats":       pingStats,
		"ha_status":        haStatus,
		"security_stats":   securityStats,
		"sdwan_health":     sdwanHealth,
		"license_info":     licenseInfo,
	}))
}

func (h *Handler) GetDeviceStatusHistory(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	// New mode (v0.10.205+): if the client passes ?range=, return server-side
	// bucketed data shaped for uPlot — one row per bucket with AVG-aggregated
	// metrics. This is what the device-detail page uses now. The legacy
	// "?hours=N → raw rows" mode is kept for backward compatibility with any
	// external caller that still relies on it.
	if rangeStr := c.Query("range"); rangeStr != "" {
		buckets, err := db.GetSystemStatusBuckets(id, rangeStr)
		if err != nil {
			httputil.InternalError(c, "Failed to get status history", err)
			return
		}
		c.JSON(http.StatusOK, response.Success(gin.H{
			"buckets": buckets,
			"range":   rangeStr,
		}))
		return
	}

	hours := httputil.ParseHours(c)

	statuses, err := db.GetSystemStatusHistory(id, hours)
	if err != nil {
		httputil.InternalError(c, "Failed to get status history", err)
		return
	}

	pingHistory, err := db.GetPingResultHistory(id, hours)
	if err != nil {
		// Non-fatal: return system status without ping data
		pingHistory = nil
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"system_status": statuses,
		"ping_history":  pingHistory,
	}))
}

func (h *Handler) GetInterfaceHistory(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	deviceID := c.Param("id")
	ifIndex := c.Param("ifIndex")

	deviceIDUint, err := strconv.ParseUint(deviceID, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}

	ifIndexInt, err := strconv.Atoi(ifIndex)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid interface index"))
		return
	}

	hours := httputil.ParseHours(c)

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	var stats []models.InterfaceStats
	err = db.Gorm().Where("device_id = ? AND \"index\" = ? AND timestamp > ?", deviceIDUint, ifIndexInt, since).
		Order("timestamp ASC").Limit(500).Find(&stats).Error
	if err != nil {
		httputil.InternalError(c, "Failed to get interface history", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(stats))
}

func (h *Handler) GetInterfaceChart(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	deviceID := c.Param("id")
	ifIndex := c.Param("ifIndex")

	deviceIDUint, err := strconv.ParseUint(deviceID, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}

	ifIndexInt, err := strconv.Atoi(ifIndex)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid interface index"))
		return
	}

	// Window resolution (v0.10.410): an explicit from/to pair (epoch ms, from
	// the drag-to-zoom selection) re-queries that sub-window at finer
	// resolution; otherwise the range preset maps to [now-dur, now]. Adaptive
	// bucketing keeps the point count readable at every zoom level.
	from, to := httputil.ParseChartWindow(c, "24h")
	buckets, err := db.GetInterfaceChartWindow(uint(deviceIDUint), ifIndexInt, from, to)
	if err != nil {
		httputil.InternalError(c, "Failed to get chart data", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(buckets))
}

// GetInterfaceSFlowChart is the sFlow-native counterpart of GetInterfaceChart:
// it serves interface bandwidth from flow_if_counters (agent-pushed) instead of
// SNMP interface_stats. Same response shape, so the frontend renders it with the
// same code and falls back to the SNMP endpoint when this returns no data.
func (h *Handler) GetInterfaceSFlowChart(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	deviceIDUint, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}
	ifIndexInt, err := strconv.Atoi(c.Param("ifIndex"))
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid interface index"))
		return
	}

	from, to := httputil.ParseChartWindow(c, "24h")
	buckets, err := db.GetFlowInterfaceChartWindow(uint(deviceIDUint), ifIndexInt, from, to)
	if err != nil {
		httputil.InternalError(c, "Failed to get sFlow chart data", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(buckets))
}

type TestDeviceRequest struct {
	IPAddress      string `json:"ip_address" binding:"required"`
	SNMPPort       int    `json:"snmp_port"`
	SNMPCommunity  string `json:"snmp_community"`
	SNMPVersion    string `json:"snmp_version"`
	SNMPV3Username string `json:"snmpv3_username"`
	SNMPV3AuthType string `json:"snmpv3_auth_type"`
	SNMPV3AuthPass string `json:"snmpv3_auth_pass"`
	SNMPV3PrivType string `json:"snmpv3_priv_type"`
	SNMPV3PrivPass string `json:"snmpv3_priv_pass"`
	ProbeID        *uint  `json:"probe_id"`
}

func (h *Handler) TestDeviceConnection(c *gin.Context) {
	var req TestDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if req.SNMPPort == 0 {
		req.SNMPPort = 161
	}
	if req.SNMPPort < 1 || req.SNMPPort > 65535 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid SNMP port"))
		return
	}
	if req.SNMPVersion == "" {
		req.SNMPVersion = "2c"
	}
	// Require community string for v1/v2c (do not default to insecure "public")
	if req.SNMPCommunity == "" && (req.SNMPVersion == "1" || req.SNMPVersion == "2c") {
		c.JSON(http.StatusBadRequest, response.Error("SNMP community string is required for v1/v2c"))
		return
	}

	// Validate IP to prevent SSRF against internal services
	if !isValidExternalIP(req.IPAddress) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid or disallowed IP address"))
		return
	}

	// Probe-managed devices cannot be tested from the API server
	if req.ProbeID != nil && *req.ProbeID > 0 {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"success":       false,
			"probe_managed": true,
			"message":       "Device is managed by a remote probe. Direct test not available — the probe polls this device automatically.",
		}))
		return
	}

	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			SNMPHost:   req.IPAddress,
			SNMPPort:   req.SNMPPort,
			Community:  req.SNMPCommunity,
			Version:    req.SNMPVersion,
			V3Username: req.SNMPV3Username,
			V3AuthType: req.SNMPV3AuthType,
			V3AuthPass: req.SNMPV3AuthPass,
			V3PrivType: req.SNMPV3PrivType,
			V3PrivPass: req.SNMPV3PrivPass,
			Timeout:    10 * time.Second,
			Retries:    1,
		},
	}

	client, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("TestDevice connect error for %s: %v", req.IPAddress, err)
		c.JSON(http.StatusOK, response.Success(gin.H{
			"success": false,
			"message": "Connection test failed: unable to reach device",
			"online":  false,
		}))
		return
	}
	defer client.Close()

	status, err := client.GetSystemStatus()
	if err != nil {
		log.Printf("TestDevice poll error for %s: %v", req.IPAddress, err)
		c.JSON(http.StatusOK, response.Success(gin.H{
			"success": false,
			"message": "Connection test failed: device did not respond to SNMP query",
			"online":  false,
		}))
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"success":  true,
		"message":  "Connected successfully",
		"online":   true,
		"hostname": status.Hostname,
		"version":  status.Version,
		"cpu":      status.CPUUsage,
		"memory":   status.MemoryUsage,
		"sessions": status.SessionCount,
		"uptime":   status.Uptime,
	}))
}

func (h *Handler) GetDeviceSecurityStats(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}
	// Unified parsing (v0.10.217, bundle D2). 720h cap retained for the
	// per-device process/security stats — going further back is unsafe
	// on busy fleets (millions of rows).
	hours := httputil.ParseHours(c)
	if hours > 720 {
		hours = 720
	}

	latest, err := db.GetLatestSecurityStats(uint(id))
	if err != nil {
		log.Printf("Device %d: failed to get latest security stats: %v", id, err)
	}
	history, err := db.GetSecurityStatsHistory(uint(id), hours)
	if err != nil {
		log.Printf("Device %d: failed to get security stats history: %v", id, err)
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"latest":  latest,
		"history": history,
	}))
}

func (h *Handler) GetDeviceSDWANHealth(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}

	health, err := db.GetLatestSDWANHealth(uint(id))
	if err != nil {
		httputil.InternalError(c, "Failed to get SD-WAN health", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"health": health}))
}

func (h *Handler) GetDeviceHAStatus(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}

	ha, err := db.GetLatestHAStatus(uint(id))
	if err != nil {
		httputil.InternalError(c, "Failed to get HA status", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"ha_status": ha}))
}

func (h *Handler) GetDeviceConfigHistory(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}

	// In v0.10.198+ the table contains one row per logical config state thanks
	// to merge-into-latest, so this is always a simple newest-first list.
	// `?distinct=true` is accepted for one release for backward-compat with
	// older clients but is now a no-op (every row is already distinct).
	const displayLimit = 100

	var totalAll int64
	db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", uint(id)).Count(&totalAll)

	var revisions []models.DeviceConfigRevision
	if err := db.Gorm().Where("device_id = ?", uint(id)).
		Order("first_seen_at DESC").Limit(displayLimit).Find(&revisions).Error; err != nil {
		httputil.InternalError(c, "Failed to get config history", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"revisions":   revisions,
		"distinct":    true, // legacy field name; every row is already distinct now
		"total_all":   totalAll,
		"total_shown": len(revisions),
	}))
}

// GetDeviceConfigDiff returns an aligned line diff of two config revisions plus
// the per-object semantic diff. The line diff is computed server-side with a
// Myers O(ND) algorithm (configdiff.DiffLines) so an inserted/removed line no
// longer drifts every subsequent line into a false delta, and volatile masking
// participates in the alignment. The raw config text is intentionally NOT
// returned here — the line diff already carries the display text, and the
// view/download endpoints serve the full text when needed.
func (h *Handler) GetDeviceConfigDiff(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}
	fromID, err := strconv.ParseUint(c.Query("from"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid 'from' revision ID"))
		return
	}
	toID, err := strconv.ParseUint(c.Query("to"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid 'to' revision ID"))
		return
	}

	var fromRev, toRev models.DeviceConfigRevision
	if err := db.Gorm().Where("id = ? AND device_id = ?", uint(fromID), uint(id)).First(&fromRev).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("'from' revision not found"))
		return
	}
	if err := db.Gorm().Where("id = ? AND device_id = ?", uint(toID), uint(id)).First(&toRev).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("'to' revision not found"))
		return
	}

	// Look up the device's vendor so we know which volatile patterns the UI
	// should highlight as "(volatile — IV churn)" rather than red/green deltas.
	vendor := ""
	if dev, err := db.GetDevice(uint(id)); err == nil && dev != nil {
		vendor = dev.Vendor
	}
	patterns := configdiff.VolatilePatternsFor(vendor)

	// Semantic per-object diff + risk classification, computed server-side (the
	// FortiGate config parser lives in Go, not the browser). Empty for vendors
	// without an object parser — the UI then falls back to the line diff.
	rep := configdiff.Analyze(vendor, []byte(fromRev.ConfigText), []byte(toRev.ConfigText))

	// Aligned, volatile-aware line diff (Myers O(ND)), computed server-side.
	lineDiff := configdiff.DiffLines(vendor, []byte(fromRev.ConfigText), []byte(toRev.ConfigText))

	c.JSON(http.StatusOK, response.Success(gin.H{
		"from": gin.H{
			"id":                  fromRev.ID,
			"timestamp":           fromRev.Timestamp,
			"checksum":            fromRev.Checksum,
			"normalized_checksum": fromRev.NormalizedChecksum,
			"trigger_source":      fromRev.TriggerSource,
			"backup_quality":      fromRev.BackupQuality,
			"changed_by":          fromRev.ChangedBy,
			"change_method":       fromRev.ChangeMethod,
			"attributed":          fromRev.Attributed,
			"attribution_checked": fromRev.AttributionChecked,
		},
		"to": gin.H{
			"id":                  toRev.ID,
			"timestamp":           toRev.Timestamp,
			"checksum":            toRev.Checksum,
			"normalized_checksum": toRev.NormalizedChecksum,
			"trigger_source":      toRev.TriggerSource,
			"backup_quality":      toRev.BackupQuality,
			"changed_by":          toRev.ChangedBy,
			"change_method":       toRev.ChangeMethod,
			"attributed":          toRev.Attributed,
			"attribution_checked": toRev.AttributionChecked,
		},
		"vendor":            vendor,
		"volatile_patterns": patterns,
		"object_changes":    rep.ObjectChanges,
		"summary":           rep.Summary,
		"line_diff":         lineDiff,
	}))
}

func (h *Handler) GetDeviceConfigRevisionDownload(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}
	revID, err := strconv.ParseUint(c.Param("revId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid revision ID"))
		return
	}

	var rev models.DeviceConfigRevision
	if err := db.Gorm().Where("id = ? AND device_id = ?", uint(revID), uint(id)).First(&rev).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Config revision not found"))
		return
	}

	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", "attachment; filename=config_"+strconv.FormatUint(uint64(rev.DeviceID), 10)+"_"+strconv.FormatUint(uint64(rev.ID), 10)+".txt")
	c.String(http.StatusOK, rev.ConfigText)
}

func (h *Handler) GetDeviceConfigRevision(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}
	revID, err := strconv.ParseUint(c.Param("revId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid revision ID"))
		return
	}

	var rev models.DeviceConfigRevision
	if err := db.Gorm().Where("id = ? AND device_id = ?", uint(revID), uint(id)).First(&rev).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Config revision not found"))
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"revision": gin.H{
			"id":          rev.ID,
			"device_id":   rev.DeviceID,
			"timestamp":   rev.Timestamp,
			"checksum":    rev.Checksum,
			"config_text": rev.ConfigText,
			"length":      rev.Length,
		},
	}))
}

func (h *Handler) DeleteDeviceConfigRevision(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}
	revID, err := strconv.ParseUint(c.Param("revId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid revision ID"))
		return
	}

	result := db.Gorm().Where("id = ? AND device_id = ?", uint(revID), uint(id)).Delete(&models.DeviceConfigRevision{})
	if result.Error != nil {
		httputil.InternalError(c, "Failed to delete config revision", err)
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, response.Error("Config revision not found"))
		return
	}

	c.JSON(http.StatusOK, response.Success(gin.H{"deleted": true}))
}

func (h *Handler) GetDeviceProcessHistory(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}

	from := c.Query("from")
	to := c.Query("to")
	limit := 100
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	query := db.Gorm().Where("device_id = ?", uint(id)).Order("timestamp DESC").Limit(limit)
	if from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			query = query.Where("timestamp >= ?", t)
		}
	}
	if to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			query = query.Where("timestamp <= ?", t)
		}
	}

	var stats []models.ProcessStats
	if err := query.Find(&stats).Error; err != nil {
		httputil.InternalError(c, "Failed to get process history", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"process_stats": stats}))
}

func (h *Handler) GetDeviceInterfaceErrors(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid device ID"))
		return
	}

	iface := c.Query("interface")
	from := c.Query("from")
	to := c.Query("to")
	limit := 100
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	query := db.Gorm().Where("device_id = ?", uint(id)).Order("timestamp DESC").Limit(limit)
	if iface != "" {
		query = query.Where("interface = ?", iface)
	}
	if from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			query = query.Where("timestamp >= ?", t)
		}
	}
	if to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			query = query.Where("timestamp <= ?", t)
		}
	}

	var errs []models.InterfaceErrors
	if err := query.Find(&errs).Error; err != nil {
		httputil.InternalError(c, "Failed to get interface errors", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"interface_errors": errs}))
}
