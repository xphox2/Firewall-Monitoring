package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/uptime"

	"firewall-mon/internal/database"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// uptimeWindowHours / uptimeSampleCap bound the read-time availability
// computation (AUDIT-318). uptimeWindowHours is only an UPPER lookback bound;
// uptimeSampleCap dominates it — at the ~60s SNMP cadence 2000 samples is only
// ~31h, so the ACTUAL observed window is whatever the retained rows span and is
// reported to the client as UptimeStats.StartTime/ObservedSeconds (the display
// labels from that, never a fixed "30 days"). We read the NEWEST rows so reboot
// detection stays anchored to recent history (GetSystemStatusHistory's ASC+LIMIT
// keeps the OLDEST rows — wrong here, see AUDIT-245); GetRecentSystemStatus is
// newest-first.
const (
	uptimeWindowHours = 720 // max lookback; sample cap dominates
	uptimeSampleCap   = 2000
)

// computeUptimeStats derives per-device availability at read time from the
// persisted system_status history (AUDIT-318). Returns a zero-value UptimeStats
// when there is no data. Cheap: one bounded, indexed range query.
func (h *Handler) computeUptimeStats(db database.Store, deviceID uint) uptime.UptimeStats {
	if db == nil || deviceID == 0 {
		return uptime.UptimeStats{}
	}
	rows, err := db.GetRecentSystemStatus(deviceID, uptimeWindowHours, uptimeSampleCap)
	if err != nil || len(rows) == 0 {
		return uptime.UptimeStats{}
	}
	// GetRecentSystemStatus is newest-first; ComputeStats needs oldest→newest.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return uptime.ComputeStats(rows, rows[0].Timestamp)
}

// computeUptimeRecord wraps computeUptimeStats as a device-tagged UptimeRecord
// for the admin dashboard payload (DeviceID SET).
func (h *Handler) computeUptimeRecord(db database.Store, deviceID uint) *models.UptimeRecord {
	return uptime.NewRecord(deviceID, h.computeUptimeStats(db, deviceID))
}

// SnapshotUptime walks every device and persists a per-device availability
// snapshot into uptime_records (AUDIT-318). It completes the write side of the
// uptime wire so the history is not permanently empty, and it always sets
// DeviceID on the persisted record (fixing the old DeviceID=0 defect). Called
// on a timer by cmd/api using the background store (h.db); it is decoupled from
// the ingest path and skips devices with no telemetry yet.
func (h *Handler) SnapshotUptime() {
	if h.db == nil {
		return
	}
	devices, err := h.db.GetAllDevices()
	if err != nil {
		log.Printf("uptime-snapshot: list devices: %v", err)
		return
	}
	for _, dev := range devices {
		stats := h.computeUptimeStats(h.db, dev.ID)
		if stats.CurrentUptime == 0 {
			continue // no system_status telemetry for this device yet
		}
		if err := h.db.SaveUptimeRecord(uptime.NewRecord(dev.ID, stats)); err != nil {
			log.Printf("uptime-snapshot: save device %d: %v", dev.ID, err)
		}
	}
}

func (h *Handler) GetPublicDevices(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]gin.H{}))
		return
	}

	var devices []models.Device
	if err := db.Gorm().Where("enabled = ? AND public_visible = ?", true, true).Find(&devices).Error; err != nil {
		httputil.InternalError(c, "Failed to get devices", err)
		return
	}

	// Return only safe public fields
	result := make([]gin.H, 0, len(devices))
	for _, d := range devices {
		result = append(result, gin.H{
			"id":             d.ID,
			"name":           d.Name,
			"status":         d.Status,
			"wan_speed_mbps": d.WanSpeedMbps,
		})
	}
	c.JSON(http.StatusOK, response.Success(result))
}

// resolvePublicDeviceID returns the device ID from the ?device_id query param,
// or falls back to the first enabled + public-visible device.
//
// A supplied device_id MUST still pass the enabled + public_visible gate: these
// endpoints are unauthenticated, so without the check an anonymous caller could
// enumerate device_id=1,2,3… and pull telemetry (hostnames, firmware/signature
// versions, interface details, VPN peers) for devices the operator explicitly
// marked non-public. public_visible is the only exposure control and it must be
// enforced here, not just in the default fallback.
func (h *Handler) resolvePublicDeviceID(c *gin.Context) (uint, bool) {
	db := h.reqDB(c)
	if idStr := c.Query("device_id"); idStr != "" {
		id, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			return 0, false
		}
		if db == nil {
			return 0, false
		}
		var dev models.Device
		if err := db.Gorm().Select("id").
			Where("id = ? AND enabled = ? AND public_visible = ?", uint(id), true, true).
			First(&dev).Error; err != nil {
			return 0, false
		}
		return dev.ID, true
	}
	// Default to first enabled + public-visible device
	if db != nil {
		var dev models.Device
		if err := db.Gorm().Where("enabled = ? AND public_visible = ?", true, true).Order("id ASC").First(&dev).Error; err == nil {
			return dev.ID, true
		}
	}
	return 0, false
}

func (h *Handler) GetPublicDashboard(c *gin.Context) {
	db := h.reqDB(c)
	h.mu.RLock()
	defer h.mu.RUnlock()

	deviceID, hasDevice := h.resolvePublicDeviceID(c)

	// Try SNMP first (only for legacy single-device mode without device_id param)
	if !hasDevice && h.snmpClient != nil {
		status, err := h.snmpClient.GetSystemStatus()
		if err == nil {
			// Legacy single-device SNMP path (mostly dead post-v0.11.74): no
			// device_id, so no per-device availability to compute (AUDIT-318).
			var uptimeStats *uptime.UptimeStats
			publicData := gin.H{
				"hostname":     status.Hostname,
				"version":      status.Version,
				"uptime":       uptime.FormatUptime(status.Uptime),
				"uptime_raw":   status.Uptime,
				"cpu":          status.CPUUsage,
				"memory":       status.MemoryUsage,
				"sessions":     status.SessionCount,
				"uptime_stats": uptimeStats,
			}
			c.JSON(http.StatusOK, response.Success(publicData))
			return
		}
	}

	// Fall back to database
	if db != nil && hasDevice {
		var status models.SystemStatus
		if err := db.Gorm().Where("device_id = ?", deviceID).Order("timestamp DESC").First(&status).Error; err == nil {
			// Get device name
			var dev models.Device
			if err := db.Gorm().Select("name").Where("id = ?", deviceID).First(&dev).Error; err != nil {
				log.Printf("Device %d: failed to get device name: %v", deviceID, err)
			}
			// AUDIT-318: real per-device availability, computed at read time
			// from this device's persisted system_status history.
			stats := h.computeUptimeStats(db, deviceID)
			uptimeStats := &stats
			publicData := gin.H{
				"hostname":     status.Hostname,
				"device_name":  dev.Name,
				"version":      status.Version,
				"uptime":       uptime.FormatUptime(status.Uptime),
				"uptime_raw":   status.Uptime,
				"cpu":          status.CPUUsage,
				"memory":       status.MemoryUsage,
				"sessions":     status.SessionCount,
				"uptime_stats": uptimeStats,
				"cached":       true,
				"cached_at":    status.Timestamp,
			}
			c.JSON(http.StatusOK, response.Success(publicData))
			return
		}
	}

	// AUDIT-252: NO global fallback. The endpoint is anonymous, and the old
	// `else if db != nil` branch served db.GetLatestSystemStatus() — the
	// newest-reporting device regardless of public_visible — whenever no
	// device passed the public gate. That handed an anonymous caller a
	// NON-public device's hostname/version/CPU/memory/sessions. With zero
	// public devices the only correct answer is the 503 below.
	c.JSON(http.StatusServiceUnavailable, response.Error("No monitoring data available"))
}

func (h *Handler) GetPublicInterfaces(c *gin.Context) {
	db := h.reqDB(c)
	h.mu.RLock()
	defer h.mu.RUnlock()

	deviceID, hasDevice := h.resolvePublicDeviceID(c)

	// Try SNMP first (only for legacy single-device mode)
	if !hasDevice && h.snmpClient != nil {
		interfaces, err := h.snmpClient.GetInterfaceStats()
		if err == nil {
			c.JSON(http.StatusOK, response.Success(interfaces))
			return
		}
	}

	// Fall back to database
	if db != nil && hasDevice {
		var latestIface models.InterfaceStats
		if err := db.Gorm().Where("device_id = ?", deviceID).Order("timestamp DESC").First(&latestIface).Error; err == nil {
			var ifaces []models.InterfaceStats
			if err := db.Gorm().Where("device_id = ? AND timestamp = ?", deviceID, latestIface.Timestamp).Find(&ifaces).Error; err != nil {
				log.Printf("Device %d: failed to get interfaces at timestamp: %v", deviceID, err)
			}
			// AUDIT-194/195: enforce the operator's public_interfaces allowlist
			// SERVER-side. It was only applied in public-dashboard.js, so an
			// anonymous caller hitting the endpoint directly received every
			// interface of a public device — internal LAN/DMZ names, MACs,
			// VLANs, counters — bypassing the curation entirely.
			allowed, ok, aerr := h.publicIfaceAllowlist(c, deviceID)
			if aerr != nil {
				// Fail CLOSED: the curation setting was unreadable, so do not
				// guess that no narrowing exists (review hardening, AUDIT-194).
				c.JSON(http.StatusServiceUnavailable, response.Error("No interface data available"))
				return
			}
			if ok {
				filtered := ifaces[:0]
				for _, iface := range ifaces {
					if allowed[iface.Name] {
						filtered = append(filtered, iface)
					}
				}
				ifaces = filtered
			}
			c.JSON(http.StatusOK, response.Success(ifaces))
			return
		}
	}

	// AUDIT-252: NO global fallback — the deleted `else if db != nil` branch
	// served db.GetLatestInterfaceStats() UNFILTERED (every device, public or
	// not) to anonymous callers whenever no device passed the public gate.
	// public-dashboard.js already .catch()es this fetch, so the 503 is the
	// contract.
	c.JSON(http.StatusServiceUnavailable, response.Error("No interface data available"))
}

// maxPublicChartRangeHours bounds the numeric `range` fallback at one year,
// mirroring httputil.ParseHours. AUDIT-323: without an upper bound,
// strconv.ParseFloat happily returns +Inf for range=Inf, and converting that
// to an int is implementation-defined (the minimum int64 on amd64), so the
// derived cutoff was an arbitrary instant rather than the requested window.
const maxPublicChartRangeHours = 8760

// publicChartLookback resolves the `range` query value to a lookback duration
// and a downsampling point budget. It is pure — the caller subtracts the
// duration from now — so the whole range table is testable without a clock or
// a database.
func publicChartLookback(rangeStr string) (time.Duration, int) {
	switch rangeStr {
	case "5m":
		return 5 * time.Minute, 10
	case "15m":
		return 15 * time.Minute, 20
	case "6h":
		return 6 * time.Hour, 360
	case "24h":
		return 24 * time.Hour, 96
	case "7d":
		return 168 * time.Hour, 168
	case "720":
		return 720 * time.Hour, 90
	case "8760":
		return 8760 * time.Hour, 365
	case "90d":
		return 2160 * time.Hour, 90
	}

	// 1h or numeric fallback (incl. the fractional public 0.25/0.5 ranges).
	//
	// AUDIT-235: parse as a float, not Atoi — the public dashboard sends
	// range=0.25 (15m) / 0.5 (30m). Atoi failed on those and silently fell
	// through to the 1h default, so the fractional windows showed the wrong
	// span end to end even after the client parseFloat fix.
	//
	// AUDIT-323: the upper bound also screens out +Inf and NaN, which fail
	// every `<=` comparison — that is what keeps the int conversion below
	// well defined. Anything out of range falls back to the 1h default.
	if parsed, err := strconv.ParseFloat(rangeStr, 64); err == nil && parsed > 0 && parsed <= maxPublicChartRangeHours {
		if parsed < 1 {
			subHour := time.Duration(parsed * float64(time.Hour)) // AUDIT-235: sub-hour public range
			return subHour, 30
		}
		return time.Duration(int(parsed)) * time.Hour, 180
	}
	return time.Hour, 60
}

func (h *Handler) GetPublicInterfaceChart(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Database not available"))
		return
	}

	deviceID, hasDevice := h.resolvePublicDeviceID(c)
	if !hasDevice {
		c.JSON(http.StatusBadRequest, response.Error("Device ID required"))
		return
	}

	ifIndexStr := c.Query("index")
	ifIndex, err := strconv.Atoi(ifIndexStr)
	if err != nil || ifIndex < 0 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid interface index"))
		return
	}

	viewType := c.DefaultQuery("view", "rate")
	if viewType != "total" && viewType != "rate" && viewType != "mix" {
		viewType = "rate"
	}

	rangeStr := c.DefaultQuery("range", "1h")

	// AUDIT-194: the chart endpoint takes a raw ifIndex, so resolve it to the
	// interface NAME the public_interfaces allowlist speaks, and serve a
	// non-allowed interface the SAME empty-series payload as the no-data case
	// below — not a 403 — so the SPA renders an empty chart instead of
	// erroring. Without this, history for ANY index of a public device was
	// served regardless of the operator's curation.
	allowed, ok, aerr := h.publicIfaceAllowlist(c, deviceID)
	if aerr != nil {
		// Fail CLOSED (review hardening, AUDIT-194): unreadable curation must
		// not expose a non-allowlisted interface's history; the empty series
		// is what the SPA already renders for missing data.
		c.JSON(http.StatusOK, response.Success(publicChartEmptySeries(viewType, rangeStr)))
		return
	}
	if ok {
		var latest models.InterfaceStats
		nameErr := db.Gorm().Select("name").
			Where("device_id = ? AND \"index\" = ?", deviceID, ifIndex).
			Order("timestamp DESC").First(&latest).Error
		if nameErr != nil || !allowed[latest.Name] {
			c.JSON(http.StatusOK, response.Success(publicChartEmptySeries(viewType, rangeStr)))
			return
		}
	}

	lookback, maxPoints := publicChartLookback(rangeStr)
	cutoff := time.Now().Add(-lookback)

	// Get raw data points
	var stats []models.InterfaceStats
	err = db.Gorm().Where("device_id = ? AND \"index\" = ? AND timestamp > ?", deviceID, ifIndex, cutoff).
		Order("timestamp ASC").Find(&stats).Error
	if err != nil {
		httputil.InternalError(c, "Failed to get interface data", err)
		return
	}

	if len(stats) < 2 {
		c.JSON(http.StatusOK, response.Success(publicChartEmptySeries(viewType, rangeStr)))
		return
	}

	// Downsample if too many points
	var sampled []models.InterfaceStats
	if len(stats) > maxPoints {
		step := len(stats) / maxPoints
		for i := 0; i < len(stats); i += step {
			sampled = append(sampled, stats[i])
			if len(sampled) >= maxPoints {
				break
			}
		}
		// Always include last point
		if len(sampled) == 0 || sampled[len(sampled)-1].Timestamp != stats[len(stats)-1].Timestamp {
			sampled = append(sampled, stats[len(stats)-1])
		}
	} else {
		sampled = stats
	}

	labels := make([]string, 0, len(sampled))
	timestamps := make([]string, 0, len(sampled))
	rxTotalVals := make([]float64, 0, len(sampled))
	txTotalVals := make([]float64, 0, len(sampled))
	rxRate := make([]float64, 0, len(sampled))
	txRate := make([]float64, 0, len(sampled))

	// Calculate totals
	var totalRx, totalTx float64
	if len(sampled) > 1 {
		last := sampled[len(sampled)-1]
		first := sampled[0]
		totalRx = float64(last.InBytes) - float64(first.InBytes)
		totalTx = float64(last.OutBytes) - float64(first.OutBytes)
		if totalRx < 0 {
			totalRx = float64(last.InBytes)
		}
		if totalTx < 0 {
			totalTx = float64(last.OutBytes)
		}
	}

	for i, p := range sampled {
		// Use appropriate time format based on range
		var labelFormat string
		if lookback < time.Hour {
			// Seconds for every sub-hour window: 5m, 15m and the AUDIT-235
			// fractional public ranges all resolve to a lookback under an hour.
			labelFormat = "15:04:05"
		} else if rangeStr == "7d" {
			labelFormat = "01-02 15:00" // date and hour for 7 days
		} else if rangeStr == "90d" {
			labelFormat = "01-02" // just date for 90 days
		} else {
			labelFormat = "15:04" // hour:minute for 1h, 6h, 24h
		}
		labels = append(labels, p.Timestamp.Format(labelFormat))
		timestamps = append(timestamps, p.Timestamp.Format("2006-01-02T15:04:05Z"))
		rxTotalVals = append(rxTotalVals, float64(p.InBytes))
		txTotalVals = append(txTotalVals, float64(p.OutBytes))

		var rRate, tRate float64
		if i > 0 {
			prev := sampled[i-1]
			deltaBytesR := float64(p.InBytes) - float64(prev.InBytes)
			deltaBytesT := float64(p.OutBytes) - float64(prev.OutBytes)
			deltaTime := p.Timestamp.Sub(prev.Timestamp).Seconds()

			if deltaTime > 0 && deltaBytesR >= 0 {
				rRate = (deltaBytesR * 8) / deltaTime / 1000000
			}
			if deltaTime > 0 && deltaBytesT >= 0 {
				tRate = (deltaBytesT * 8) / deltaTime / 1000000
			}
		}
		rxRate = append(rxRate, rRate)
		txRate = append(txRate, tRate)
	}

	c.JSON(http.StatusOK, response.Success(map[string]interface{}{
		"labels":     labels,
		"rx_total":   rxTotalVals,
		"tx_total":   txTotalVals,
		"rx_rate":    rxRate,
		"tx_rate":    txRate,
		"total_rx":   float64(totalRx),
		"total_tx":   float64(totalTx),
		"view":       viewType,
		"range":      rangeStr,
		"timestamps": timestamps,
	}))
}

// publicChartEmptySeries is the empty-series payload GetPublicInterfaceChart
// serves both when an interface has too few points to chart AND (AUDIT-194)
// when the requested interface is outside the public allowlist — the two cases
// are deliberately indistinguishable to an anonymous caller.
func publicChartEmptySeries(viewType, rangeStr string) map[string]interface{} {
	return map[string]interface{}{
		"labels":   []string{},
		"rx_total": []float64{},
		"tx_total": []float64{},
		"rx_rate":  []float64{},
		"tx_rate":  []float64{},
		"total_rx": float64(0),
		"total_tx": float64(0),
		"view":     viewType,
		"range":    rangeStr,
	}
}

// errDBUnavailable marks the fail-closed path when the curation setting
// cannot be read at all (review hardening, AUDIT-194).
var errDBUnavailable = errors.New("database unavailable")

// publicIfaceAllowlist returns the operator-curated interface NAMES for a
// device and whether a non-empty list exists. Mirrors public-dashboard.js:
// an EMPTY/absent list means "no narrowing configured" → all interfaces.
// The setting is "public_interfaces", JSON of the shape
// {"<deviceID>":["wan1",...]} (default "{}"). ok=false — no filtering — is
// deliberately the answer for an empty/absent list, an unset key, or
// unparsable JSON: deny-all-on-empty would blank every public dashboard
// whose operator never configured a narrowing. A DB ERROR is different
// (review hardening on AUDIT-194): the setting may exist but be unreadable,
// so failing open would serve an anonymous caller every interface of a
// curated device during a transient fault — err is returned and the caller
// must fail CLOSED.
func (h *Handler) publicIfaceAllowlist(c *gin.Context, deviceID uint) (map[string]bool, bool, error) {
	db := h.reqDB(c)
	if db == nil {
		return nil, false, errDBUnavailable
	}
	var s models.SystemSetting
	if err := db.Gorm().Select("value").Where("\"key\" = ?", "public_interfaces").First(&s).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, false, nil // never configured — no narrowing
		}
		return nil, false, err
	}
	var lists map[string][]string
	if err := json.Unmarshal([]byte(s.Value), &lists); err != nil {
		return nil, false, nil
	}
	names := lists[strconv.FormatUint(uint64(deviceID), 10)]
	if len(names) == 0 {
		return nil, false, nil
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	return allowed, true, nil
}

// publicBoolSetting reads a boolean system setting for the unauthenticated
// public surface, defaulting to false (the safe default that GetPublicDisplay-
// Settings advertises) when the key is unset or the DB is unavailable. Used to
// enforce the public_show_* toggles SERVER-side — the SPA only hides the widgets
// client-side, so the API must not answer when a toggle is off.
func (h *Handler) publicBoolSetting(c *gin.Context, key string) bool {
	db := h.reqDB(c)
	if db == nil {
		return false
	}
	var s models.SystemSetting
	if err := db.Gorm().Select("value").Where("\"key\" = ?", key).First(&s).Error; err != nil {
		return false
	}
	return s.Value == "true"
}

func (h *Handler) GetPublicVPN(c *gin.Context) {
	db := h.reqDB(c)
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Enforce the public_show_vpn toggle server-side (default off).
	if !h.publicBoolSetting(c, "public_show_vpn") {
		c.JSON(http.StatusOK, response.Success([]gin.H{}))
		return
	}

	deviceID, hasDevice := h.resolvePublicDeviceID(c)

	if db != nil && hasDevice {
		vpnStatuses, err := db.GetLatestVPNStatuses(deviceID)
		if err == nil && vpnStatuses != nil {
			result := make([]gin.H, 0, len(vpnStatuses))
			for _, vpn := range vpnStatuses {
				result = append(result, gin.H{
					"tunnel_name":   vpn.TunnelName,
					"tunnel_type":   vpn.TunnelType,
					"remote_ip":     vpn.RemoteIP,
					"status":        vpn.Status,
					"state":         vpn.State,
					"phase1_name":   vpn.Phase1Name,
					"bytes_in":      vpn.BytesIn,
					"bytes_out":     vpn.BytesOut,
					"tunnel_uptime": vpn.TunnelUptime,
				})
			}
			c.JSON(http.StatusOK, response.Success(result))
			return
		}
	}

	c.JSON(http.StatusServiceUnavailable, response.Error("No VPN data available"))
}

func (h *Handler) GetPublicConnections(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("No connections available"))
		return
	}

	// Enforce the public_show_connections toggle server-side (default off). The
	// SPA hides the widget, but without this the endpoint dumped the full
	// inter-device topology (source/dest names, type, status) to anyone.
	if !h.publicBoolSetting(c, "public_show_connections") {
		c.JSON(http.StatusOK, response.Success([]gin.H{}))
		return
	}

	// Only expose connections whose BOTH endpoints are public-visible devices, so
	// a public connection can't leak the name/existence of a non-public device.
	var publicIDs []uint
	if err := db.Gorm().Model(&models.Device{}).
		Where("enabled = ? AND public_visible = ?", true, true).
		Pluck("id", &publicIDs).Error; err != nil {
		httputil.InternalError(c, "Failed to resolve public devices", err)
		return
	}
	if len(publicIDs) == 0 {
		c.JSON(http.StatusOK, response.Success([]gin.H{}))
		return
	}

	var connections []models.DeviceConnection
	if err := db.Gorm().Preload("SourceDevice").Preload("DestDevice").
		Where("source_device_id IN ? AND dest_device_id IN ?", publicIDs, publicIDs).
		Limit(100).Find(&connections).Error; err != nil {
		httputil.InternalError(c, "Failed to get connections", err)
		return
	}

	result := make([]gin.H, 0, len(connections))
	for _, conn := range connections {
		sourceName := ""
		destName := ""
		if conn.SourceDevice != nil {
			sourceName = conn.SourceDevice.Name
		}
		if conn.DestDevice != nil {
			destName = conn.DestDevice.Name
		}
		result = append(result, gin.H{
			"id":     conn.ID,
			"name":   conn.Name,
			"source": sourceName,
			"dest":   destName,
			"type":   conn.ConnectionType,
			"status": conn.Status,
			"notes":  "",
		})
	}
	c.JSON(http.StatusOK, response.Success(result))
}

func (h *Handler) GetPublicStatusHistory(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("No data available"))
		return
	}

	deviceID, hasDevice := h.resolvePublicDeviceID(c)
	if !hasDevice {
		c.JSON(http.StatusBadRequest, response.Error("No device specified"))
		return
	}

	// Unified parsing (v0.10.217, bundle D2). httputil.ParseHours enforces
	// the 24h default + 8760h (1 year) cap shared by every endpoint that
	// accepts an `hours` query parameter.
	//
	// AUDIT-235: the public dashboard's 15m/30m ranges send hours=0.25/0.5.
	// ParseHours is integer-only (Atoi) and truncates those to its 24h default,
	// so the CPU/memory history silently showed 24h. For a genuine sub-hour
	// value, query by an explicit cutoff duration (mirrors GetSystemStatusHistory
	// — ASC + LIMIT 2000); integer hours keep the shared helper + method.
	var statuses []models.SystemStatus
	var err error
	var subHour time.Duration
	if hq := c.Query("hours"); hq != "" {
		if f, ferr := strconv.ParseFloat(hq, 64); ferr == nil && f > 0 && f < 1 {
			subHour = time.Duration(f * float64(time.Hour))
		}
	}
	if subHour > 0 {
		cutoff := time.Now().Add(-subHour)
		err = db.Gorm().Where("device_id = ? AND timestamp > ?", deviceID, cutoff).
			Order("timestamp ASC").Limit(2000).Find(&statuses).Error
	} else {
		statuses, err = db.GetSystemStatusHistory(deviceID, httputil.ParseHours(c))
	}
	if err != nil {
		httputil.InternalError(c, "Failed to get status history", err)
		return
	}

	type publicPoint struct {
		Timestamp   string  `json:"timestamp"`
		CPUUsage    float64 `json:"cpu_usage"`
		MemoryUsage float64 `json:"memory_usage"`
	}
	result := make([]publicPoint, 0, len(statuses))
	for _, s := range statuses {
		result = append(result, publicPoint{
			Timestamp:   s.Timestamp.Format("2006-01-02T15:04:05Z"),
			CPUUsage:    s.CPUUsage,
			MemoryUsage: s.MemoryUsage,
		})
	}
	c.JSON(http.StatusOK, response.Success(result))
}

func (h *Handler) GetAdminDashboard(c *gin.Context) {
	db := h.reqDB(c)
	h.mu.RLock()
	defer h.mu.RUnlock()

	var status *models.SystemStatus
	var interfaces []models.InterfaceStats
	var sensors []models.HardwareSensor

	// Try SNMP first
	if h.snmpClient != nil {
		s, err := h.snmpClient.GetSystemStatus()
		if err == nil {
			status = s
		}
		ifaces, err := h.snmpClient.GetInterfaceStats()
		if err == nil {
			interfaces = ifaces
		}
		hw, err := h.snmpClient.GetHardwareSensors()
		if err == nil {
			sensors = hw
		}
	}

	// Fall back to DB if SNMP unavailable
	if status == nil && db != nil {
		s, err := db.GetLatestSystemStatus()
		if err == nil && s != nil {
			status = s
		}
	}
	if len(interfaces) == 0 && db != nil {
		ifaces, err := db.GetLatestInterfaceStats()
		if err == nil {
			interfaces = ifaces
		}
	}

	if status == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("No monitoring data available"))
		return
	}

	var recentAlerts []models.Alert
	if db != nil {
		alerts, err := db.GetAlerts(10, nil)
		if err != nil {
			log.Printf("Failed to get recent alerts: %v", err)
		}
		recentAlerts = alerts
	}

	dashboard := models.DashboardData{
		SystemStatus:    *status,
		Interfaces:      interfaces,
		HardwareSensors: sensors,
		RecentAlerts:    recentAlerts,
		// AUDIT-318: per-device availability for the device this dashboard row
		// resolved to, computed at read time (DeviceID set on the record).
		UptimeData: h.computeUptimeRecord(db, status.DeviceID),
	}

	c.JSON(http.StatusOK, response.Success(dashboard))
}

func (h *Handler) GetDashboardAll(c *gin.Context) {
	db := h.reqDB(c)
	devices := []models.Device{}
	connections := []models.DeviceConnection{}
	recentAlerts := []models.Alert{}

	if db != nil {
		// Defensive bounds (v0.10.217, bundle D3). Devices + connections
		// are configuration tables, but on a fleet with thousands of
		// auto-detected connections the previous unbounded Find could
		// pull an enormous payload. 1000 is well above any realistic
		// admin-managed fleet, low enough to fit in a single response.
		if err := db.Gorm().Preload("Site").Preload("Probe").Limit(1000).Find(&devices).Error; err != nil {
			log.Printf("Failed to get devices: %v", err)
		}

		if err := db.Gorm().Preload("SourceDevice").Preload("DestDevice").Limit(1000).Find(&connections).Error; err != nil {
			log.Printf("Failed to get connections: %v", err)
		}

		if err := db.Gorm().Order("timestamp DESC").Limit(20).Find(&recentAlerts).Error; err != nil {
			log.Printf("Failed to get recent alerts: %v", err)
		}
	}

	// Redact SNMP secrets — on the device list AND on the devices preloaded
	// inside each connection (the latter leaked ciphertext before).
	httputil.RedactDevices(devices)
	httputil.RedactConnections(connections)

	// Per-device enrichment: latest system status, interface summary, VPN summary
	type DeviceEnrichment struct {
		DeviceID     uint       `json:"device_id"`
		HasStatus    bool       `json:"has_status"`
		StatusTime   *time.Time `json:"status_time,omitempty"`
		StatusRows   int64      `json:"status_rows"`
		CPUUsage     float64    `json:"cpu_usage"`
		MemoryUsage  float64    `json:"memory_usage"`
		SessionCount int        `json:"session_count"`
		IfaceTotal   int        `json:"iface_total"`
		IfaceUp      int        `json:"iface_up"`
		IfaceDown    int        `json:"iface_down"`
		VPNTotal     int        `json:"vpn_total"`
		VPNUp        int        `json:"vpn_up"`
		HAMode       string     `json:"ha_mode,omitempty"`
		HAMembers    int        `json:"ha_members,omitempty"`
		SDWANTotal   int        `json:"sdwan_total,omitempty"`
		SDWANAlive   int        `json:"sdwan_alive,omitempty"`
	}

	// AUDIT-033: pre-fix this ran ~13 queries PER device (count + latest +
	// per-metric counts for status/iface/vpn/ha/sdwan) — ~650 queries at 50
	// devices. Replaced with a fixed set of batched aggregate queries (one per
	// data type) that compute every device's summary at once using the
	// codebase's max-timestamp self-join pattern (portable across Postgres and
	// the SQLite test backend). Query count is now O(1) in the device count.
	enrichments := make(map[uint]*DeviceEnrichment)
	if db != nil && len(devices) > 0 {
		ids := make([]uint, len(devices))
		for i, dev := range devices {
			ids[i] = dev.ID
			enrichments[dev.ID] = &DeviceEnrichment{DeviceID: dev.ID}
		}
		g := db.Gorm()

		// latest builds "the row(s) at MAX(timestamp) per device" subquery for
		// a given time-series table, scoped to the dashboard's device set.
		latest := func(table string) *gorm.DB {
			return g.Table(table).Select("device_id, MAX(timestamp) AS mx").
				Where("device_id IN ?", ids).Group("device_id")
		}

		// 1. system_status total row counts per device.
		type cntRow struct {
			DeviceID uint
			C        int64
		}
		var statusCounts []cntRow
		if err := g.Model(&models.SystemStatus{}).Select("device_id, COUNT(*) AS c").
			Where("device_id IN ?", ids).Group("device_id").Scan(&statusCounts).Error; err != nil {
			log.Printf("dashboard: status counts: %v", err)
		}
		for _, r := range statusCounts {
			if e := enrichments[r.DeviceID]; e != nil {
				e.StatusRows = r.C
			}
		}

		// 2. latest system_status values per device.
		type statusRow struct {
			DeviceID     uint
			Timestamp    time.Time
			CPUUsage     float64
			MemoryUsage  float64
			SessionCount int
		}
		var statusLatest []statusRow
		if err := g.Table("system_status AS s").
			Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest("system_status")).
			Where("s.device_id IN ?", ids).
			Select("s.device_id AS device_id, s.timestamp AS timestamp, s.cpu_usage AS cpu_usage, s.memory_usage AS memory_usage, s.session_count AS session_count").
			Scan(&statusLatest).Error; err != nil {
			log.Printf("dashboard: latest status: %v", err)
		}
		for i := range statusLatest {
			r := statusLatest[i]
			if e := enrichments[r.DeviceID]; e != nil {
				e.HasStatus = true
				ts := r.Timestamp
				e.StatusTime = &ts
				e.CPUUsage = r.CPUUsage
				e.MemoryUsage = r.MemoryUsage
				e.SessionCount = r.SessionCount
			}
		}

		// 3+4. interface and VPN summaries (total + up at the latest timestamp).
		type upAgg struct {
			DeviceID uint
			Total    int64
			Up       int64
		}
		runUpAgg := func(table string) []upAgg {
			var rows []upAgg
			if err := g.Table(table+" AS s").
				Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest(table)).
				Where("s.device_id IN ?", ids).Group("s.device_id").
				Select("s.device_id AS device_id, COUNT(*) AS total, SUM(CASE WHEN s.status = 'up' THEN 1 ELSE 0 END) AS up").
				Scan(&rows).Error; err != nil {
				log.Printf("dashboard: %s summary: %v", table, err)
			}
			return rows
		}
		for _, r := range runUpAgg("interface_stats") {
			if e := enrichments[r.DeviceID]; e != nil {
				e.IfaceTotal = int(r.Total)
				e.IfaceUp = int(r.Up)
				e.IfaceDown = int(r.Total - r.Up)
			}
		}
		for _, r := range runUpAgg("vpn_status") {
			if e := enrichments[r.DeviceID]; e != nil {
				e.VPNTotal = int(r.Total)
				e.VPNUp = int(r.Up)
			}
		}

		// 5. HA summary: mode + member count at the latest timestamp.
		type haRow struct {
			DeviceID uint
			Mode     string
			Members  int64
		}
		var haAgg []haRow
		if err := g.Table("ha_status AS s").
			Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest("ha_status")).
			Where("s.device_id IN ?", ids).Group("s.device_id").
			Select("s.device_id AS device_id, MAX(s.system_mode) AS mode, COUNT(*) AS members").
			Scan(&haAgg).Error; err != nil {
			log.Printf("dashboard: ha summary: %v", err)
		}
		for _, r := range haAgg {
			if e := enrichments[r.DeviceID]; e != nil {
				e.HAMode = r.Mode
				e.HAMembers = int(r.Members)
			}
		}

		// 6. SD-WAN summary: total + alive at the latest timestamp.
		type sdRow struct {
			DeviceID uint
			Total    int64
			Alive    int64
		}
		var sdAgg []sdRow
		if err := g.Table("sdwan_health AS s").
			Joins("JOIN (?) AS l ON s.device_id = l.device_id AND s.timestamp = l.mx", latest("sdwan_health")).
			Where("s.device_id IN ?", ids).Group("s.device_id").
			Select("s.device_id AS device_id, COUNT(*) AS total, SUM(CASE WHEN s.state = 'alive' THEN 1 ELSE 0 END) AS alive").
			Scan(&sdAgg).Error; err != nil {
			log.Printf("dashboard: sdwan summary: %v", err)
		}
		for _, r := range sdAgg {
			if e := enrichments[r.DeviceID]; e != nil {
				e.SDWANTotal = int(r.Total)
				e.SDWANAlive = int(r.Alive)
			}
		}
	}

	dashboard := models.DashboardData{
		Devices:      devices,
		RecentAlerts: recentAlerts,
		Connections:  connections,
	}

	c.JSON(http.StatusOK, response.Success(gin.H{
		"dashboard":   dashboard,
		"enrichments": enrichments,
	}))
}

// dashboardSummaryDevice is the minimal device shape the landing dashboard needs
// for its count cards, stale-device card, and noisy-device leaderboard seed. It
// deliberately omits the heavy enrichment (CPU/mem/iface/VPN) and connection
// payload that GetDashboardAll computes — those are only used by the Devices page
// and the connection map, so pulling them on the landing page was pure waste.
type dashboardSummaryDevice struct {
	ID         uint      `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	LastPolled time.Time `json:"last_polled"`
}

// GetDashboardSummary is the fast landing-dashboard endpoint. It returns only
// what the first paint needs, using cheap COUNT/GROUP BY queries instead of the
// 1000-device + 1000-connection + 6-aggregate enrichment load in GetDashboardAll.
// Both the vitals rail and the stat grid consume this (coalesced client-side), so
// the heavy /api/dashboard endpoint no longer runs on login.
func (h *Handler) GetDashboardSummary(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	val, err := h.dashCache.get("dashboard-summary", dashboardSummaryTTL, func() (interface{}, error) {
		return h.computeDashboardSummary(), nil
	})
	if err != nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}
	c.JSON(http.StatusOK, response.Success(val))
}

// dashboardSummaryTTL bounds how long one computed summary is reused. The vitals
// rail polls this every 30s from EVERY admin page, and the 24h syslog COUNT
// inside it was measured at 1.49-1.81s on production, so before caching it was
// the largest recurring request-path cost in the product.
const dashboardSummaryTTL = 15 * time.Second

// computeDashboardSummary builds the summary payload.
//
// It runs on the BACKGROUND store h.db, not h.reqDB(c), and that is load-bearing
// rather than an oversight: the result is shared by every client through
// dashCache, and ttlCache collapses concurrent misses with singleflight. If the
// compute inherited the leader request's context, that one client navigating away
// would cancel the query for every caller coalesced behind it — and since errors
// are not cached, the cache would never warm. The payload itself is a pure global
// aggregate with no per-user component (device counts, a minimal id/name/status
// device list, probe counts, bounded 24h totals), so sharing it is correct.
func (h *Handler) computeDashboardSummary() gin.H {
	db := h.db
	g := db.Gorm()

	// Device counts by status — a single GROUP BY over the small config table.
	var statusCounts []struct {
		Status string
		C      int64
	}
	if err := g.Model(&models.Device{}).Select("status, COUNT(*) AS c").Group("status").Scan(&statusCounts).Error; err != nil {
		log.Printf("dashboard summary: status counts: %v", err)
	}
	var total, online, offline int64
	for _, r := range statusCounts {
		total += r.C
		switch r.Status {
		case "online":
			online = r.C
		case "offline":
			offline = r.C
		}
	}

	// Minimal device list (id/name/status/last_polled) for the stale + noisy cards.
	devices := make([]dashboardSummaryDevice, 0)
	if err := g.Model(&models.Device{}).Select("id, name, status, last_polled").Limit(1000).Scan(&devices).Error; err != nil {
		log.Printf("dashboard summary: device list: %v", err)
	}

	// Probe counts (excluding decommissioned): active drives the stat card,
	// pending + stale drive the vitals-rail severity readout.
	probeCount := func(where string, args ...interface{}) int64 {
		var n int64
		q := g.Model(&models.Probe{}).Where("decommissioned_at IS NULL")
		if where != "" {
			q = q.Where(where, args...)
		}
		if err := q.Count(&n).Error; err != nil {
			log.Printf("dashboard summary: probe count (%s): %v", where, err)
		}
		return n
	}
	probeActive := probeCount("approval_status = ? AND status = ?", "approved", "online")
	probePending := probeCount("approval_status = ?", "pending")
	probeStale := probeCount("approval_status = ? AND status <> ?", "approved", "online")

	// Syslog + trap 24h totals via bare bounded COUNTs. GetSyslogStats/GetTrapStats
	// also compute severity + hourly-bucket breakdowns (6 and 4 queries over the
	// partitioned tables) that the rail/stat-card never use — here we only need the
	// total, so we count directly (2 + 1 queries, window-pruned).
	cutoff24 := time.Now().Add(-24 * time.Hour)
	var syslog24, syslogSummary24, trap24 int64
	if err := g.Model(&models.SyslogMessage{}).Where("timestamp > ?", cutoff24).Count(&syslog24).Error; err != nil {
		log.Printf("dashboard summary: syslog count: %v", err)
	}
	if err := g.Model(&models.SyslogSummary{}).Where("timestamp > ?", cutoff24).
		Select("COALESCE(SUM(count),0)").Scan(&syslogSummary24).Error; err != nil {
		log.Printf("dashboard summary: syslog summary count: %v", err)
	}
	syslog24 += syslogSummary24
	if err := g.Model(&models.TrapEvent{}).Where("timestamp > ?", cutoff24).Count(&trap24).Error; err != nil {
		log.Printf("dashboard summary: trap count: %v", err)
	}

	return gin.H{
		"device_counts":       gin.H{"total": total, "online": online, "offline": offline},
		"devices":             devices,
		"probe_count_active":  probeActive,
		"probe_count_pending": probePending,
		"probe_count_stale":   probeStale,
		"syslog_24h":          syslog24,
		"trap_24h":            trap24,
	}
}

// GetNoisyDevices returns the top-N devices ranked by recent alert + syslog
// volume, computed with a fixed set of GROUP BY device_id queries (bounded by the
// hours window → partition pruning on syslog_messages). This replaces the old
// dashboard behavior of firing /alerts/stats + /syslog/stats per device (2N
// round-trips) with a single request.
func (h *Handler) GetNoisyDevices(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]gin.H{}))
		return
	}
	limit := 10
	if lq := c.Query("limit"); lq != "" {
		if n, err := strconv.Atoi(lq); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	c.JSON(http.StatusOK, response.Success(noisyDevices(db.Gorm(), httputil.ParseHours(c), limit)))
}

// noisyRow is one entry in the noisy-device leaderboard.
type noisyRow struct {
	DeviceID uint   `json:"device_id"`
	Name     string `json:"name"`
	Alerts   int64  `json:"alerts"`
	Syslog   int64  `json:"syslog"`
	Total    int64  `json:"total"`
}

// noisyDevices computes the top-`limit` devices by alert + syslog volume over the
// last `hours`, with a fixed set of GROUP BY device_id queries (bounded window →
// partition pruning). Shared by GET /api/dashboard/noisy and the cached health
// composite. Errors are logged and degrade to partial results, never fatal.
func noisyDevices(g *gorm.DB, hours, limit int) []noisyRow {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	type devCount struct {
		DeviceID uint
		C        int64
	}

	alertByDev := map[uint]int64{}
	syslogByDev := map[uint]int64{}

	var alertRows []devCount
	if err := g.Model(&models.Alert{}).Select("device_id, COUNT(*) AS c").
		Where("timestamp > ? AND device_id <> 0", cutoff).Group("device_id").Scan(&alertRows).Error; err != nil {
		log.Printf("noisy: alert counts: %v", err)
	}
	for _, r := range alertRows {
		alertByDev[r.DeviceID] = r.C
	}

	var sysRows []devCount
	if err := g.Model(&models.SyslogMessage{}).Select("device_id, COUNT(*) AS c").
		Where("timestamp > ? AND device_id <> 0", cutoff).Group("device_id").Scan(&sysRows).Error; err != nil {
		log.Printf("noisy: syslog counts: %v", err)
	}
	for _, r := range sysRows {
		syslogByDev[r.DeviceID] = r.C
	}

	// Syslog summaries (rolled-up) carry a count column, folded in like GetSyslogStats.
	var sumRows []devCount
	if err := g.Model(&models.SyslogSummary{}).Select("device_id, COALESCE(SUM(count),0) AS c").
		Where("timestamp > ? AND device_id <> 0", cutoff).Group("device_id").Scan(&sumRows).Error; err != nil {
		log.Printf("noisy: syslog summary counts: %v", err)
	}
	for _, r := range sumRows {
		syslogByDev[r.DeviceID] += r.C
	}

	// Union device ids, look up names in one query.
	idSet := map[uint]bool{}
	for id := range alertByDev {
		idSet[id] = true
	}
	for id := range syslogByDev {
		idSet[id] = true
	}
	names := map[uint]string{}
	if len(idSet) > 0 {
		ids := make([]uint, 0, len(idSet))
		for id := range idSet {
			ids = append(ids, id)
		}
		var devs []struct {
			ID   uint
			Name string
		}
		if err := g.Model(&models.Device{}).Select("id, name").Where("id IN ?", ids).Scan(&devs).Error; err != nil {
			log.Printf("noisy: device names: %v", err)
		}
		for _, d := range devs {
			names[d.ID] = d.Name
		}
	}

	rows := make([]noisyRow, 0, len(idSet))
	for id := range idSet {
		// Skip devices that were deleted but still have telemetry rows.
		name, ok := names[id]
		if !ok {
			continue
		}
		a := alertByDev[id]
		s := syslogByDev[id]
		rows = append(rows, noisyRow{DeviceID: id, Name: name, Alerts: a, Syslog: s, Total: a + s})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Total > rows[j].Total })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// GetDeviceDataDiag returns per-device system_status record counts and latest values.
// Used to diagnose why some devices may show "No data" in the UI.
func (h *Handler) GetDeviceDataDiag(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}

	// Defensive cap (v0.10.217, bundle D3).
	var devices []models.Device
	if err := db.Gorm().Select("id, name, ip_address, status, last_polled, probe_id").Limit(1000).Find(&devices).Error; err != nil {
		httputil.InternalError(c, "Failed to get devices", err)
		return
	}

	type DeviceDiag struct {
		DeviceID   uint       `json:"device_id"`
		Name       string     `json:"name"`
		IPAddress  string     `json:"ip_address"`
		Status     string     `json:"status"`
		LastPolled time.Time  `json:"last_polled"`
		ProbeID    *uint      `json:"probe_id"`
		StatusRows int64      `json:"status_rows"`
		LatestCPU  float64    `json:"latest_cpu"`
		LatestMem  float64    `json:"latest_mem"`
		LatestTime *time.Time `json:"latest_time,omitempty"`
	}

	results := make([]DeviceDiag, 0, len(devices))
	for _, dev := range devices {
		diag := DeviceDiag{
			DeviceID:   dev.ID,
			Name:       dev.Name,
			IPAddress:  dev.IPAddress,
			Status:     dev.Status,
			LastPolled: dev.LastPolled,
			ProbeID:    dev.ProbeID,
		}

		if err := db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", dev.ID).Count(&diag.StatusRows).Error; err != nil {
			log.Printf("Device %d: failed to count status rows: %v", dev.ID, err)
		}

		var ss models.SystemStatus
		if err := db.Gorm().Where("device_id = ?", dev.ID).Order("timestamp DESC").First(&ss).Error; err == nil {
			diag.LatestCPU = ss.CPUUsage
			diag.LatestMem = ss.MemoryUsage
			diag.LatestTime = &ss.Timestamp
		}

		results = append(results, diag)
	}

	c.JSON(http.StatusOK, response.Success(results))
}

func (h *Handler) GetDashboardStats(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success(nil))
		return
	}

	hours := httputil.ParseHours(c)

	stats, err := db.GetDashboardTimeSeries(hours)
	if err != nil {
		httputil.InternalError(c, "Failed to get dashboard stats", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(stats))
}
