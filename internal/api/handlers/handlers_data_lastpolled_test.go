package handlers

import (
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestRelayHandlers_BumpLastPolled is the regression for the DEVICE_OFFLINE
// flap where only 4 of ~20 relay handlers bumped devices.last_polled. The
// poller's stale sweep fires on last_polled, so a device whose system-status /
// interface-stats / vpn-status collection failed while OTHER polled telemetry
// (disk, load, sensors, HA, licenses, …) kept arriving flapped offline every
// cycle. Every handler that receives device-attributed polled telemetry must
// bump last_polled + status after a successful save.
func TestRelayHandlers_BumpLastPolled(t *testing.T) {
	batch := func(extra map[string]interface{}) func(deviceID uint) interface{} {
		return func(deviceID uint) interface{} {
			row := map[string]interface{}{"device_id": deviceID}
			for k, v := range extra {
				row[k] = v
			}
			return []map[string]interface{}{row}
		}
	}

	cases := []struct {
		name    string
		handler func(*Handler) func(*gin.Context)
		path    string
		body    func(deviceID uint) interface{}
	}{
		{"interface-addresses", func(h *Handler) func(*gin.Context) { return h.ReceiveInterfaceAddresses }, "/interface-addresses", batch(map[string]interface{}{"if_name": "wan1", "ip_address": "10.0.0.1"})},
		{"processor-stats", func(h *Handler) func(*gin.Context) { return h.ReceiveProcessorStats }, "/processor-stats", batch(nil)},
		{"disk-usage", func(h *Handler) func(*gin.Context) { return h.ReceiveDiskUsage }, "/disk-usage", batch(nil)},
		{"load-average", func(h *Handler) func(*gin.Context) { return h.ReceiveLoadAverage }, "/load-average", batch(nil)},
		{"hardware-sensors", func(h *Handler) func(*gin.Context) { return h.ReceiveHardwareSensors }, "/hardware-sensors", batch(map[string]interface{}{"name": "temp1", "value": 42.0})},
		{"ha-statuses", func(h *Handler) func(*gin.Context) { return h.ReceiveHAStatuses }, "/ha-statuses", batch(nil)},
		{"security-stats", func(h *Handler) func(*gin.Context) { return h.ReceiveSecurityStats }, "/security-stats", batch(nil)},
		{"sdwan-health", func(h *Handler) func(*gin.Context) { return h.ReceiveSDWANHealth }, "/sdwan-health", batch(nil)},
		{"license-info", func(h *Handler) func(*gin.Context) { return h.ReceiveLicenseInfo }, "/license-info", batch(nil)},
		{"interface-errors", func(h *Handler) func(*gin.Context) { return h.ReceiveInterfaceErrors }, "/interface-errors", batch(map[string]interface{}{"if_name": "wan1"})},
		{"sensor-details", func(h *Handler) func(*gin.Context) { return h.ReceiveSensorDetails }, "/sensor-details", batch(map[string]interface{}{"name": "fan1", "value": 3200.0})},
		{"license-details", func(h *Handler) func(*gin.Context) { return h.ReceiveLicenseDetails }, "/license-details", batch(nil)},
		{"process-snapshot", func(h *Handler) func(*gin.Context) { return h.ReceiveProcessSnapshot }, "/process-snapshot",
			func(deviceID uint) interface{} { return map[string]interface{}{"device_id": deviceID} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db := setupTestHandler(t)
			probe, device := setupProbeAndDevice(t, db)

			// Seed the pre-fix failure state: the device looks stale/offline.
			stale := time.Now().Add(-time.Hour)
			if err := db.Gorm().Model(&models.Device{}).Where("id = ?", device.ID).
				Updates(map[string]interface{}{"status": "offline", "last_polled": stale}).Error; err != nil {
				t.Fatalf("seed stale device: %v", err)
			}

			before := time.Now().Add(-time.Second)
			w := doTestRequest(t, tc.handler(h), "POST", tc.path, probe.ID, probe.RegistrationKey, tc.body(device.ID))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}

			var dev models.Device
			if err := db.Gorm().First(&dev, device.ID).Error; err != nil {
				t.Fatalf("reload device: %v", err)
			}
			if dev.Status != "online" || dev.LastPolled.Before(before) {
				t.Errorf("device not bumped online: status=%q last_polled=%v", dev.Status, dev.LastPolled)
			}
		})
	}
}

// TestRelayHandlers_ForeignDeviceNotBumped: a device NOT assigned to the
// sending probe must never be bumped — the allowlist filter drops the row AND
// the bump (a spoofed batch must not keep another site's device online).
func TestRelayHandlers_ForeignDeviceNotBumped(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	stale := time.Now().Add(-time.Hour)
	foreign := &models.Device{Name: "other-fw", IPAddress: "192.168.9.9", Status: "offline", LastPolled: stale}
	if err := db.Gorm().Create(foreign).Error; err != nil {
		t.Fatalf("create foreign device: %v", err)
	}

	body := []map[string]interface{}{{"device_id": foreign.ID}}
	w := doTestRequest(t, h.ReceiveProcessorStats, "POST", "/processor-stats", probe.ID, probe.RegistrationKey, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var dev models.Device
	if err := db.Gorm().First(&dev, foreign.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if dev.Status != "offline" || !dev.LastPolled.Equal(stale) && dev.LastPolled.After(stale.Add(time.Minute)) {
		t.Errorf("foreign device was bumped: status=%q last_polled=%v", dev.Status, dev.LastPolled)
	}
}

// TestRelayHandlers_PassiveSourcesDoNotBump pins the intentional exclusion:
// device-PUSHED sources (syslog, traps, flow samples, flow counter samples)
// prove the device is emitting, not that the collector can poll it — they must
// never hold a device "online".
func TestRelayHandlers_PassiveSourcesDoNotBump(t *testing.T) {
	cases := []struct {
		name    string
		handler func(*Handler) func(*gin.Context)
		path    string
	}{
		{"syslog", func(h *Handler) func(*gin.Context) { return h.ReceiveSyslogMessages }, "/syslog"},
		{"traps", func(h *Handler) func(*gin.Context) { return h.ReceiveTrapEvents }, "/traps"},
		{"flow-samples", func(h *Handler) func(*gin.Context) { return h.ReceiveFlowSamples }, "/flows"},
		{"flow-counter-samples", func(h *Handler) func(*gin.Context) { return h.ReceiveFlowCounterSamples }, "/flow-counters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db := setupTestHandler(t)
			probe, device := setupProbeAndDevice(t, db)

			stale := time.Now().Add(-time.Hour)
			if err := db.Gorm().Model(&models.Device{}).Where("id = ?", device.ID).
				Updates(map[string]interface{}{"status": "offline", "last_polled": stale}).Error; err != nil {
				t.Fatalf("seed stale device: %v", err)
			}

			body := []map[string]interface{}{{"device_id": device.ID, "message": "x", "source_ip": device.IPAddress}}
			w := doTestRequest(t, tc.handler(h), "POST", tc.path, probe.ID, probe.RegistrationKey, body)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}

			var dev models.Device
			if err := db.Gorm().First(&dev, device.ID).Error; err != nil {
				t.Fatalf("reload device: %v", err)
			}
			if dev.Status == "online" {
				t.Errorf("passive source %s bumped device online (last_polled=%v)", tc.name, dev.LastPolled)
			}
		})
	}
}

// TestRelayHandlers_SpooledBatchUsesRowTimestamps is the regression for the
// PR #117 spool-replay skew: a collector draining hours of buffered batches
// after a server outage used to bump last_polled to NOW per batch, holding a
// device that died mid-outage "online" for the whole drain window. The bump
// must use the batch's own (per-device) row timestamps.
func TestRelayHandlers_SpooledBatchUsesRowTimestamps(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	// Last seen 4h ago but still "online": the server (and its sweep) was down.
	seed := time.Now().Add(-4 * time.Hour)
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", device.ID).
		Updates(map[string]interface{}{"status": "online", "last_polled": seed}).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// A drained spool batch: rows collected 3h ago.
	rowTime := time.Now().Add(-3 * time.Hour)
	body := []map[string]interface{}{{"device_id": device.ID, "timestamp": rowTime}}
	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-status", probe.ID, probe.RegistrationKey, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var dev models.Device
	if err := db.Gorm().First(&dev, device.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if diff := dev.LastPolled.Sub(rowTime); diff < -time.Minute || diff > time.Minute {
		t.Errorf("last_polled = %v, want ≈ the row time %v (not now)", dev.LastPolled, rowTime)
	}

	// Monotonic: an older spooled batch arriving later (drain interleaves with
	// retries) must never drag last_polled backwards.
	older := time.Now().Add(-3*time.Hour - 30*time.Minute)
	body = []map[string]interface{}{{"device_id": device.ID, "timestamp": older}}
	if w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-status", probe.ID, probe.RegistrationKey, body); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var dev2 models.Device
	if err := db.Gorm().First(&dev2, device.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if !dev2.LastPolled.Equal(dev.LastPolled) {
		t.Errorf("last_polled regressed from %v to %v on an older batch", dev.LastPolled, dev2.LastPolled)
	}
}

// TestRelayHandlers_StaleEvidenceNeverRevives: a drain batch whose rows are
// older than the freshness window advances last_polled but must NOT flip an
// offline device back online — each re-flip would cost a duplicate dedup-free
// DEVICE_OFFLINE critical email when the sweep re-fires. Fresh rows still
// re-online as before.
func TestRelayHandlers_StaleEvidenceNeverRevives(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	seed := time.Now().Add(-4 * time.Hour)
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", device.ID).
		Updates(map[string]interface{}{"status": "offline", "last_polled": seed}).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Stale rows (3h old): clock advances, status must stay offline.
	rowTime := time.Now().Add(-3 * time.Hour)
	body := []map[string]interface{}{{"device_id": device.ID, "timestamp": rowTime}}
	if w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-status", probe.ID, probe.RegistrationKey, body); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var dev models.Device
	if err := db.Gorm().First(&dev, device.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if dev.Status != "offline" {
		t.Errorf("status = %q after stale-row batch, want offline (stale evidence must not revive)", dev.Status)
	}
	if diff := dev.LastPolled.Sub(rowTime); diff < -time.Minute || diff > time.Minute {
		t.Errorf("last_polled = %v, want ≈ %v (clock still advances on stale evidence)", dev.LastPolled, rowTime)
	}

	// Fresh rows (zero timestamp → handler stamps now): device comes online.
	body = []map[string]interface{}{{"device_id": device.ID}}
	before := time.Now().Add(-time.Second)
	if w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-status", probe.ID, probe.RegistrationKey, body); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var dev2 models.Device
	if err := db.Gorm().First(&dev2, device.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if dev2.Status != "online" || dev2.LastPolled.Before(before) {
		t.Errorf("fresh batch did not re-online: status=%q last_polled=%v", dev2.Status, dev2.LastPolled)
	}
}

// TestReceivePingResults_PerDeviceTimestamps pins the per-device evidence map:
// one drained ping batch can span hours and multiple devices, so device A's
// fresh success must not extend dead device B's evidence, and B's spooled
// FAILURES newer than its last success must not extend it either.
func TestReceivePingResults_PerDeviceTimestamps(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, deviceA := setupProbeAndDevice(t, db)
	deviceB := &models.Device{Name: "test-fw-b", IPAddress: "192.168.1.2", ProbeID: &probe.ID}
	if err := db.Gorm().Create(deviceB).Error; err != nil {
		t.Fatalf("create device B: %v", err)
	}

	seed := time.Now().Add(-4 * time.Hour)
	for _, id := range []uint{deviceA.ID, deviceB.ID} {
		if err := db.Gorm().Model(&models.Device{}).Where("id = ?", id).
			Updates(map[string]interface{}{"status": "online", "last_polled": seed}).Error; err != nil {
			t.Fatalf("seed device %d: %v", id, err)
		}
	}

	bSuccess := time.Now().Add(-3 * time.Hour)
	bFailure := time.Now().Add(-1 * time.Hour)
	body := []map[string]interface{}{
		{"device_id": deviceA.ID, "target_ip": deviceA.IPAddress, "success": true, "latency": 1.0},
		{"device_id": deviceB.ID, "target_ip": deviceB.IPAddress, "success": true, "latency": 1.0, "timestamp": bSuccess},
		{"device_id": deviceB.ID, "target_ip": deviceB.IPAddress, "success": false, "timestamp": bFailure},
	}
	before := time.Now().Add(-time.Second)
	if w := doTestRequest(t, h.ReceivePingResults, "POST", "/pings", probe.ID, probe.RegistrationKey, body); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var a, b models.Device
	if err := db.Gorm().First(&a, deviceA.ID).Error; err != nil {
		t.Fatalf("reload A: %v", err)
	}
	if err := db.Gorm().First(&b, deviceB.ID).Error; err != nil {
		t.Fatalf("reload B: %v", err)
	}
	if a.Status != "online" || a.LastPolled.Before(before) {
		t.Errorf("device A not bumped to now: status=%q last_polled=%v", a.Status, a.LastPolled)
	}
	if diff := b.LastPolled.Sub(bSuccess); diff < -time.Minute || diff > time.Minute {
		t.Errorf("device B last_polled = %v, want ≈ its own last SUCCESS %v (not A's fresh row, not B's newer failure)",
			b.LastPolled, bSuccess)
	}
}

// TestReceivePingResults_OnlySuccessBumps: a successful ping proves the device
// is reachable and bumps last_polled; a batch of FAILED pings must not keep an
// unreachable device online.
func TestReceivePingResults_OnlySuccessBumps(t *testing.T) {
	for _, tc := range []struct {
		name     string
		success  bool
		wantBump bool
	}{
		{"success-bumps", true, true},
		{"failure-does-not", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db := setupTestHandler(t)
			probe, device := setupProbeAndDevice(t, db)

			stale := time.Now().Add(-time.Hour)
			if err := db.Gorm().Model(&models.Device{}).Where("id = ?", device.ID).
				Updates(map[string]interface{}{"status": "offline", "last_polled": stale}).Error; err != nil {
				t.Fatalf("seed stale device: %v", err)
			}

			body := []map[string]interface{}{{
				"device_id": device.ID,
				"target_ip": device.IPAddress,
				"success":   tc.success,
				"latency":   1.5,
			}}
			before := time.Now().Add(-time.Second)
			w := doTestRequest(t, h.ReceivePingResults, "POST", "/pings", probe.ID, probe.RegistrationKey, body)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}

			var dev models.Device
			if err := db.Gorm().First(&dev, device.ID).Error; err != nil {
				t.Fatalf("reload device: %v", err)
			}
			bumped := dev.Status == "online" && !dev.LastPolled.Before(before)
			if bumped != tc.wantBump {
				t.Errorf("bumped=%v want %v (status=%q last_polled=%v)", bumped, tc.wantBump, dev.Status, dev.LastPolled)
			}
		})
	}
}
