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
