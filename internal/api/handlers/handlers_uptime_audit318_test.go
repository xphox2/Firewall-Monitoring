package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

type uptimeStatsView struct {
	UptimePercent  float64 `json:"uptime_percent"`
	TotalDowntime  float64 `json:"total_downtime_seconds"`
	DowntimeEvents int     `json:"downtime_events"`
	CurrentUptime  uint64  `json:"current_uptime"`
}

// insertStatus seeds one system_status row for a device.
func insertStatus(t *testing.T, h *Handler, deviceID uint, ts time.Time, uptimeTicks uint64) {
	t.Helper()
	row := &models.SystemStatus{DeviceID: deviceID, Timestamp: ts, Uptime: uptimeTicks}
	if err := h.db.Gorm().Create(row).Error; err != nil {
		t.Fatalf("seed system_status: %v", err)
	}
}

// callGetUptime invokes GetUptime for a device_id and returns the decoded stats.
func callGetUptime(t *testing.T, h *Handler, deviceID uint) uptimeStatsView {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/uptime?device_id="+strconv.Itoa(int(deviceID)), nil)

	h.GetUptime(c)

	if w.Code != http.StatusOK {
		t.Fatalf("GetUptime status = %d, want 200", w.Code)
	}
	var env struct {
		Data struct {
			DeviceID uint            `json:"device_id"`
			Stats    uptimeStatsView `json:"stats"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v (%s)", err, w.Body.String())
	}
	if env.Data.DeviceID != deviceID {
		t.Fatalf("response device_id = %d, want %d", env.Data.DeviceID, deviceID)
	}
	return env.Data.Stats
}

// TestGetUptime_PerDeviceIndependent (AUDIT-318): GetUptime with a device_id
// returns availability computed from THAT device's system_status history, and
// two devices yield independent numbers — device 1 (a reboot) reports a down
// event with accumulated downtime, device 2 (monotonic) reports none.
func TestGetUptime_PerDeviceIndependent(t *testing.T) {
	h, _ := setupTestHandler(t)

	d1 := &models.Device{Name: "fw1", IPAddress: "10.0.0.1"}
	d2 := &models.Device{Name: "fw2", IPAddress: "10.0.0.2"}
	if err := h.db.Gorm().Create(d1).Error; err != nil {
		t.Fatalf("create d1: %v", err)
	}
	if err := h.db.Gorm().Create(d2).Error; err != nil {
		t.Fatalf("create d2: %v", err)
	}

	base := time.Now().Add(-4 * time.Hour)
	// device 1: counter drops (reboot) between samples 2 and 3.
	insertStatus(t, h, d1.ID, base, 500000)
	insertStatus(t, h, d1.ID, base.Add(time.Hour), 900000)
	insertStatus(t, h, d1.ID, base.Add(2*time.Hour), 10000)
	insertStatus(t, h, d1.ID, base.Add(3*time.Hour), 50000)
	// device 2: strictly monotonic.
	insertStatus(t, h, d2.ID, base, 100000)
	insertStatus(t, h, d2.ID, base.Add(time.Hour), 200000)
	insertStatus(t, h, d2.ID, base.Add(2*time.Hour), 300000)

	s1 := callGetUptime(t, h, d1.ID)
	s2 := callGetUptime(t, h, d2.ID)

	if s1.DowntimeEvents != 1 {
		t.Errorf("device 1 DowntimeEvents = %d, want 1", s1.DowntimeEvents)
	}
	if s1.TotalDowntime <= 0 {
		t.Errorf("device 1 TotalDowntime = %f, want > 0", s1.TotalDowntime)
	}
	if s2.DowntimeEvents != 0 {
		t.Errorf("device 2 DowntimeEvents = %d, want 0 (leak from device 1)", s2.DowntimeEvents)
	}
	if s1.CurrentUptime == 0 || s2.CurrentUptime == 0 {
		t.Errorf("current uptime frozen at zero: d1=%d d2=%d", s1.CurrentUptime, s2.CurrentUptime)
	}
	if s1.DowntimeEvents == s2.DowntimeEvents {
		t.Errorf("devices not independent: both DowntimeEvents = %d", s1.DowntimeEvents)
	}
}

// TestSnapshotUptime_PersistsDeviceTaggedRecord (AUDIT-318): the periodic
// snapshot persists an uptime_records row with a NON-ZERO DeviceID, guarding
// the old GetUptimeRecord DeviceID=0 defect, and the record is retrievable via
// the device-scoped GetUptimeRecords.
func TestSnapshotUptime_PersistsDeviceTaggedRecord(t *testing.T) {
	h, db := setupTestHandler(t)

	d := &models.Device{Name: "fw", IPAddress: "10.0.0.9"}
	if err := db.Gorm().Create(d).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	base := time.Now().Add(-2 * time.Hour)
	insertStatus(t, h, d.ID, base, 100000)
	insertStatus(t, h, d.ID, base.Add(time.Hour), 200000)

	h.SnapshotUptime()

	recs, err := db.GetUptimeRecords(d.ID, 100)
	if err != nil {
		t.Fatalf("GetUptimeRecords: %v", err)
	}
	if len(recs) == 0 {
		t.Fatalf("no uptime_records persisted by snapshot")
	}
	if recs[0].DeviceID != d.ID {
		t.Fatalf("persisted DeviceID = %d, want %d (DeviceID=0 defect)", recs[0].DeviceID, d.ID)
	}
}
