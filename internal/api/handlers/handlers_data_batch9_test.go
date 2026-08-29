package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"

	"github.com/gin-gonic/gin"
)

// setupTestHandlerWithAlerts wires a real AlertManager (backed by the same test
// DB) so RecordProbeDataTruncation actually writes a PROBE_DATA_TRUNCATED alert
// row we can assert on — the truncation SIGNAL that AUDIT-196's streaming decode
// must preserve.
func setupTestHandlerWithAlerts(t *testing.T) (*Handler, *database.Database) {
	t.Helper()
	h, db := setupTestHandler(t)
	cfg := &config.Config{}
	am := alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db)
	h.SetAlertManager(am)
	return h, db
}

func savedCount(t *testing.T, body []byte) float64 {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v (%s)", err, string(body))
	}
	data, _ := resp["data"].(map[string]interface{})
	saved, _ := data["saved"].(float64)
	return saved
}

func truncationAlertCount(t *testing.T, db *database.Database) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ?", "PROBE_DATA_TRUNCATED").Count(&n).Error; err != nil {
		t.Fatalf("count truncation alerts: %v", err)
	}
	return n
}

// ── AUDIT-196: decode-time cap + preserved truncation alert ───────────────────

// TestReceiveSystemStatuses_TruncationAlertFires pins the AUDIT-196 requirement
// that the decode caps at 100 AND the operator-visible PROBE_DATA_TRUNCATED
// alert still fires (the streaming decoder counts the dropped tail without
// retaining it, so the 20%-overshoot threshold is evaluated on the true count).
func TestReceiveSystemStatuses_TruncationAlertFires(t *testing.T) {
	h, db := setupTestHandlerWithAlerts(t)
	probe, device := setupProbeAndDevice(t, db)

	statuses := make([]map[string]interface{}, 200) // cap 100, >20% overshoot
	for i := range statuses {
		statuses[i] = map[string]interface{}{
			"device_id": device.ID,
			"probe_id":  probe.ID,
			"timestamp": time.Now(),
		}
	}

	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey, statuses)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 100 {
		t.Errorf("saved = %v, want exactly 100 (decode cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 1 {
		t.Errorf("PROBE_DATA_TRUNCATED alerts = %d, want 1 (truncation signal lost)", got)
	}
}

// TestReceiveFlowSamples_CapsAt1000AndAlerts is the flows (cap 1000) counterpart:
// a 1300-sample batch is capped to 1000 and fires exactly one truncation alert.
func TestReceiveFlowSamples_CapsAt1000AndAlerts(t *testing.T) {
	h, db := setupTestHandlerWithAlerts(t)
	probe, _ := setupProbeAndDevice(t, db)

	samples := make([]map[string]interface{}, 1300)
	for i := range samples {
		// DeviceID 0 / no sampler address → passes the ownership filter unchanged,
		// so `saved` reflects the decode cap, not device filtering.
		samples[i] = map[string]interface{}{"timestamp": time.Now()}
	}

	w := doTestRequest(t, h.ReceiveFlowSamples, "POST", "/flow-samples", probe.ID, probe.RegistrationKey, samples)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 1000 {
		t.Errorf("saved = %v, want exactly 1000 (decode cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 1 {
		t.Errorf("PROBE_DATA_TRUNCATED alerts = %d, want 1", got)
	}
}

// TestReceiveSystemStatuses_NonArrayBody_Returns400 pins the malformed/non-array
// 400 shape the handlers' ShouldBindJSON path emitted (an object where an array
// is expected).
func TestReceiveSystemStatuses_NonArrayBody_Returns400(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	// A JSON object where the handler expects an array — pre-fix ShouldBindJSON
	// and post-fix decodeCappedArray both 400 this.
	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey,
		map[string]interface{}{"not": "an array"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("non-array body: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

// ── AUDIT-253: the eleven [:500] endpoints now cap at 1000, not 500 ───────────

// TestReceiveVPNStatuses_KeepsRowsBeyond500 is the load-bearing pre-fix-failing
// test: the old handler silently resliced to [:500], dropping rows 501+ with no
// alert. Post-fix the cap is 1000, so a 700-row batch of owned devices keeps ALL
// 700 (pre-fix: 500), and only past 1000 does truncation kick in (with the alert
// AUDIT-196 preserved — pre-fix the [:500] path emitted none).
func TestReceiveVPNStatuses_KeepsRowsBeyond500(t *testing.T) {
	h, db := setupTestHandlerWithAlerts(t)
	probe, device := setupProbeAndDevice(t, db)

	mk := func(n int) []map[string]interface{} {
		rows := make([]map[string]interface{}, n)
		for i := range rows {
			rows[i] = map[string]interface{}{
				"device_id": device.ID,
				"probe_id":  probe.ID,
				"timestamp": time.Now(),
			}
		}
		return rows
	}

	// 700 > old 500 cap: every row must survive now.
	w := doTestRequest(t, h.ReceiveVPNStatuses, "POST", "/vpn-statuses", probe.ID, probe.RegistrationKey, mk(700))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 700 {
		t.Errorf("saved = %v, want 700 (rows 501-700 were dropped at the old 500 cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 0 {
		t.Errorf("truncation alerts = %d, want 0 (700 <= 1000 cap, no truncation)", got)
	}

	// 1300 > 1000 cap: truncated to 1000 and the alert fires.
	w = doTestRequest(t, h.ReceiveVPNStatuses, "POST", "/vpn-statuses", probe.ID, probe.RegistrationKey, mk(1300))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 1000 {
		t.Errorf("saved = %v, want 1000 (cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 1 {
		t.Errorf("truncation alerts = %d, want 1 (1300 > 1000 must alert)", got)
	}
}

// ── AUDIT-255: empty post-filter slice must be 200 {saved:0}, not 500 ─────────

// TestReceiveTailHandlers_AllNotOwned_Returns200 covers the three gorm.Create
// endpoints (InterfaceErrors, SensorDetails, LicenseDetails). Pre-fix, a batch of
// only not-owned devices filtered to an empty slice and gorm.Create returned
// ErrEmptySlice → 500. Post-fix each guards len==0 and returns 200 {saved:0}.
func TestReceiveTailHandlers_AllNotOwned_Returns200(t *testing.T) {
	cases := []struct {
		name string
		path string
		pick func(*Handler) func(*gin.Context)
	}{
		{"InterfaceErrors", "/interface-errors", func(h *Handler) func(*gin.Context) { return h.ReceiveInterfaceErrors }},
		{"SensorDetails", "/sensor-details", func(h *Handler) func(*gin.Context) { return h.ReceiveSensorDetails }},
		{"LicenseDetails", "/license-details", func(h *Handler) func(*gin.Context) { return h.ReceiveLicenseDetails }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db := setupTestHandler(t)
			probe, _ := setupProbeAndDevice(t, db)
			other := &models.Device{Name: "other-fw", IPAddress: "10.77.0.9"}
			if err := db.Gorm().Create(other).Error; err != nil {
				t.Fatalf("create other device: %v", err)
			}
			body := []map[string]interface{}{{
				"device_id": other.ID,
				"probe_id":  probe.ID,
				"timestamp": time.Now(),
			}}
			w := doTestRequest(t, tc.pick(h), "POST", tc.path, probe.ID, probe.RegistrationKey, body)
			if w.Code != http.StatusOK {
				t.Fatalf("%s all-not-owned: status = %d, want 200 (empty filter must not 500); body: %s", tc.name, w.Code, w.Body.String())
			}
			if saved := savedCount(t, w.Body.Bytes()); saved != 0 {
				t.Errorf("%s: saved = %v, want 0", tc.name, saved)
			}
		})
	}
}

// ── AUDIT-254: the config-revision row lock is a real GORM-v2 clause ──────────

// TestReceiveConfigRevision_UsesRowLockClause is a source-level guard: the
// GORM-v1 `gorm:query_option` "FOR UPDATE" key was silently ignored by GORM v2
// (no lock → concurrent backups for one device both read the same prevRev, both
// INSERT → duplicate revisions + CONFIG_CHANGE alerts). The fix must use the v2
// clause.Locking clause and the dead v1 key must be gone. SQLite serializes the
// whole DB so a true concurrency test can't distinguish them; this guards the
// mechanism that protects Postgres.
func TestReceiveConfigRevision_UsesRowLockClause(t *testing.T) {
	src, err := os.ReadFile("handlers_data.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	s := string(src)
	if strings.Contains(s, `gorm:query_option`) {
		t.Error("handlers_data.go still uses the GORM-v1 `gorm:query_option` key (a v2 no-op)")
	}
	if !strings.Contains(s, `clause.Locking{Strength: "UPDATE"}`) {
		t.Error("handlers_data.go must lock with clause.Locking{Strength: \"UPDATE\"} (real FOR UPDATE)")
	}
}
