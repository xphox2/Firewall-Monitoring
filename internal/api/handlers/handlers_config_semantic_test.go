package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestGetDeviceConfigDiff_ObjectChanges_Shape asserts the diff endpoint returns
// the per-object semantic diff + summary the object view renders. fortigateRawA
// -> fortigateRawC adds firewall policy 2 (a real change), so object_changes must
// contain it while admin (only ENC/last-login drift) must NOT appear.
func TestGetDeviceConfigDiff_ObjectChanges_Shape(t *testing.T) {
	h, _, device := setupFortiGateProbeDevice(t)

	rev1 := &models.DeviceConfigRevision{
		DeviceID: device.ID, Checksum: "raw-1", NormalizedChecksum: "norm-A",
		ConfigText: fortigateRawA, Length: len(fortigateRawA), BackupQuality: "full",
	}
	rev2 := &models.DeviceConfigRevision{
		DeviceID: device.ID, Checksum: "raw-3", NormalizedChecksum: "norm-C",
		ConfigText: fortigateRawC, Length: len(fortigateRawC), BackupQuality: "full",
	}
	if err := h.db.Gorm().Create(rev1).Error; err != nil {
		t.Fatalf("create rev1: %v", err)
	}
	if err := h.db.Gorm().Create(rev2).Error; err != nil {
		t.Fatalf("create rev2: %v", err)
	}

	w := doDiffEndpointRequest(t, h, device.ID, rev1.ID, rev2.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			ObjectChanges []struct {
				Path string `json:"path"`
				Op   string `json:"op"`
				Risk struct {
					Severity string `json:"severity"`
				} `json:"risk"`
			} `json:"object_changes"`
			Summary struct {
				Added       int    `json:"added"`
				Modified    int    `json:"modified"`
				MaxSeverity string `json:"max_severity"`
			} `json:"summary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}

	var addedPolicy2, sawAdmin bool
	for _, c := range resp.Data.ObjectChanges {
		if c.Path == "firewall.policy/2" && c.Op == "added" {
			addedPolicy2 = true
		}
		if c.Path == "system.admin/admin" {
			sawAdmin = true
		}
	}
	if !addedPolicy2 {
		t.Errorf("expected firewall.policy/2 added in object_changes; got %+v", resp.Data.ObjectChanges)
	}
	if sawAdmin {
		t.Error("system.admin/admin should NOT appear (only ENC/last-login drift, normalized away)")
	}
	if resp.Data.Summary.Added < 1 {
		t.Errorf("summary.added = %d, want >= 1", resp.Data.Summary.Added)
	}
}

// TestReceiveConfigRevision_AttributionFromSyslog proves a real config change is
// attributed to the admin from a correlated FortiGate config-change syslog event,
// and that the revision row + alert carry that attribution.
func TestReceiveConfigRevision_AttributionFromSyslog(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)
	am := alerts.NewAlertManager(&config.Config{}, nil, h.db.(*database.Database))
	h.SetAlertManager(am)

	// First backup establishes the baseline (insert-first, no alert/attribution).
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "raw-a",
		"length":      len(fortigateRawA),
	})

	// A FortiGate config-change event arrives for this device just before the
	// change-detection backup that captures the new state.
	syslog := &models.SyslogMessage{
		DeviceID:  device.ID,
		Timestamp: time.Now(),
		SourceIP:  "10.20.30.40",
		Message: `logid="0100044546" type="event" subtype="system" user="netadmin" ` +
			`ui="GUI(10.20.30.40)" action="Edit" cfgpath="firewall.policy" cfgobj="2"`,
	}
	if err := h.db.Gorm().Create(syslog).Error; err != nil {
		t.Fatalf("create syslog: %v", err)
	}

	// Second backup carries the real change (policy 2 added) -> insert-change.
	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawC,
		"checksum":    "raw-c",
		"length":      len(fortigateRawC),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	// The newest revision row must be attributed to the admin.
	var rev models.DeviceConfigRevision
	if err := h.db.Gorm().Where("device_id = ?", device.ID).Order("id DESC").First(&rev).Error; err != nil {
		t.Fatalf("load latest rev: %v", err)
	}
	if rev.ChangedBy != "netadmin" {
		t.Errorf("ChangedBy = %q, want netadmin", rev.ChangedBy)
	}
	if rev.ChangeMethod != "GUI" {
		t.Errorf("ChangeMethod = %q, want GUI", rev.ChangeMethod)
	}
	if !rev.Attributed {
		t.Error("Attributed should be true when a matching session was found")
	}
	if !rev.AttributionChecked {
		t.Error("AttributionChecked should be true for a real change")
	}

	// The alert should exist and name the admin.
	var alert models.Alert
	if err := h.db.Gorm().Where("device_id = ? AND alert_type = ?", device.ID, "CONFIG_CHANGE").
		Order("id DESC").First(&alert).Error; err != nil {
		t.Fatalf("expected a CONFIG_CHANGE alert: %v", err)
	}
	if want := "netadmin"; !strings.Contains(alert.Message, want) {
		t.Errorf("alert message %q should mention %q", alert.Message, want)
	}
}

// TestReceiveConfigRevision_OutOfBandWhenNoSyslog proves a real change with no
// correlating syslog event is flagged unattributed (possible out-of-band) and the
// alert is escalated accordingly.
func TestReceiveConfigRevision_OutOfBandWhenNoSyslog(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)
	am := alerts.NewAlertManager(&config.Config{}, nil, h.db.(*database.Database))
	h.SetAlertManager(am)

	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "raw-a",
		"length":      len(fortigateRawA),
	})
	// No syslog event seeded -> change cannot be attributed.
	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawC,
		"checksum":    "raw-c",
		"length":      len(fortigateRawC),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var rev models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id DESC").First(&rev)
	if rev.Attributed {
		t.Error("Attributed should be false with no correlating syslog event")
	}
	// The change WAS checked (correlation attempted) — this is what distinguishes
	// a genuine out-of-band change from a never-correlated first-seen row.
	if !rev.AttributionChecked {
		t.Error("AttributionChecked should be true (correlation was attempted) even when no session matched")
	}
	// The baseline (first-seen) revision must NOT be marked checked — it is not a
	// real change and must never render as out-of-band.
	var baseline models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").First(&baseline)
	if baseline.AttributionChecked {
		t.Error("first-seen baseline revision must have AttributionChecked=false (never correlated)")
	}

	var alert models.Alert
	if err := h.db.Gorm().Where("device_id = ? AND alert_type = ?", device.ID, "CONFIG_CHANGE").
		Order("id DESC").First(&alert).Error; err != nil {
		t.Fatalf("expected a CONFIG_CHANGE alert: %v", err)
	}
	if !strings.Contains(alert.Message, "out-of-band") {
		t.Errorf("alert message %q should flag possible out-of-band change", alert.Message)
	}
}
