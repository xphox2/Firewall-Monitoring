package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// fortigatePadding is shared filler used to push the test fixtures past the
// 1KB minimum the validator (configdiff.ValidateFortiGateBackup) requires.
// It contains multiple structurally valid `config X / end` blocks so the
// block-count threshold is also satisfied. The same padding is applied to
// every fixture so the normalized hashes still differ only where the
// fixture-specific lines differ.
const fortigatePadding = `
config system replacemsg-image
    edit "default-image-1"
        set image-type "gif"
    next
    edit "default-image-2"
        set image-type "gif"
    next
end
config system dns
    set primary 8.8.8.8
    set secondary 8.8.4.4
end
config system ntp
    set ntpsync enable
end
config system snmp sysinfo
    set status disable
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 192.168.1.1
        set device "wan1"
    next
end
config firewall service category
    edit "General"
        set comment "General services"
    next
    edit "Web Access"
    next
end
`

// FortiOS-shaped config snapshots that differ only in volatile lines (random
// 4-byte ENC IV salt + private-key body + #conf_file_ver). Two unchanged
// backups of the same logical config look like this.
const fortigateRawA = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466111111
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC AbCdEfGh1234567890iVrandomA==
        set last-login 2026-04-27 14:32:11
    next
end
config vpn certificate local
    edit "Fortinet_CA_SSL"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
RANDOM_IV_AAAA_body_aaaa
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
        set action accept
    next
end
` + fortigatePadding

const fortigateRawB = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466222222
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC QqWwEeRr1111111111iVrandomB==
        set last-login 2026-04-27 14:38:42
    next
end
config vpn certificate local
    edit "Fortinet_CA_SSL"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
RANDOM_IV_BBBB_body_bbbb
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
        set action accept
    next
end
` + fortigatePadding

// Real change: a second firewall policy added.
const fortigateRawC = `#config-version=FGT60F-7.4.4-FW-build2660-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=58388916466333333
config system global
    set hostname "FW-HOME"
    set admin-port 443
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC NewIVCcccCccccccccccccccccc==
        set last-login 2026-04-27 15:00:00
    next
end
config vpn certificate local
    edit "Fortinet_CA_SSL"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
RANDOM_IV_CCCC_body_cccc
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
config firewall policy
    edit 1
        set name "ALLOW_LAN"
        set action accept
    next
    edit 2
        set name "ALLOW_GUEST"
        set action accept
    next
end
` + fortigatePadding

func setupFortiGateProbeDevice(t *testing.T) (*Handler, *models.Probe, *models.Device) {
	t.Helper()
	h, db := setupTestHandler(t)
	const probeKey = "test-key-abc123"
	probe := &models.Probe{
		Name:            "test-probe",
		RegistrationKey: database.HashProbeKey(probeKey), // AUDIT-017: stored hashed
		ApprovalStatus:  "approved",
		Status:          "online",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("create probe: %v", err)
	}
	probe.RegistrationKey = probeKey // expose plaintext for the Bearer token
	device := &models.Device{
		Name:      "fgt-1",
		IPAddress: "192.168.5.2",
		Vendor:    "fortigate", // critical: routes through configdiff.vendor_fortigate
		ProbeID:   &probe.ID,
	}
	if err := db.Gorm().Create(device).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	return h, probe, device
}

// The marquee test: prove that two "no real change" FortiGate backups don't
// produce a CONFIG_CHANGE alert opportunity. Both rows are stored (always-
// IV-drifted backups (different raw bytes, same normalized hash) MERGE into
// the prior row in v0.10.198+. We get exactly one row, VerifyCount=2, and the
// stored ConfigText is the *latest* bytes (so restore has fresh ENC ciphertext).
//
// As of v0.10.200 this test also wires up a real AlertManager and asserts the
// CONFIG_CHANGE alerts table is empty after the merge — the false-alert
// regression we keep coming back to. If a future change in the normalizer or
// handler flow accidentally re-introduces the alert on IV drift, this test
// fails loudly instead of silently sending production noise.
func TestReceiveConfigRevision_FortiGateIVDrift_MergesIntoLatest(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)
	am := alerts.NewAlertManager(&config.Config{}, nil, h.db)
	h.SetAlertManager(am)

	body1 := map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "raw-a-md5",
		"length":      len(fortigateRawA),
	}
	body2 := map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawB,
		"checksum":    "raw-b-md5", // different raw checksum (random IVs change every emission)
		"length":      len(fortigateRawB),
	}

	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, body1)
	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, body2)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 1 {
		t.Fatalf("merge-into-latest: expected 1 stored revision, got %d", len(revs))
	}

	rev := revs[0]
	if rev.VerifyCount != 2 {
		t.Errorf("VerifyCount = %d, want 2 (one insert + one merge)", rev.VerifyCount)
	}
	// The stored bytes must be the LATEST (B), not the first (A) — that's the
	// restorability guarantee.
	if rev.Checksum != "raw-b-md5" {
		t.Errorf("merged Checksum should be the latest emission's: got %q, want %q",
			rev.Checksum, "raw-b-md5")
	}
	if rev.ConfigText != fortigateRawB {
		t.Errorf("merged ConfigText should be the latest emission's bytes (B), not the original (A)")
	}

	// The response action must be "merge" — distinct from "insert-change",
	// which is the only path that triggers CheckConfigRevision.
	var resp struct {
		Data struct {
			Action string `json:"action"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v body=%s", err, w.Body.String())
	}
	if resp.Data.Action != "merge" {
		t.Errorf("action = %q, want %q (IV-drift must merge, not insert-change)",
			resp.Data.Action, "merge")
	}

	// Zero CONFIG_CHANGE alerts must have been raised. This is the marquee
	// guarantee: the false-alert problem is gone.
	var alertCount int64
	h.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ?", device.ID, "CONFIG_CHANGE").
		Count(&alertCount)
	if alertCount != 0 {
		t.Errorf("CONFIG_CHANGE alerts after IV-drift merge = %d, want 0 — FALSE ALERT REGRESSION",
			alertCount)
	}
}

// Counterpart to the merge test: a real config change MUST fire exactly one
// CONFIG_CHANGE alert. Without this assertion paired against the no-alert one
// above, a regression that silenced all config alerts entirely would slip
// through the merge test.
func TestReceiveConfigRevision_FortiGateRealChange_FiresExactlyOneAlert(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)
	am := alerts.NewAlertManager(&config.Config{}, nil, h.db)
	h.SetAlertManager(am)

	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "raw-a",
		"length":      len(fortigateRawA),
	})
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawC, // adds policy 2 — real structural change
		"checksum":    "raw-c",
		"length":      len(fortigateRawC),
	})

	var alertCount int64
	h.db.Gorm().Model(&models.Alert{}).
		Where("device_id = ? AND alert_type = ?", device.ID, "CONFIG_CHANGE").
		Count(&alertCount)
	if alertCount != 1 {
		t.Errorf("CONFIG_CHANGE alerts after real change = %d, want 1", alertCount)
	}
}

// Suspect bytes (failing the structural validator) MUST NOT overwrite the
// previously-good revision in place. They INSERT as a new row tagged
// "suspect" so the prior good copy is preserved as a safety net.
func TestReceiveConfigRevision_SuspectBytes_DoNotOverwriteGood(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

	// 1) First, a good backup. This INSERTs and becomes the latest revision.
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "good-md5",
		"length":      len(fortigateRawA),
	})

	// 2) A truncated/garbage payload arrives — too small to validate, but the
	//    HTTP-level size limit (50MB) accepts it. Server tags as suspect and
	//    INSERTs a new row rather than overwriting the good prior bytes.
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": "this is not a real config, way too short",
		"checksum":    "bad-md5",
		"length":      40,
	})

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 2 {
		t.Fatalf("suspect bytes must INSERT, not merge: expected 2 rows, got %d", len(revs))
	}

	good, suspect := revs[0], revs[1]
	if good.Checksum != "good-md5" {
		t.Errorf("first row should still hold the good bytes; checksum=%q", good.Checksum)
	}
	if good.ConfigText != fortigateRawA {
		t.Error("first row's ConfigText was overwritten by suspect bytes — DATA LOSS REGRESSION")
	}
	if suspect.BackupQuality != "suspect" {
		t.Errorf("second row should be tagged 'suspect'; got %q", suspect.BackupQuality)
	}
}

// Counterpart: a real config change (added firewall policy) MUST produce a
// different normalized hash so the alert path can fire.
func TestReceiveConfigRevision_FortiGateRealChange_DetectedViaNormalizedHash(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "raw-a",
		"length":      len(fortigateRawA),
	})
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawC, // adds policy 2
		"checksum":    "raw-c",
		"length":      len(fortigateRawC),
	})

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 2 {
		t.Fatalf("expected 2 stored revisions, got %d", len(revs))
	}
	if revs[0].NormalizedChecksum == revs[1].NormalizedChecksum {
		t.Errorf("real change (added policy) must produce different normalized hashes; got identical: %q",
			revs[0].NormalizedChecksum)
	}
}

// Provenance flows through the JSON body: TriggerSource the collector sets
// is stored on first INSERT, and refreshed to the latest value on each merge.
// (BackupQuality is similar — masking can be turned on/off across emissions.)
//
// In v0.10.198+, two backups of the same logical state merge into one row, so
// the test verifies the LATEST trigger/quality values are reflected after the
// merge, with VerifyCount=2.
func TestReceiveConfigRevision_TriggerSourceAndQualityRoundTrip(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

	// Explicit syslog trigger + masked quality from collector
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":      device.ID,
		"config_text":    fortigateRawA,
		"checksum":       "x",
		"length":         len(fortigateRawA),
		"trigger_source": "syslog",
		"backup_quality": "masked",
	})

	// Same logical state from a poll cycle — should MERGE into the prior row.
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawB,
		"checksum":    "y",
		"length":      len(fortigateRawB),
	})

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 1 {
		t.Fatalf("merge-into-latest: expected 1 revision, got %d", len(revs))
	}
	rev := revs[0]
	if rev.VerifyCount != 2 {
		t.Errorf("VerifyCount = %d, want 2", rev.VerifyCount)
	}
	// On merge the latest emission's trigger/quality win — that's the most
	// recent provenance the system has.
	if rev.TriggerSource != "poll" {
		t.Errorf("trigger_source after merge: got %q want %q (latest emission's value)",
			rev.TriggerSource, "poll")
	}
	if rev.BackupQuality == "" {
		t.Error("backup_quality must be populated even after merge")
	}
}

// Response body shape sanity (helps the collector know what was stored).
func TestReceiveConfigRevision_ResponseShape(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "x",
		"length":      len(fortigateRawA),
	})

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Saved              uint   `json:"saved"`
			NormalizedChecksum string `json:"normalized_checksum"`
			TriggerSource      string `json:"trigger_source"`
			BackupQuality      string `json:"backup_quality"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if !resp.Success {
		t.Errorf("success = false")
	}
	if resp.Data.Saved == 0 {
		t.Errorf("saved id must be non-zero")
	}
	if resp.Data.NormalizedChecksum == "" {
		t.Errorf("normalized_checksum must be in response")
	}
	if resp.Data.TriggerSource != "poll" {
		t.Errorf("trigger_source default should be 'poll', got %q", resp.Data.TriggerSource)
	}
}
