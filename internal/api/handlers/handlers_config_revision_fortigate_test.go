package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"firewall-mon/internal/models"
)

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
`

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
`

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
`

func setupFortiGateProbeDevice(t *testing.T) (*Handler, *models.Probe, *models.Device) {
	t.Helper()
	h, db := setupTestHandler(t)
	probe := &models.Probe{
		Name:            "test-probe",
		RegistrationKey: "test-key-abc123",
		ApprovalStatus:  "approved",
		Status:          "online",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("create probe: %v", err)
	}
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
// store), and the normalized_checksum is identical between them so the alert
// path's `prevNormalized != rev.NormalizedChecksum` guard short-circuits.
func TestReceiveConfigRevision_FortiGateIVDrift_NoChangeDetected(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

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

	// Both rows must be stored (always-store rule — restorability over dedup).
	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 2 {
		t.Fatalf("expected 2 stored revisions (always-store), got %d", len(revs))
	}

	// The marquee assertion: normalized_checksum must be IDENTICAL across the
	// two rows even though raw bytes differ — the FortiGate normalizer stripped
	// the volatile lines (ENC ciphertext + private-key body + headers).
	if revs[0].NormalizedChecksum == "" {
		t.Fatal("normalized_checksum must be populated on save")
	}
	if revs[0].NormalizedChecksum != revs[1].NormalizedChecksum {
		t.Errorf("FortiGate IV-drifted backups must produce equal normalized hashes:\n  a=%q\n  b=%q",
			revs[0].NormalizedChecksum, revs[1].NormalizedChecksum)
	}

	// The two raw checksums (sent by the collector) should NOT match — that's
	// the whole point: raw bytes drift, normalized doesn't.
	if revs[0].Checksum == revs[1].Checksum {
		t.Errorf("test fixture mistake: raw checksums shouldn't match (test asserts the IV-drift case): a=%q b=%q",
			revs[0].Checksum, revs[1].Checksum)
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

// Provenance flows through the JSON body: TriggerSource and BackupQuality the
// collector sets must end up on the stored row. Defaults apply when omitted.
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

	// Defaults when collector omits them
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawB,
		"checksum":    "y",
		"length":      len(fortigateRawB),
	})

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 2 {
		t.Fatalf("expected 2 revisions, got %d", len(revs))
	}
	if revs[0].TriggerSource != "syslog" {
		t.Errorf("rev0 trigger_source: got %q want %q", revs[0].TriggerSource, "syslog")
	}
	if revs[0].BackupQuality != "masked" {
		t.Errorf("rev0 backup_quality: got %q want %q", revs[0].BackupQuality, "masked")
	}
	if revs[1].TriggerSource != "poll" {
		t.Errorf("rev1 default trigger_source: got %q want %q", revs[1].TriggerSource, "poll")
	}
	if revs[1].BackupQuality == "" {
		t.Error("rev1 backup_quality must default to normalizer-detected value, not empty")
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
