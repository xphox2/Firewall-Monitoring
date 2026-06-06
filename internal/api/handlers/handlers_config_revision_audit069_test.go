package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestConfigRevision_AcceptsBackupQualityField(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":      device.ID,
		"config_text":    fortigateRawA,
		"checksum":       "raw-masked",
		"length":         len(fortigateRawA),
		"backup_quality": "masked",
		"trigger_source": "syslog",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 1 {
		t.Fatalf("expected 1 stored revision, got %d", len(revs))
	}
	if revs[0].BackupQuality != "masked" {
		t.Errorf("BackupQuality = %q, want %q (server must accept the wire field, not drop it)",
			revs[0].BackupQuality, "masked")
	}
	if revs[0].TriggerSource != "syslog" {
		t.Errorf("TriggerSource = %q, want %q", revs[0].TriggerSource, "syslog")
	}

	var resp struct {
		Data struct {
			BackupQuality string `json:"backup_quality"`
			TriggerSource string `json:"trigger_source"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v body=%s", err, w.Body.String())
	}
	if resp.Data.BackupQuality != "masked" {
		t.Errorf("response backup_quality = %q, want %q", resp.Data.BackupQuality, "masked")
	}
	if resp.Data.TriggerSource != "syslog" {
		t.Errorf("response trigger_source = %q, want %q", resp.Data.TriggerSource, "syslog")
	}
}

func TestConfigRevision_LegacyWithoutField_StillWorks(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": fortigateRawA,
		"checksum":    "legacy-raw",
		"length":      len(fortigateRawA),
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&revs)
	if len(revs) != 1 {
		t.Fatalf("expected 1 stored revision, got %d", len(revs))
	}
	if revs[0].TriggerSource != "poll" {
		t.Errorf("TriggerSource default = %q, want %q (collector omitted it; server must default)",
			revs[0].TriggerSource, "poll")
	}
	if revs[0].BackupQuality == "" {
		t.Error("BackupQuality must be populated by the server-side normalizer when the collector omits it")
	}

	var resp struct {
		Data struct {
			BackupQuality string `json:"backup_quality"`
			TriggerSource string `json:"trigger_source"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v body=%s", err, w.Body.String())
	}
	if resp.Data.BackupQuality == "" {
		t.Error("response data.backup_quality must be populated even when the collector omits it")
	}
	if resp.Data.TriggerSource != "poll" {
		t.Errorf("response data.trigger_source = %q, want %q", resp.Data.TriggerSource, "poll")
	}
}

func TestConfigRevision_MetricIncrements(t *testing.T) {
	h, probe, device := setupFortiGateProbeDevice(t)

	before := h.backupQualitySnapshot()

	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":      device.ID,
		"config_text":    fortigateRawA,
		"checksum":       "raw-m1",
		"length":         len(fortigateRawA),
		"backup_quality": "masked",
	})
	doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":      device.ID,
		"config_text":    fortigateRawC,
		"checksum":       "raw-m2",
		"length":         len(fortigateRawC),
		"backup_quality": "masked",
	})

	after := h.backupQualitySnapshot()

	if got := after["masked"] - before["masked"]; got != 2 {
		t.Errorf("probe_config_backup_quality_total{quality=\"masked\"} delta = %d, want 2 (each masked backup must tick the counter exactly once)", got)
	}
}

func TestGetDeviceConfigHistory_QualityFilter(t *testing.T) {
	h, _, device := setupFortiGateProbeDevice(t)

	now := time.Now()
	mk := func(idx int, quality string) {
		rev := &models.DeviceConfigRevision{
			DeviceID:           device.ID,
			Timestamp:          now.Add(time.Duration(idx) * time.Minute),
			FirstSeenAt:        now.Add(time.Duration(idx) * time.Minute),
			LastVerifiedAt:     now.Add(time.Duration(idx)*time.Minute + 30*time.Second),
			VerifyCount:        1,
			Checksum:           "raw-" + string(rune('a'+idx)),
			NormalizedChecksum: "norm-" + string(rune('a'+idx)),
			ConfigText:         "c" + string(rune('a'+idx)),
			Length:             1,
			BackupQuality:      quality,
		}
		if err := h.db.Gorm().Create(rev).Error; err != nil {
			t.Fatalf("create rev %d: %v", idx, err)
		}
	}
	mk(0, "full")
	mk(1, "masked")
	mk(2, "full")
	mk(3, "masked")
	mk(4, "suspect")

	type resp struct {
		Success bool `json:"success"`
		Data    struct {
			Revisions  []models.DeviceConfigRevision `json:"revisions"`
			TotalAll   int                           `json:"total_all"`
			TotalShown int                           `json:"total_shown"`
			Quality    string                        `json:"quality"`
		} `json:"data"`
	}

	cases := []struct {
		query     string
		wantCount int
		wantQual  string
	}{
		{"", 5, ""},
		{"quality=masked", 2, "masked"},
		{"quality=full", 2, "full"},
		{"quality=suspect", 1, "suspect"},
		{"quality=garbage", 5, ""},
	}
	for _, tc := range cases {
		w := doDeviceQueryRequest(t, h.GetDeviceConfigHistory, "GET", "/config-history", tc.query, device.ID)
		if w.Code != http.StatusOK {
			t.Fatalf("query=%q: status = %d (body=%s)", tc.query, w.Code, w.Body.String())
		}
		var r resp
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatalf("query=%q: unmarshal: %v", tc.query, err)
		}
		if r.Data.TotalAll != 5 {
			t.Errorf("query=%q: total_all = %d, want 5 (filter must not affect total_all)", tc.query, r.Data.TotalAll)
		}
		if r.Data.TotalShown != tc.wantCount {
			t.Errorf("query=%q: total_shown = %d, want %d", tc.query, r.Data.TotalShown, tc.wantCount)
		}
		if r.Data.Quality != tc.wantQual {
			t.Errorf("query=%q: echoed quality = %q, want %q", tc.query, r.Data.Quality, tc.wantQual)
		}
		for _, r0 := range r.Data.Revisions {
			if tc.wantQual != "" && r0.BackupQuality != tc.wantQual {
				t.Errorf("query=%q: revision with quality=%q leaked into filtered list", tc.query, r0.BackupQuality)
			}
		}
	}
}
