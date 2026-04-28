package handlers

import (
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// seedRevisions inserts n revisions for deviceID, each timestamped at the given
// duration before now (older ones get a more-negative duration). Each row's
// NormalizedChecksum cycles through `checksums` so the caller can build runs
// of identical-vs-distinct hashes for the collapse test.
func seedRevisions(t *testing.T, h *Handler, deviceID uint, n int, ageStep time.Duration, checksums []string) {
	t.Helper()
	now := time.Now()
	for i := 0; i < n; i++ {
		ts := now.Add(-time.Duration(i) * ageStep)
		cs := checksums[i%len(checksums)]
		rev := &models.DeviceConfigRevision{
			DeviceID:           deviceID,
			Timestamp:          ts,
			Checksum:           "raw-" + strconv.Itoa(i),
			NormalizedChecksum: cs,
			ConfigText:         "config-" + strconv.Itoa(i),
			Length:             10,
		}
		if err := h.db.Gorm().Create(rev).Error; err != nil {
			t.Fatalf("create rev %d: %v", i, err)
		}
	}
}

func TestCleanupConfigRevisions_KeepsTop50Regardless(t *testing.T) {
	// Scenario: 200 revisions, all spread over the last 7 days. The top-50
	// floor should keep the 50 newest. The 90-day window keeps everything,
	// but identical-NormalizedChecksum runs in rows 51-200 should collapse to
	// distinct values only.
	h, _, device := setupFortiGateProbeDevice(t)
	// 5 distinct checksums cycling — many duplicates in the older window.
	seedRevisions(t, h, device.ID, 200, 1*time.Hour, []string{"a", "b", "c", "d", "e"})

	if err := h.db.CleanupConfigRevisions(); err != nil {
		t.Fatalf("CleanupConfigRevisions: %v", err)
	}

	// Top 50 newest must all survive — all 50 rows still in DB.
	var newest []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("timestamp DESC").Limit(50).Find(&newest)
	if len(newest) != 50 {
		t.Errorf("top-50: got %d, want 50 still present", len(newest))
	}

	// In the older window, only one row per distinct NormalizedChecksum should
	// remain. With 5 distinct checksums, 5 rows older than the 50-row floor.
	var older []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ? AND timestamp < ?", device.ID, newest[len(newest)-1].Timestamp).
		Order("timestamp DESC").Find(&older)
	if len(older) > 5 {
		t.Errorf("older window should have at most 5 rows after collapse (one per distinct hash), got %d", len(older))
	}

	// Sanity: union of newest + older should be 50 + at-most-5 = at-most-55.
	var total int64
	h.db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&total)
	if total > 55 {
		t.Errorf("retention should bound total to ~55, got %d", total)
	}
}

func TestCleanupConfigRevisions_DeletesBeyond90Days(t *testing.T) {
	// Scenario: 60 revisions, spaced 7 days apart → spans 60*7 = 420 days.
	// Top-50 floor kicks in at row 50, but rows older than 90d should still
	// be deleted ONLY if they're outside the top 50. With 60 rows, the top
	// 50 are within ~50*7=350 days; rows 51-60 are >350d old and should be
	// fully deleted (none kept since they're outside top-50 AND >90d).
	h, _, device := setupFortiGateProbeDevice(t)
	seedRevisions(t, h, device.ID, 60, 7*24*time.Hour, []string{"a", "b", "c"})

	if err := h.db.CleanupConfigRevisions(); err != nil {
		t.Fatalf("CleanupConfigRevisions: %v", err)
	}

	// Top 50 are kept regardless of age — the policy says "last 50 OR 90 days,
	// whichever is greater", and 50 > what 90d would yield here.
	var total int64
	h.db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&total)
	if total != 50 {
		t.Errorf("expected exactly 50 rows after cleanup (top-50 floor wins over 90d), got %d", total)
	}
}

func TestCleanupConfigRevisions_FewerThan50_LeavesAllWithin90Days(t *testing.T) {
	// Scenario: only 10 revisions exist, all within the last 24 hours. Cleanup
	// must not delete anything (top-50 floor not reached, 90d not exceeded).
	h, _, device := setupFortiGateProbeDevice(t)
	seedRevisions(t, h, device.ID, 10, 1*time.Hour, []string{"a", "b", "c"})

	if err := h.db.CleanupConfigRevisions(); err != nil {
		t.Fatalf("CleanupConfigRevisions: %v", err)
	}

	var total int64
	h.db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&total)
	if total != 10 {
		t.Errorf("expected 10 rows preserved, got %d", total)
	}
}

func TestCleanupConfigRevisions_FewerThan50_DeletesOlderThan90Days(t *testing.T) {
	// Scenario: 10 revisions exist, but 5 are older than 90 days. With <50
	// rows, the top-50 floor doesn't apply — only the 90-day rule does.
	h, _, device := setupFortiGateProbeDevice(t)
	now := time.Now()
	for i, age := range []time.Duration{
		1 * time.Hour,            // recent
		2 * time.Hour,            // recent
		3 * time.Hour,            // recent
		4 * time.Hour,            // recent
		5 * time.Hour,            // recent
		95 * 24 * time.Hour,      // older than 90d → should be deleted
		100 * 24 * time.Hour,     // older than 90d → should be deleted
		120 * 24 * time.Hour,     // older than 90d → should be deleted
		200 * 24 * time.Hour,     // older than 90d → should be deleted
		400 * 24 * time.Hour,     // older than 90d → should be deleted
	} {
		rev := &models.DeviceConfigRevision{
			DeviceID:           device.ID,
			Timestamp:          now.Add(-age),
			Checksum:           "r" + strconv.Itoa(i),
			NormalizedChecksum: "n" + strconv.Itoa(i),
			ConfigText:         "c",
			Length:             1,
		}
		if err := h.db.Gorm().Create(rev).Error; err != nil {
			t.Fatalf("create rev %d: %v", i, err)
		}
	}

	if err := h.db.CleanupConfigRevisions(); err != nil {
		t.Fatalf("CleanupConfigRevisions: %v", err)
	}

	var total int64
	h.db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&total)
	if total != 5 {
		t.Errorf("expected 5 rows after 90d-rule cleanup (recent only), got %d", total)
	}
}

func TestCleanupConfigRevisions_CollapseKeepsLatestPerHashRun(t *testing.T) {
	// Build a precise scenario: 60 rows total. Top 50 (newest) all unique
	// hashes ("u0".."u49"). Rows 51-60 (oldest) cycle through hashes
	// "x", "y", "x", "y", "x", "y", "x", "y", "x", "y". After the collapse
	// pass, rows 51-60 should reduce to 2 rows: the most-recent "x" and
	// most-recent "y". Top 50 remain untouched.
	//
	// Spacing rows over 12 hours each — 60 rows = 30 days, well under 90d
	// floor, so only the top-50 + collapse path runs.
	h, _, device := setupFortiGateProbeDevice(t)
	now := time.Now()
	for i := 0; i < 60; i++ {
		ts := now.Add(-time.Duration(i) * 12 * time.Hour)
		var cs string
		if i < 50 {
			cs = "u" + strconv.Itoa(i)
		} else if i%2 == 0 {
			cs = "x"
		} else {
			cs = "y"
		}
		rev := &models.DeviceConfigRevision{
			DeviceID:           device.ID,
			Timestamp:          ts,
			Checksum:           "r" + strconv.Itoa(i),
			NormalizedChecksum: cs,
			ConfigText:         "c",
			Length:             1,
		}
		if err := h.db.Gorm().Create(rev).Error; err != nil {
			t.Fatalf("create rev %d: %v", i, err)
		}
	}

	if err := h.db.CleanupConfigRevisions(); err != nil {
		t.Fatalf("CleanupConfigRevisions: %v", err)
	}

	var total int64
	h.db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&total)
	// 50 (top) + 2 (one each for "x" and "y" collapse) = 52
	if total != 52 {
		t.Errorf("expected 52 rows after collapse (top-50 + 1-per-hash older), got %d", total)
	}

	// The surviving older-window rows must be the MOST RECENT of each hash run.
	// For "x", that's row index 50 (i=50, age=600h). For "y", row index 51
	// (i=51, age=612h). Verify by checksum.
	var older []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ? AND normalized_checksum IN ?", device.ID, []string{"x", "y"}).
		Order("timestamp DESC").Find(&older)
	if len(older) != 2 {
		t.Fatalf("expected exactly 2 collapse-survivor rows, got %d", len(older))
	}
	if older[0].Checksum != "r50" {
		t.Errorf("most-recent 'x' should be r50, got raw=%q", older[0].Checksum)
	}
	if older[1].Checksum != "r51" {
		t.Errorf("most-recent 'y' should be r51, got raw=%q", older[1].Checksum)
	}
}
