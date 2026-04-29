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

// New retention policy in v0.10.198+ (after the merge-into-latest storage
// model): only two rules — delete >365 days, cap at 500 distinct states per
// device. The legacy "top-50 + 90-day collapse" logic was made redundant by
// merge-into-latest (no IV-drift duplicates accumulate).

func TestCleanupConfigRevisions_DeletesBeyond365Days(t *testing.T) {
	h, _, device := setupFortiGateProbeDevice(t)
	now := time.Now()
	for i, age := range []time.Duration{
		1 * time.Hour,         // recent
		30 * 24 * time.Hour,   // recent
		180 * 24 * time.Hour,  // recent (within 365d)
		364 * 24 * time.Hour,  // recent (just under 365d)
		370 * 24 * time.Hour,  // older than 365d → delete
		500 * 24 * time.Hour,  // older than 365d → delete
		1000 * 24 * time.Hour, // older than 365d → delete
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
	if total != 4 {
		t.Errorf("expected 4 rows after 365d cleanup (rows within 365d only), got %d", total)
	}
}

func TestCleanupConfigRevisions_CapsAt500PerDevice(t *testing.T) {
	// Even within the 365-day window, no device should retain >500 distinct
	// states. (Devices that genuinely change >500 times in a year are rare,
	// but unbounded growth would let them hose the DB.)
	h, _, device := setupFortiGateProbeDevice(t)
	now := time.Now()
	// Seed 600 distinct rows over 60 days. All are within 365d, so only the
	// per-device cap should fire.
	for i := 0; i < 600; i++ {
		rev := &models.DeviceConfigRevision{
			DeviceID:           device.ID,
			Timestamp:          now.Add(-time.Duration(i) * time.Hour),
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
	if total != 500 {
		t.Errorf("expected 500 rows after per-device cap, got %d", total)
	}

	// The 500 kept rows must be the most recent 500 (smallest age values).
	var oldest models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("timestamp ASC").Limit(1).First(&oldest)
	if oldest.Checksum != "r499" {
		t.Errorf("oldest kept row should be r499 (the 500th most recent), got %q", oldest.Checksum)
	}
}

func TestCleanupConfigRevisions_UnderCapAndUnder365_PreservesEverything(t *testing.T) {
	// Common case: ~10 rows on a stable device. Nothing to delete.
	h, _, device := setupFortiGateProbeDevice(t)
	seedRevisions(t, h, device.ID, 10, 1*time.Hour, []string{"a", "b", "c"})

	if err := h.db.CleanupConfigRevisions(); err != nil {
		t.Fatalf("CleanupConfigRevisions: %v", err)
	}

	var total int64
	h.db.Gorm().Model(&models.DeviceConfigRevision{}).Where("device_id = ?", device.ID).Count(&total)
	if total != 10 {
		t.Errorf("expected all 10 rows preserved, got %d", total)
	}
}

// doDeviceQueryRequest is a routing helper for handlers that take :id and
// optional query strings (GetDeviceConfigHistory).
func doDeviceQueryRequest(t *testing.T, h func(*gin.Context), method, path, query string, deviceID uint) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.Handle(method, "/api/devices/:id"+path, h)
	url := "/api/devices/" + strconv.FormatUint(uint64(deviceID), 10) + path
	if query != "" {
		url = url + "?" + query
	}
	req := httptest.NewRequest(method, url, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

type historyResp struct {
	Success bool `json:"success"`
	Data    struct {
		Revisions     []models.DeviceConfigRevision `json:"revisions"`
		Distinct      bool                          `json:"distinct"`
		TotalAll      int                           `json:"total_all"`
		TotalDistinct int                           `json:"total_distinct"`
		TotalShown    int                           `json:"total_shown"`
	} `json:"data"`
}

// In v0.10.198+ the History endpoint just returns every stored row ordered
// by FirstSeenAt DESC (newest-first). Each row already represents one
// distinct config state thanks to merge-into-latest, so there's no
// distinct/all toggle and no client-side collapse.
func TestGetDeviceConfigHistory_ReturnsRowsNewestFirst(t *testing.T) {
	h, _, device := setupFortiGateProbeDevice(t)
	now := time.Now()
	// 4 rows with distinct hashes, oldest → newest by FirstSeenAt.
	for i, hash := range []string{"A", "B", "C", "D"} {
		rev := &models.DeviceConfigRevision{
			DeviceID:           device.ID,
			Timestamp:          now.Add(time.Duration(i) * time.Minute),
			FirstSeenAt:        now.Add(time.Duration(i) * time.Minute),
			LastVerifiedAt:     now.Add(time.Duration(i)*time.Minute + 30*time.Second),
			VerifyCount:        1,
			Checksum:           "raw-" + strconv.Itoa(i),
			NormalizedChecksum: hash,
			ConfigText:         "c" + strconv.Itoa(i),
			Length:             1,
		}
		if err := h.db.Gorm().Create(rev).Error; err != nil {
			t.Fatalf("create rev %d: %v", i, err)
		}
	}

	w := doDeviceQueryRequest(t, h.GetDeviceConfigHistory, "GET", "/config-history", "", device.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}

	var resp historyResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}

	if resp.Data.TotalAll != 4 {
		t.Errorf("total_all = %d, want 4", resp.Data.TotalAll)
	}
	if len(resp.Data.Revisions) != 4 {
		t.Fatalf("revisions = %d, want 4", len(resp.Data.Revisions))
	}

	// Newest-first by FirstSeenAt — D, C, B, A.
	wantHashes := []string{"D", "C", "B", "A"}
	for i, r := range resp.Data.Revisions {
		if r.NormalizedChecksum != wantHashes[i] {
			t.Errorf("rev %d: normalized = %q, want %q", i, r.NormalizedChecksum, wantHashes[i])
		}
	}
}

// TestCollapseLegacyConfigRevisionDuplicates exercises the one-time migration
// that runs at server startup to clean up IV-drift duplicates left behind by
// the v0.10.187 → v0.10.197 always-store era.
func TestCollapseLegacyConfigRevisionDuplicates(t *testing.T) {
	// Scenario: A → B → A → C across 20 rows (5+5+5+5). After collapse, exactly
	// 4 rows remain — the most recent of each run — with VerifyCount=5 each.
	h, _, device := setupFortiGateProbeDevice(t)
	now := time.Now()
	hashes := []string{
		"A", "A", "A", "A", "A",
		"B", "B", "B", "B", "B",
		"A", "A", "A", "A", "A",
		"C", "C", "C", "C", "C",
	}
	for i, h2 := range hashes {
		rev := &models.DeviceConfigRevision{
			DeviceID:           device.ID,
			Timestamp:          now.Add(time.Duration(i) * time.Minute),
			Checksum:           "r" + strconv.Itoa(i),
			NormalizedChecksum: h2,
			ConfigText:         "c",
			Length:             1,
		}
		if err := h.db.Gorm().Create(rev).Error; err != nil {
			t.Fatalf("create rev %d: %v", i, err)
		}
	}

	deleted, err := h.db.CollapseLegacyConfigRevisionDuplicates()
	if err != nil {
		t.Fatalf("CollapseLegacyConfigRevisionDuplicates: %v", err)
	}
	if deleted != 16 {
		t.Errorf("collapsed-deleted count = %d, want 16 (4 runs × 4 deleted-per-run)", deleted)
	}

	var revs []models.DeviceConfigRevision
	h.db.Gorm().Where("device_id = ?", device.ID).Order("timestamp ASC").Find(&revs)
	if len(revs) != 4 {
		t.Fatalf("after collapse: expected 4 rows, got %d", len(revs))
	}

	wantHashes := []string{"A", "B", "A", "C"}
	wantCSums := []string{"r4", "r9", "r14", "r19"} // last of each run
	for i, r := range revs {
		if r.NormalizedChecksum != wantHashes[i] {
			t.Errorf("row %d hash = %q, want %q", i, r.NormalizedChecksum, wantHashes[i])
		}
		if r.Checksum != wantCSums[i] {
			t.Errorf("row %d checksum = %q, want %q (most recent of run)", i, r.Checksum, wantCSums[i])
		}
		if r.VerifyCount != 5 {
			t.Errorf("row %d VerifyCount = %d, want 5", i, r.VerifyCount)
		}
	}

	// Idempotency: running the collapse again should be a no-op.
	deleted2, err := h.db.CollapseLegacyConfigRevisionDuplicates()
	if err != nil {
		t.Fatalf("second collapse failed: %v", err)
	}
	if deleted2 != 0 {
		t.Errorf("second collapse should be idempotent (deleted=0), got %d", deleted2)
	}
}

// _unused_legacy_top50_test was deleted with the old retention policy.
func _unused_legacy_top50_test(t *testing.T) {
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
