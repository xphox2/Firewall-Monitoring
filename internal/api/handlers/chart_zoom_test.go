package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// Drag-to-zoom (v0.11.270): the charts re-query the selected window instead of
// only stretching the points already loaded.

func statusHistoryGet(t *testing.T, h *Handler, query string) (int, map[string]json.RawMessage) {
	t.Helper()
	router := gin.New()
	router.GET("/devices/:id/status-history", h.GetDeviceStatusHistory)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/devices/1/status-history?"+query, nil))
	var body struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.Data
}

// The branch is chosen by ?from=, and the response shape shows which ran:
// bucket units cannot tell them apart (6h and the 24h fallback both use 5min).
func TestGetDeviceStatusHistory_WindowAndPresetBranches(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw", IPAddress: "192.0.2.10"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	for m := 0; m < 120; m++ {
		db.Gorm().Create(&models.SystemStatus{DeviceID: dev.ID, Timestamp: now.Add(-time.Duration(m) * time.Minute), CPUUsage: 30})
	}

	from, to := now.Add(-90*time.Minute).UnixMilli(), now.UnixMilli()
	code, data := statusHistoryGet(t, h, fmt.Sprintf("from=%d&to=%d", from, to))
	if code != http.StatusOK || data["from"] == nil || data["to"] == nil || data["range"] != nil {
		t.Fatalf("window: status %d, keys %v; want from/to echoed and no range", code, keysOf(data))
	}
	var buckets []map[string]interface{}
	_ = json.Unmarshal(data["buckets"], &buckets)
	if len(buckets) < 85 || len(buckets) > 91 {
		t.Errorf("a 90-minute window gave %d buckets, want ~90 minute buckets", len(buckets))
	}

	code, data = statusHistoryGet(t, h, "range=6h")
	if code != http.StatusOK || string(data["range"]) != `"6h"` || data["from"] != nil {
		t.Errorf("range=6h: status %d, keys %v; want the preset branch (range echoed, no from/to)", code, keysOf(data))
	}

	for _, q := range []string{"from=abc&to=1", fmt.Sprintf("from=%d&to=%d", to, from), fmt.Sprintf("from=%d", from)} {
		if code, _ := statusHistoryGet(t, h, q); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, code)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestGetPublicStatusHistory_ZoomWindow(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)
	_ = seedStatusRows(t, h, dev.ID, 48*time.Hour, time.Minute)
	now := time.Now()

	// A 2-hour window a day ago is served, sampled inside it.
	from, to := now.Add(-26*time.Hour), now.Add(-24*time.Hour)
	w := doPublicGet(t, h.GetPublicStatusHistory, fmt.Sprintf("/endpoint?device_id=%d&hours=48&from=%d&to=%d", dev.ID, from.UnixMilli(), to.UnixMilli()))
	var b publicStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || w.Code != 200 || len(b.Data) < 100 {
		t.Fatalf("status %d, %d points (err %v); want the 2 h window at up to %d points", w.Code, len(b.Data), err, publicZoomMaxPoints)
	}
	first, _ := time.Parse(time.RFC3339, b.Data[0].Timestamp)
	last, _ := time.Parse(time.RFC3339, b.Data[len(b.Data)-1].Timestamp)
	if first.Before(from.Add(-time.Second)) || last.After(to.Add(time.Second)) {
		t.Errorf("points span %v..%v, want inside %v..%v", first, last, from, to)
	}

	// Junk falls back to the preset (the public page stays lenient).
	if _, span := statusSpan(t, h, fmt.Sprintf("/endpoint?device_id=%d&hours=24&from=x&to=y", dev.ID)); span < 23*time.Hour {
		t.Errorf("junk from/to spanned %v, want the 24 h preset", span)
	}
	// A window entirely in the future is empty after clamping to now.
	fut := now.Add(time.Hour)
	if w := doPublicGet(t, h.GetPublicStatusHistory, fmt.Sprintf("/endpoint?device_id=%d&from=%d&to=%d", dev.ID, fut.UnixMilli(), fut.Add(time.Hour).UnixMilli())); w.Code != http.StatusBadRequest {
		t.Errorf("future window: status %d, want 400", w.Code)
	}
}

func TestPublicZoomWindow_ClampsAndWidens(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	get := func(from, to time.Time) (time.Time, time.Time, bool, error) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", fmt.Sprintf("/x?from=%d&to=%d", from.UnixMilli(), to.UnixMilli()), nil)
		return publicZoomWindow(c, now)
	}
	// Older than the 1-year cap: clamped, not refused.
	f, to, ok, err := get(now.Add(-9000*time.Hour), now.Add(-8000*time.Hour))
	if !ok || err != nil || !f.Equal(now.Add(-maxPublicChartRangeHours*time.Hour)) || !to.Equal(now.Add(-8000*time.Hour)) {
		t.Errorf("past the cap: %v..%v ok=%v err=%v, want from clamped to the cap", f, to, ok, err)
	}
	// Ending in the future: to clamped to now FIRST, then a short window widened backwards.
	f, to, ok, err = get(now.Add(-time.Minute), now.Add(time.Hour))
	if !ok || err != nil || !to.Equal(now) || !f.Equal(now.Add(-publicZoomMinWindow)) {
		t.Errorf("short, future-ending window: %v..%v, want %v..%v", f, to, now.Add(-publicZoomMinWindow), now)
	}
	// A normal window passes through.
	f, to, ok, _ = get(now.Add(-3*time.Hour), now.Add(-time.Hour))
	if !ok || !f.Equal(now.Add(-3*time.Hour)) || !to.Equal(now.Add(-time.Hour)) {
		t.Errorf("normal window changed: %v..%v", f, to)
	}
}

func TestPublicLabelFormat_BySpan(t *testing.T) {
	for span, want := range map[time.Duration]string{
		30 * time.Minute:    "15:04:05",
		6 * time.Hour:       "15:04",
		10 * 24 * time.Hour: "01-02 15:00",
		90 * 24 * time.Hour: "01-02",
	} {
		if got := publicLabelFormat(span); got != want {
			t.Errorf("span %v: %q, want %q", span, got, want)
		}
	}
}

func TestGetPublicInterfaceChart_ZoomWindowUsesSpanLabels(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)
	now := time.Now()
	for m := 0; m < 180; m++ {
		ts := now.Add(-time.Duration(180-m) * time.Minute)
		db.Gorm().Create(&models.InterfaceStats{DeviceID: dev.ID, Index: 1, Name: "wan1", Status: "up", Timestamp: ts, InBytes: uint64(m) * 1000, OutBytes: uint64(m) * 500})
	}
	from, to := now.Add(-40*time.Minute), now.Add(-10*time.Minute)
	w := doPublicGet(t, h.GetPublicInterfaceChart, fmt.Sprintf("/endpoint?device_id=%d&index=1&range=720&from=%d&to=%d", dev.ID, from.UnixMilli(), to.UnixMilli()))
	var body struct {
		Data struct {
			Labels     []string `json:"labels"`
			Timestamps []string `json:"timestamps"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || len(body.Data.Labels) < 10 {
		t.Fatalf("status %d, %d labels (err %v)", w.Code, len(body.Data.Labels), err)
	}
	if len(body.Data.Labels[0]) != len("15:04:05") {
		t.Errorf("a 30-minute zoom label %q, want seconds (15:04:05)", body.Data.Labels[0])
	}
	first, _ := time.Parse(time.RFC3339, body.Data.Timestamps[0])
	if first.Before(from.Add(-time.Second)) {
		t.Errorf("first point %v is before the window %v", first, from)
	}
}

// A 10-day zoom labels by date and hour; the preset rule (keyed on the range
// string, here the numeric 720) would label it 15:04.
func TestGetPublicInterfaceChart_LongZoomLabelsByDate(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)
	now := time.Now()
	for d := 0; d < 12; d++ {
		ts := now.Add(-time.Duration(12-d) * 24 * time.Hour)
		db.Gorm().Create(&models.InterfaceStats{DeviceID: dev.ID, Index: 1, Name: "wan1", Status: "up", Timestamp: ts, InBytes: uint64(d) * 1000})
	}
	from, to := now.Add(-11*24*time.Hour), now.Add(-time.Hour)
	w := doPublicGet(t, h.GetPublicInterfaceChart, fmt.Sprintf("/endpoint?device_id=%d&index=1&range=720&from=%d&to=%d", dev.ID, from.UnixMilli(), to.UnixMilli()))
	var body struct {
		Data struct {
			Labels []string `json:"labels"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Data.Labels) == 0 {
		t.Fatalf("status %d (err %v): %s", w.Code, err, w.Body.String())
	}
	if len(body.Data.Labels[0]) != len("01-02 15:00") {
		t.Errorf("a 10-day zoom label %q, want date + hour (01-02 15:00)", body.Data.Labels[0])
	}
}
