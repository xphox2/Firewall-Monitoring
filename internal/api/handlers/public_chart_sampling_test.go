package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// The public tiles read boundary samples instead of every row (v0.11.259).

type publicChartBody struct {
	Data struct {
		Timestamps []string  `json:"timestamps"`
		RxRate     []float64 `json:"rx_rate"`
		RxTotal    []float64 `json:"rx_total"`
	} `json:"data"`
}

// A year of hourly counters at a steady 8 Mbps inbound. The tile must span the
// whole year, report the true average rate between its points, send UTC
// timestamps, and never read the window without a LIMIT.
func TestGetPublicInterfaceChart_YearRangeSamplesWholeWindow(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db) // no allowlist set: all interfaces public
	// The helper seeds a zero-counter wan1 row two minutes ago; replace it with
	// the year below so the newest row is the series' own.
	if err := db.Gorm().Where(`device_id = ? AND "index" = 1`, dev.ID).Delete(&models.InterfaceStats{}).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Hour)
	const bytesPerHour = 3_600_000_000 // 8 Mbps
	rows := make([]models.InterfaceStats, 0, 8700)
	for i := 8700; i >= 1; i-- {
		ts := now.Add(-time.Duration(i)*time.Hour + 30*time.Minute) // mid-bucket, see chart_sample_test.go
		rows = append(rows, models.InterfaceStats{DeviceID: dev.ID, Index: 1, Name: "wan1", Timestamp: ts, InBytes: uint64((8700 - i) * bytesPerHour)})
	}
	if err := db.Gorm().CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatal(err)
	}

	var stmts []string
	capture := func(tx *gorm.DB) {
		if sql := tx.Statement.SQL.String(); strings.Contains(sql, "interface_stats") {
			stmts = append(stmts, sql)
		}
	}
	if err := db.Gorm().Callback().Query().After("gorm:query").Register("test:pub_q", capture); err != nil {
		t.Fatal(err)
	}
	if err := db.Gorm().Callback().Row().After("gorm:row").Register("test:pub_r", capture); err != nil {
		t.Fatal(err)
	}

	w := doPublicGet(t, h.GetPublicInterfaceChart, fmt.Sprintf("/endpoint?device_id=%d&index=1&range=8760", dev.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var b publicChartBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	n := len(b.Data.Timestamps)
	if n < 300 || n > 366 {
		t.Fatalf("%d points, want up to 365 buckets + the newest", n)
	}
	first, err1 := time.Parse(time.RFC3339, b.Data.Timestamps[0])
	last, err2 := time.Parse(time.RFC3339, b.Data.Timestamps[n-1])
	if err1 != nil || err2 != nil {
		t.Fatalf("timestamps not RFC3339 UTC: %q %q", b.Data.Timestamps[0], b.Data.Timestamps[n-1])
	}
	if !last.Equal(rows[len(rows)-1].Timestamp) {
		t.Fatalf("last point %v, want the newest row %v — a local time followed by a literal Z shifts every label", last, rows[len(rows)-1].Timestamp.UTC())
	}
	if last.Sub(first) < 8000*time.Hour {
		t.Fatalf("points span %v, want nearly the whole year", last.Sub(first))
	}
	for i := 1; i < n; i++ {
		if r := b.Data.RxRate[i]; r < 7.99 || r > 8.01 {
			t.Fatalf("rx_rate[%d] = %v Mbps, want 8 between consecutive samples", i, r)
		}
	}
	// Exactly the sampler (no allowlist is set, so the name lookup does not run);
	// an empty capture would make the loop below assert nothing.
	if len(stmts) != 1 {
		t.Fatalf("captured %d interface_stats statements, want exactly the sampler", len(stmts))
	}
	for _, s := range stmts {
		if !strings.Contains(s, "LIMIT") {
			t.Fatalf("an interface_stats statement without LIMIT — the window is read unbounded again: %s", s)
		}
	}
}

type publicStatusBody struct {
	Data []struct {
		Timestamp string `json:"timestamp"`
	} `json:"data"`
}

func seedStatusRows(t *testing.T, h *Handler, devID uint, span time.Duration, every time.Duration) {
	t.Helper()
	now := time.Now()
	var rows []models.SystemStatus
	for ts := now.Add(-span + every/2); ts.Before(now); ts = ts.Add(every) {
		rows = append(rows, models.SystemStatus{DeviceID: devID, Timestamp: ts, CPUUsage: 5})
	}
	if err := h.db.Gorm().CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatal(err)
	}
}

func statusSpan(t *testing.T, h *Handler, url string) (int, time.Duration) {
	t.Helper()
	w := doPublicGet(t, h.GetPublicStatusHistory, url)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var b publicStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Data) < 2 {
		return len(b.Data), 0
	}
	first, _ := time.Parse(time.RFC3339, b.Data[0].Timestamp)
	last, _ := time.Parse(time.RFC3339, b.Data[len(b.Data)-1].Timestamp)
	return len(b.Data), last.Sub(first)
}

// The CPU/memory tile used to read the first 2,000 rows — about 31 hours of
// production data — so a week-long range showed only its first day and a half.
func TestGetPublicStatusHistory_WeekSpansTheWeek(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)
	seedStatusRows(t, h, dev.ID, 168*time.Hour, time.Minute) // 10,080 rows
	n, span := statusSpan(t, h, fmt.Sprintf("/endpoint?device_id=%d&hours=168", dev.ID))
	if n > 181 || span < 160*time.Hour {
		t.Fatalf("%d points spanning %v, want <= 181 points across nearly the whole week", n, span)
	}
	// The newest point is within a minute of now as an absolute instant: a
	// local time followed by a literal Z would be off by the zone offset.
	w := doPublicGet(t, h.GetPublicStatusHistory, fmt.Sprintf("/endpoint?device_id=%d&hours=168", dev.ID))
	var b publicStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || len(b.Data) == 0 {
		t.Fatalf("decode: %v", err)
	}
	last, err := time.Parse(time.RFC3339, b.Data[len(b.Data)-1].Timestamp)
	if err != nil || time.Since(last) > 2*time.Minute || time.Since(last) < 0 {
		t.Fatalf("newest point %q is not the last minute in UTC (err %v)", b.Data[len(b.Data)-1].Timestamp, err)
	}
}

func TestGetPublicStatusHistory_SubHourAndDefault(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := seedPublicDeviceWithInterfaces(t, db)
	seedStatusRows(t, h, dev.ID, 48*time.Hour, time.Minute)
	if _, span := statusSpan(t, h, fmt.Sprintf("/endpoint?device_id=%d&hours=0.25", dev.ID)); span > 15*time.Minute || span < 10*time.Minute {
		t.Fatalf("hours=0.25 spans %v, want ~15 minutes (AUDIT-235)", span)
	}
	if _, span := statusSpan(t, h, fmt.Sprintf("/endpoint?device_id=%d", dev.ID)); span > 24*time.Hour || span < 23*time.Hour {
		t.Fatalf("no hours spans %v, want the 24 h default", span)
	}
}
