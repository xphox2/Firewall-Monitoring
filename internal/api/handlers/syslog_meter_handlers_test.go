package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

func seedRawSyslog(t *testing.T, db *database.Database, n int) {
	t.Helper()
	rows := make([]models.SyslogMessage, n)
	for i := range rows {
		rows[i] = models.SyslogMessage{Timestamp: time.Now().Add(-time.Minute), Severity: 5, Message: "m"}
	}
	if err := db.Gorm().CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatalf("seed syslog: %v", err)
	}
}

func syslogListTotal(t *testing.T, h *Handler) (int64, bool) {
	t.Helper()
	c, rec := jsonReq(http.MethodGet, "/x?hours=24", "")
	h.GetSyslogMessages(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetSyslogMessages = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Total       int64 `json:"total"`
			TotalCapped bool  `json:"total_capped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data.Total, body.Data.TotalCapped
}

// The pager's exact COUNT over 24 h read ~4.7M index entries on production.
// It now stops one past the cap — which only works as a real subquery: GORM's
// Count on a query carrying a Limit still counts every row.
func TestGetSyslogMessages_PagerCountIsCapped(t *testing.T) {
	h, db := setupTestHandler(t)
	seedRawSyslog(t, db, 12)
	if total, capped := syslogListTotal(t, h); total != 12 || capped {
		t.Fatalf("12 rows: total=%d capped=%v, want exact 12", total, capped)
	}
	seedRawSyslog(t, db, syslogPagerCountCap)

	// The result alone cannot tell the capped count from a full count that is
	// clamped afterwards — both read 10,000 — so also check the statement: the
	// count must run over a LIMITed subquery.
	var mu sync.Mutex
	var counts []string
	if err := db.Gorm().Callback().Query().After("gorm:query").Register("test:capture_count", func(tx *gorm.DB) {
		if sql := tx.Statement.SQL.String(); strings.Contains(strings.ToLower(sql), "count(") {
			mu.Lock()
			counts = append(counts, sql)
			mu.Unlock()
		}
	}); err != nil {
		t.Fatal(err)
	}
	if total, capped := syslogListTotal(t, h); total != syslogPagerCountCap || !capped {
		t.Fatalf("%d rows: total=%d capped=%v, want %d and capped", syslogPagerCountCap+12, total, capped, syslogPagerCountCap)
	}
	if len(counts) != 1 || !strings.Contains(counts[0], "LIMIT") || !strings.Contains(counts[0], "AS t") {
		t.Fatalf("count statements = %q, want one count over a LIMITed subquery", counts)
	}
}

// The vitals rail's 24 h syslog figure is the meter's, like the Syslog page's
// cards — not a raw COUNT once a minute.
func TestComputeDashboardSummary_Syslog24hFromMeter(t *testing.T) {
	h, db := setupTestHandler(t)
	seedRawSyslog(t, db, 3) // disagrees with the meter on purpose
	if err := db.Gorm().Create(&models.SyslogIngestHourly{
		Timestamp: time.Now().UTC().Truncate(time.Hour), Severity: 5, RowCount: 50,
	}).Error; err != nil {
		t.Fatal(err)
	}
	cs := &computeStatus{}
	out := h.computeDashboardSummary(cs)
	if got := out["syslog_24h"]; got != int64(50) {
		t.Fatalf("syslog_24h = %v, want 50 from the meter", got)
	}
	if cs.partial() {
		t.Fatalf("partial with blocks %v", cs.failed)
	}
}

func TestComputeDashboardSummary_EmptyMeterIsZeroNotPartial(t *testing.T) {
	h, _ := setupTestHandler(t)
	cs := &computeStatus{}
	if got := h.computeDashboardSummary(cs)["syslog_24h"]; got != int64(0) || cs.partial() {
		t.Fatalf("syslog_24h=%v partial=%v failed=%v, want 0 and not partial", got, cs.partial(), cs.failed)
	}
}

func TestComputeDashboardSummary_MeterFailureMarksPartial(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().Exec("DROP TABLE syslog_ingest_hourly").Error; err != nil {
		t.Fatal(err)
	}
	cs := &computeStatus{}
	h.computeDashboardSummary(cs)
	found := false
	for _, f := range cs.failed {
		found = found || f == "summary syslog 24h"
	}
	if !found {
		t.Fatalf("failed blocks = %v, want \"summary syslog 24h\" so the rail shows degraded, not a confident 0", cs.failed)
	}
}
