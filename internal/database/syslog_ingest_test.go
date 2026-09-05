package database

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The ingest meter is the only producer of syslog_ingest_hourly, and the
// Retention page's rate and projection rest entirely on it being exact. These
// pin the accounting: every row that landed is counted once, in the hour it
// arrived, whatever a concurrent flush or a failed one is doing.

func ingestTestDB(t *testing.T, at time.Time) (*Database, *time.Time) {
	t.Helper()
	d := NewDatabaseForTesting(t)
	clock := at
	d.ingest.now = func() time.Time { return clock }
	// Start the flush interval at the injected clock so no save flushes on
	// its own; each test flushes explicitly (or advances the clock).
	d.ingest.lastFlush = at
	return d, &clock
}

func ingestMsgs(sev int, n int, body string) []models.SyslogMessage {
	out := make([]models.SyslogMessage, n)
	for i := range out {
		out[i] = models.SyslogMessage{Timestamp: time.Now(), Severity: sev, Message: body, Hostname: "fw"}
	}
	return out
}

func readIngestRows(t *testing.T, d *Database) map[string]models.SyslogIngestHourly {
	t.Helper()
	var rows []models.SyslogIngestHourly
	if err := d.db.Order("timestamp, severity").Find(&rows).Error; err != nil {
		t.Fatalf("read syslog_ingest_hourly: %v", err)
	}
	out := make(map[string]models.SyslogIngestHourly, len(rows))
	for _, r := range rows {
		out[fmt.Sprintf("%s/%d", r.Timestamp.UTC().Format("15"), r.Severity)] = r
	}
	return out
}

func TestSyslogIngest_CountsRowsAndBytesPerSeverity(t *testing.T) {
	at := time.Date(2026, 9, 5, 10, 20, 0, 0, time.UTC)
	d, _ := ingestTestDB(t, at)

	msgs := append(ingestMsgs(5, 3, "abcd"), ingestMsgs(3, 2, "xyzxyz")...)
	if err := d.SaveSyslogMessages(msgs); err != nil {
		t.Fatalf("SaveSyslogMessages: %v", err)
	}
	if err := d.flushSyslogIngest(true); err != nil {
		t.Fatalf("flush: %v", err)
	}

	rows := readIngestRows(t, d)
	if got := rows["10/5"]; got.RowCount != 3 || got.ByteCount != 3*(4+2) {
		t.Errorf("severity 5 = %+v, want 3 rows, %d bytes (message+hostname)", got, 3*(4+2))
	}
	if got := rows["10/3"]; got.RowCount != 2 || got.ByteCount != 2*(6+2) {
		t.Errorf("severity 3 = %+v, want 2 rows, %d bytes", got, 2*(6+2))
	}
	if len(rows) != 2 {
		t.Errorf("wrote %d rows, want 2 (only non-zero cells)", len(rows))
	}
}

// A batch that partially fails counts only the rows that landed: the fallback
// drops the unsalvageable ones and still returns nil.
func TestSyslogIngest_PartialBatchCountsOnlySavedRows(t *testing.T) {
	at := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	d, _ := ingestTestDB(t, at)

	// Occupy primary key 5 so a batch carrying ID 5 fails as a statement and
	// falls back per row, where only the ID-6 row can succeed.
	if err := d.db.Create(&models.SyslogMessage{ID: 5, Severity: 5, Message: "pre"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	batch := []models.SyslogMessage{
		{ID: 5, Severity: 5, Message: "dup"},
		{ID: 6, Severity: 5, Message: "ok"},
	}
	if err := d.SaveSyslogMessages(batch); err != nil {
		t.Fatalf("SaveSyslogMessages returned %v; a partial failure must not be an error", err)
	}
	if err := d.flushSyslogIngest(true); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got := readIngestRows(t, d)["10/5"]
	if got.RowCount != 1 || got.ByteCount != 2 {
		t.Errorf("counted %d rows / %d bytes, want 1 / 2 — only the row that landed", got.RowCount, got.ByteCount)
	}
}

// Two flushes inside one hour accumulate into ONE row (ON CONFLICT adds), and
// rows counted in two different hours land in two rows.
func TestSyslogIngest_FlushesAccumulateWithinTheHourAndSplitAcrossHours(t *testing.T) {
	at := time.Date(2026, 9, 5, 10, 5, 0, 0, time.UTC)
	d, clock := ingestTestDB(t, at)

	save := func(n int) {
		t.Helper()
		if err := d.SaveSyslogMessages(ingestMsgs(6, n, "m")); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	save(4)
	if err := d.flushSyslogIngest(false); err != nil {
		t.Fatalf("flush 1: %v", err)
	}
	*clock = at.Add(20 * time.Minute)
	save(6)
	if err := d.flushSyslogIngest(true); err != nil {
		t.Fatalf("flush 2: %v", err)
	}
	*clock = at.Add(70 * time.Minute) // 11:15
	save(1)
	if err := d.flushSyslogIngest(true); err != nil {
		t.Fatalf("flush 3: %v", err)
	}

	rows := readIngestRows(t, d)
	if got := rows["10/6"]; got.RowCount != 10 {
		t.Errorf("hour 10 = %d rows, want 10 (two flushes must add into one row)", got.RowCount)
	}
	if got := rows["11/6"]; got.RowCount != 1 {
		t.Errorf("hour 11 = %d rows, want 1", got.RowCount)
	}
	if len(rows) != 2 {
		t.Errorf("%d rows, want exactly 2", len(rows))
	}
}

// A failed flush merges its counts back — additively, so rows that arrived
// during the failed flush are kept — and the next flush lands the exact total.
func TestSyslogIngest_FailedFlushMergesBackThenLandsExactTotal(t *testing.T) {
	at := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	d, _ := ingestTestDB(t, at)

	if err := d.SaveSyslogMessages(ingestMsgs(5, 7, "m")); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := d.db.Migrator().DropTable(&models.SyslogIngestHourly{}); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := d.flushSyslogIngest(false); err == nil {
		t.Fatal("flush against a dropped table succeeded; the test cannot exercise merge-back")
	}
	// Counts that arrive after the failure, in the same hour, must survive too.
	if err := d.SaveSyslogMessages(ingestMsgs(5, 3, "m")); err != nil {
		t.Fatalf("save after failure: %v", err)
	}
	if err := d.db.AutoMigrate(&models.SyslogIngestHourly{}); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if err := d.flushSyslogIngest(true); err != nil {
		t.Fatalf("flush after recreate: %v", err)
	}
	if got := readIngestRows(t, d)["10/5"]; got.RowCount != 10 || got.ByteCount != 10*3 {
		t.Errorf("landed %d rows / %d bytes after a failed flush, want 10 / 30 — nothing lost, nothing doubled",
			got.RowCount, got.ByteCount)
	}
}

// Concurrent ingest from many goroutines totals exactly. Run with -race: the
// meter's lock discipline (never held across the flush round-trip) is the
// property under test.
func TestSyslogIngest_ConcurrentSavesTotalExactly(t *testing.T) {
	d := NewDatabaseForTesting(t)
	// Every :memory: connection is its own database; pin the pool to one so
	// concurrent goroutines share the table they migrated.
	sqlDB, err := d.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)

	const workers, perWorker, batch = 8, 20, 5
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if err := d.SaveSyslogMessages(ingestMsgs(5, batch, "m")); err != nil {
					t.Errorf("save: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	if err := d.flushSyslogIngest(true); err != nil {
		t.Fatalf("final flush: %v", err)
	}

	var total int64
	if err := d.db.Raw(`SELECT COALESCE(SUM(row_count), 0) FROM syslog_ingest_hourly WHERE severity = 5`).
		Scan(&total).Error; err != nil {
		t.Fatal(err)
	}
	if want := int64(workers * perWorker * batch); total != want {
		t.Errorf("landed %d rows, want %d", total, want)
	}
}

func TestSyslogIngest_OutOfRangeSeverityLandsInBucket7(t *testing.T) {
	at := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	d, _ := ingestTestDB(t, at)

	msgs := []models.SyslogMessage{{Severity: 9, Message: "m"}, {Severity: -1, Message: "m"}}
	if err := d.SaveSyslogMessages(msgs); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := d.flushSyslogIngest(true); err != nil {
		t.Fatalf("flush: %v", err)
	}
	rows := readIngestRows(t, d)
	if got := rows["10/7"]; got.RowCount != 2 {
		t.Errorf("bucket 7 = %d rows, want 2 (out-of-range severities are clamped, never dropped)", got.RowCount)
	}
	if len(rows) != 1 {
		t.Errorf("%d rows written, want 1", len(rows))
	}
}

// Before a full day of buckets exists the rate is extrapolated from what there
// is, and the caller is told how many hours that was.
func TestSyslogIngestRate_ExtrapolatesFromPartialWindow(t *testing.T) {
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	d, _ := ingestTestDB(t, at)

	seed := []models.SyslogIngestHourly{
		{Timestamp: at.Add(-3 * time.Hour), Severity: 5, RowCount: 100, ByteCount: 10000},
		{Timestamp: at.Add(-2 * time.Hour), Severity: 5, RowCount: 200, ByteCount: 20000},
		{Timestamp: at.Add(-1 * time.Hour), Severity: 4, RowCount: 30, ByteCount: 900},
	}
	if err := d.db.Create(&seed).Error; err != nil {
		t.Fatal(err)
	}

	per, hours := d.SyslogIngestRate(at)
	if hours != 3 {
		t.Errorf("hours = %v, want 3 (oldest bucket is 3 h old)", hours)
	}
	if per[5].Rows != 300 || per[5].Bytes != 30000 {
		t.Errorf("severity 5 = %+v, want 300 rows / 30000 bytes", per[5])
	}
	if per[4].Rows != 30 {
		t.Errorf("severity 4 = %+v, want 30 rows", per[4])
	}
}

// Buckets older than the window are excluded from the sum but still make the
// window a full 24 h — a quiet day is a real zero, not an unknown.
func TestSyslogIngestRate_FullWindowIgnoresOlderBuckets(t *testing.T) {
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	d, _ := ingestTestDB(t, at)

	seed := []models.SyslogIngestHourly{
		{Timestamp: at.Add(-30 * time.Hour), Severity: 5, RowCount: 999},
		{Timestamp: at.Add(-5 * time.Hour), Severity: 5, RowCount: 10},
	}
	if err := d.db.Create(&seed).Error; err != nil {
		t.Fatal(err)
	}
	per, hours := d.SyslogIngestRate(at)
	if hours != 24 {
		t.Errorf("hours = %v, want 24", hours)
	}
	if per[5].Rows != 10 {
		t.Errorf("severity 5 = %d rows, want 10 (the 30 h-old bucket is outside the window)", per[5].Rows)
	}
}

func TestSyslogIngestRate_EmptyTableIsUnavailable(t *testing.T) {
	d := NewDatabaseForTesting(t)
	per, hours := d.SyslogIngestRate(time.Now())
	if hours != 0 {
		t.Errorf("hours = %v on an empty table, want 0 (rate unavailable, not a zero rate)", hours)
	}
	for sev, p := range per {
		if p.Rows != 0 || p.Bytes != 0 {
			t.Errorf("severity %d = %+v on an empty table", sev, p)
		}
	}
}

// A Database literal has no meter (a handful of tests build one); the meter
// paths must be no-ops, not nil dereferences.
func TestSyslogIngest_NilMeterIsNoOp(t *testing.T) {
	d := &Database{}
	d.meterSyslog(ingestMsgs(5, 1, "m"))
	if err := d.flushSyslogIngest(true); err != nil {
		t.Errorf("flush on a nil meter = %v, want nil", err)
	}
}
