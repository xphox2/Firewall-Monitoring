package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The dirty-bucket scan is issued in fixed-width id pieces. These tests pin
// that shape, because the defect it replaced cannot be reproduced by a small
// fixture: as ONE statement over (watermark, ceiling] the scan timed out once
// on production (2026-10-25), could never advance the watermark afterwards,
// and stalled the hourly tier for a month.
//
// Every fixture here holds 5m rows only, so the daily tier owns nothing and
// returns before it scans; the hooks filter on "1h" all the same.

type dirtyChunk struct{ lo, hi int64 }

// useDirtyScanChunk sets the piece width for one test.
func useDirtyScanChunk(t *testing.T, n int64) {
	t.Helper()
	orig := flowSummaryDirtyScanChunk
	flowSummaryDirtyScanChunk = n
	t.Cleanup(func() {
		flowSummaryDirtyScanChunk = orig
		flowSummaryDirtyChunkHook = nil
		flowSummaryBucketHook = nil
	})
}

func maxRollupID(t *testing.T, d *Database) int64 {
	t.Helper()
	var id int64
	if err := d.Gorm().Model(&models.FlowRollup{}).Select("COALESCE(MAX(id),0)").Scan(&id).Error; err != nil {
		t.Fatalf("max rollup id: %v", err)
	}
	return id
}

// builtSummary seeds one row in each of `hours` hourly buckets and runs the
// summariser until the hourly tier is caught up, so the next pass is purely a
// dirty walk. It returns the first bucket and the watermark the build left.
func builtSummary(t *testing.T, d *Database, hours int) (base time.Time, watermark int64) {
	t.Helper()
	base = time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Hour)
	for h := 0; h < hours; h++ {
		seedSummaryHour(t, d, base, h, 100, "10.0.0.1")
	}
	for i := 0; i < 5; i++ {
		d.RunFlowSummaryCycle()
	}
	if !d.summaryBackfillComplete() {
		t.Fatal("precondition: the summary did not finish building")
	}
	watermark = d.summaryWatermark("1h")
	if watermark != maxRollupID(t, d) {
		t.Fatalf("precondition: watermark %d is not the newest id %d", watermark, maxRollupID(t, d))
	}
	return base, watermark
}

func assertBucketsAgree(t *testing.T, d *Database, base time.Time, hours int, when string) {
	t.Helper()
	for h := 0; h < hours; h++ {
		if want, got := summaryBucketBytes(d, base.Add(time.Duration(h)*time.Hour)); got != want {
			t.Fatalf("%s: bucket %d holds %d bytes against %d in the source", when, h, got, want)
		}
	}
}

// TestFlowSummary_DirtyScanIsChunked: the scan covers (watermark, ceiling]
// exactly, in pieces no wider than the chunk, and still finds every bucket.
//
// ONE new row per bucket with consecutive ids: a piece boundary then falls on
// a row that is the only evidence of its bucket, so an off-by-one bound loses
// that bucket visibly. The rows go in newest-hour first, so id order is the
// reverse of time order and the walk is oldest-first only if the list is
// sorted.
func TestFlowSummary_DirtyScanIsChunked(t *testing.T) {
	d := NewDatabaseForTesting(t)
	const hours = 20
	base, watermark := builtSummary(t, d, hours)
	useDirtyScanChunk(t, 3)

	for h := hours - 1; h >= 0; h-- {
		seedSummaryHour(t, d, base, h, 5000, "10.0.0.9")
	}
	ceiling := maxRollupID(t, d)

	var chunks []dirtyChunk
	flowSummaryDirtyChunkHook = func(iv string, lo, hi int64) error {
		if iv == "1h" {
			chunks = append(chunks, dirtyChunk{lo, hi})
		}
		return nil
	}
	var walked []time.Time
	flowSummaryBucketHook = func(iv string, b time.Time) error {
		if iv == "1h" {
			walked = append(walked, b)
		}
		return nil
	}
	d.RunFlowSummaryCycle() // ONE pass
	flowSummaryDirtyChunkHook, flowSummaryBucketHook = nil, nil

	assertBucketsAgree(t, d, base, hours, "after one pass")

	if len(chunks) != 7 {
		t.Fatalf("20 ids in pieces of 3 is 7 statements; the scan issued %d: %v", len(chunks), chunks)
	}
	if chunks[0].lo != watermark {
		t.Errorf("the scan started at id %d, not at the watermark %d", chunks[0].lo, watermark)
	}
	if last := chunks[len(chunks)-1].hi; last != ceiling {
		t.Errorf("the scan ended at id %d, not at the ceiling %d", last, ceiling)
	}
	for i, c := range chunks {
		if w := c.hi - c.lo; w <= 0 || w > 3 {
			t.Errorf("statement %d covers ids (%d, %d]: %d wide against a chunk of 3. A statement "+
				"whose range grows with the backlog is the defect.", i, c.lo, c.hi, w)
		}
		if i > 0 && c.lo != chunks[i-1].hi {
			t.Errorf("statement %d starts at %d but the previous one ended at %d: ids between "+
				"them were never scanned", i, c.lo, chunks[i-1].hi)
		}
	}

	// The tier was caught up and the new rows add no bucket, so the backfill
	// walks nothing: every call is the dirty walk's.
	if len(walked) != hours {
		t.Fatalf("the dirty walk ran %d buckets, want %d", len(walked), hours)
	}
	for i := 1; i < len(walked); i++ {
		if !walked[i].After(walked[i-1]) {
			t.Fatalf("the dirty walk is not oldest-first at position %d (%s then %s); the pieces "+
				"arrive in id order and the merged list must be sorted",
				i, walked[i-1].Format(time.RFC3339), walked[i].Format(time.RFC3339))
		}
	}
}

// TestFlowSummary_DirtyScanRecomputesEachBucketOnce: an hour's rows carry
// several distinct stamps and are spread over many pieces. Deduplicating per
// piece, or on the raw stamp, recomputes the bucket once per stamp — in a
// production walk that is up to thirteen times a bucket with no time bound.
func TestFlowSummary_DirtyScanRecomputesEachBucketOnce(t *testing.T) {
	d := NewDatabaseForTesting(t)
	const hours = 4
	base, _ := builtSummary(t, d, hours)
	useDirtyScanChunk(t, 1)

	// seedSummaryHour always stamps +5m, so the distinct stamps are local.
	for _, offset := range []time.Duration{5 * time.Minute, 20 * time.Minute, 35 * time.Minute} {
		for h := 0; h < hours; h++ {
			if err := d.Gorm().Create(&models.FlowRollup{
				Timestamp: base.Add(time.Duration(h)*time.Hour + offset),
				DeviceID:  1, IntervalType: "5m",
				SrcAddr: "10.0.0.9", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
				BytesSum: 5000, PacketsSum: 1, FlowCount: 1,
			}).Error; err != nil {
				t.Fatalf("seed hour %d +%s: %v", h, offset, err)
			}
		}
	}

	runs := map[time.Time]int{}
	flowSummaryBucketHook = func(iv string, b time.Time) error {
		if iv == "1h" {
			runs[b]++
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	flowSummaryBucketHook = nil

	for h := 0; h < hours; h++ {
		b := base.Add(time.Duration(h) * time.Hour)
		if runs[b] != 1 {
			t.Errorf("bucket %d was recomputed %d times in one pass, want exactly 1", h, runs[b])
		}
	}
	assertBucketsAgree(t, d, base, hours, "after one pass")
}

// TestFlowSummary_DirtyScanChunkBounds covers the loop's two edges.
func TestFlowSummary_DirtyScanChunkBounds(t *testing.T) {
	t.Run("a zero chunk means the default, not an endless loop", func(t *testing.T) {
		d := NewDatabaseForTesting(t)
		base, watermark := builtSummary(t, d, 4)
		useDirtyScanChunk(t, 0)
		for h := 0; h < 4; h++ {
			seedSummaryHour(t, d, base, h, 5000, "10.0.0.9")
		}
		ceiling := maxRollupID(t, d)

		var chunks []dirtyChunk
		flowSummaryDirtyChunkHook = func(iv string, lo, hi int64) error {
			if iv != "1h" {
				return nil
			}
			chunks = append(chunks, dirtyChunk{lo, hi})
			if len(chunks) > 1000 {
				return fmt.Errorf("the scan is not advancing")
			}
			return nil
		}
		d.RunFlowSummaryCycle()
		flowSummaryDirtyChunkHook = nil

		if len(chunks) != 1 || chunks[0] != (dirtyChunk{watermark, ceiling}) {
			t.Fatalf("with the chunk unset, 4 new ids must be one statement over (%d, %d]; got %v",
				watermark, ceiling, chunks)
		}
		assertBucketsAgree(t, d, base, 4, "after one pass")
	})

	t.Run("a watermark above the ceiling scans nothing", func(t *testing.T) {
		d := NewDatabaseForTesting(t)
		_, watermark := builtSummary(t, d, 4)
		useDirtyScanChunk(t, 3)
		d.setSummaryWatermark("1h", watermark+100)

		calls := 0
		flowSummaryDirtyChunkHook = func(iv string, lo, hi int64) error {
			if iv == "1h" {
				calls++
			}
			return nil
		}
		d.RunFlowSummaryCycle()
		flowSummaryDirtyChunkHook = nil

		if calls != 0 {
			t.Errorf("a watermark above every id issued %d scan statement(s), want none", calls)
		}
		if got := d.summaryWatermark("1h"); got != watermark {
			t.Errorf("the watermark is %d after the pass, want the ceiling %d", got, watermark)
		}
	})
}

// TestFlowSummary_DirtyChunkErrorHoldsTheWatermark: one piece failing fails
// the scan. Carrying on with the pieces that did succeed would hand the walk a
// short list, and the watermark would then pass ids nobody looked at.
func TestFlowSummary_DirtyChunkErrorHoldsTheWatermark(t *testing.T) {
	d := NewDatabaseForTesting(t)
	const hours = 20
	base, watermark := builtSummary(t, d, hours)
	useDirtyScanChunk(t, 3)
	for h := 0; h < hours; h++ {
		seedSummaryHour(t, d, base, h, 5000, "10.0.0.9")
	}

	n, failed := 0, false
	flowSummaryDirtyChunkHook = func(iv string, lo, hi int64) error {
		if iv != "1h" {
			return nil
		}
		if n++; n == 4 && !failed {
			failed = true
			return fmt.Errorf("synthetic statement timeout on ids %d-%d", lo, hi)
		}
		return nil
	}
	walked := 0
	flowSummaryBucketHook = func(iv string, b time.Time) error {
		if iv == "1h" {
			walked++
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	flowSummaryBucketHook = nil

	if !failed {
		t.Fatal("precondition: the fourth statement was never issued")
	}
	if got := d.summaryWatermark("1h"); got != watermark {
		t.Errorf("the watermark moved from %d to %d on a pass whose scan failed part-way", watermark, got)
	}
	if walked != 0 {
		t.Errorf("%d bucket(s) were recomputed from a scan that failed part-way; a partial list "+
			"must not reach the walk", walked)
	}

	d.RunFlowSummaryCycle()
	assertBucketsAgree(t, d, base, hours, "on the pass after the failure")
}

// TestFlowSummary_DirtyChunkQueryErrorIsReturned pins the path a real
// statement timeout takes: the error comes from the query, not from a hook. A
// helper that swallowed it would report "no rows" for ids it never read.
func TestFlowSummary_DirtyChunkQueryErrorIsReturned(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Hour)
	seedSummaryHour(t, d, base, 0, 100, "10.0.0.1")

	if stamps, err := dirtyChunkStamps(d.Gorm(), []string{"5m"}, 0, 10); err != nil || len(stamps) != 1 {
		t.Fatalf("precondition: a healthy query returned %d stamp(s), err %v", len(stamps), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if stamps, err := dirtyChunkStamps(d.Gorm().WithContext(ctx), []string{"5m"}, 0, 10); err == nil {
		t.Errorf("a cancelled query returned %d stamp(s) and no error", len(stamps))
	}
}

// TestFlowSummary_DirtyScanChunkDefaultIsBounded: every other test sets its
// own chunk, so raising the default would pass them all and put production
// back on statements sized by the backlog.
func TestFlowSummary_DirtyScanChunkDefaultIsBounded(t *testing.T) {
	if flowSummaryDirtyScanChunkDefault <= 0 || flowSummaryDirtyScanChunkDefault > 1_000_000 {
		t.Errorf("flowSummaryDirtyScanChunkDefault is %d; it must stay within (0, 1,000,000], "+
			"the widest id range measured safe against the 30s statement_timeout",
			flowSummaryDirtyScanChunkDefault)
	}
}

// TestFlowSummary_StalledTierRecoversUnaided is the state production was found
// in, on this code: a watermark left far behind, the tier's rows all
// superseded, its fill marker blank. With the scan in pieces the tier catches
// up by itself; nothing has to be reset by hand.
//
// SQLite has no statement timeout, so the hook stands in for one: any
// statement wider than the chunk fails, as the single statement over the whole
// backlog did in production on every pass.
func TestFlowSummary_StalledTierRecoversUnaided(t *testing.T) {
	d := NewDatabaseForTesting(t)
	const built, hours = 6, 10
	base, stale := builtSummary(t, d, built)
	useDirtyScanChunk(t, 3)

	// A month of traffic the tier never saw: new hours, and more in old ones.
	for h := 0; h < hours; h++ {
		seedSummaryHour(t, d, base, h, 5000, "10.0.0.9")
		seedSummaryHour(t, d, base, h, 700, "10.0.0.7")
	}
	for _, m := range []any{&models.FlowSummary{}, &models.FlowSummaryTop{}, &models.FlowSummaryBucket{}} {
		if err := d.Gorm().Where("interval_type = ?", "1h").Delete(m).Error; err != nil {
			t.Fatalf("empty the hourly tier: %v", err)
		}
	}
	d.clearSummaryFillMarker("1h")
	if got := d.summaryWatermark("1h"); got != stale {
		t.Fatalf("precondition: the watermark is %d, want it left at %d", got, stale)
	}
	if d.summaryBackfillComplete() {
		t.Fatal("precondition: an emptied tier with no fill marker reads as complete")
	}

	flowSummaryDirtyChunkHook = func(iv string, lo, hi int64) error {
		if hi-lo > 3 {
			return fmt.Errorf("synthetic statement timeout: ids %d-%d is %d wide", lo, hi, hi-lo)
		}
		return nil
	}
	for i := 0; i < 6 && !d.summaryBackfillComplete(); i++ {
		d.RunFlowSummaryCycle()
	}
	if !d.summaryBackfillComplete() {
		t.Fatal("the stalled tier did not catch up")
	}
	assertBucketsAgree(t, d, base, hours, "after catching up")
	if got, want := d.summaryWatermark("1h"), maxRollupID(t, d); got != want {
		t.Errorf("the watermark is %d after catching up, want the newest id %d", got, want)
	}

	seedSummaryHour(t, d, base, 1, 9000, "10.0.0.5")
	d.RunFlowSummaryCycle()
	assertBucketsAgree(t, d, base, hours, "after a late row")
}

// TestFlowSummary_DailyTierDirtyScanIsChunked: the daily tier goes through the
// same piece loop with a day-wide bucket. Every other fixture here is 5m-only
// and never reaches it.
func TestFlowSummary_DailyTierDirtyScanIsChunked(t *testing.T) {
	d := NewDatabaseForTesting(t)
	day := time.Now().UTC().AddDate(0, 0, -40).Truncate(24 * time.Hour)
	seedDay := func(offset int, bytes uint64, src string) {
		t.Helper()
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.AddDate(0, 0, offset),
			DeviceID:  1, IntervalType: "1d",
			SrcAddr: src, DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: bytes, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed day %d: %v", offset, err)
		}
	}
	dayBytes := func(offset int) (want, got uint64) {
		b := day.AddDate(0, 0, offset)
		d.Gorm().Model(&models.FlowRollup{}).
			Where("timestamp >= ? AND timestamp < ?", b, b.AddDate(0, 0, 1)).
			Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
		d.Gorm().Model(&models.FlowSummary{}).
			Where("interval_type = ? AND timestamp = ?", "1d", b).
			Select("COALESCE(SUM(bytes_sum),0)").Scan(&got)
		return
	}
	const days = 4
	for o := 0; o < days; o++ {
		seedDay(o, 100, "10.0.0.1")
	}
	for i := 0; i < 5; i++ {
		d.RunFlowSummaryCycle()
	}
	watermark := d.summaryWatermark("1d")
	if watermark != maxRollupID(t, d) {
		t.Fatalf("precondition: daily watermark %d is not the newest id %d", watermark, maxRollupID(t, d))
	}
	useDirtyScanChunk(t, 1)
	for o := days - 1; o >= 0; o-- {
		seedDay(o, 5000, "10.0.0.9")
	}

	var chunks []dirtyChunk
	flowSummaryDirtyChunkHook = func(iv string, lo, hi int64) error {
		if iv == "1d" {
			chunks = append(chunks, dirtyChunk{lo, hi})
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	flowSummaryDirtyChunkHook = nil

	if len(chunks) != days || chunks[0].lo != watermark || chunks[len(chunks)-1].hi != maxRollupID(t, d) {
		t.Fatalf("the daily tier's scan of %d new ids in pieces of 1 was %v (watermark %d)", days, chunks, watermark)
	}
	for o := 0; o < days; o++ {
		if want, got := dayBytes(o); got != want || want != 5100 {
			t.Fatalf("day %d holds %d bytes against %d in the source (want 5100)", o, got, want)
		}
	}
}
