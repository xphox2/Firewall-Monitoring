//go:build integration

package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The rollup ladder has had two production incidents and, until this file, zero
// PostgreSQL coverage — every promotion test ran on SQLite only. That is the
// wrong way round: production is PostgreSQL, and the two dialects do NOT agree
// on the bucket expressions the ladder groups by. SQLite's "5min" bucket was
// silently a MINUTE bucket until v0.11.253, which no SQLite test could catch
// because every SQLite test shared the same wrong expression.
//
// These run the real ladder against a real PostgreSQL through the same
// dialect-dispatched SQL production uses.

// TestFlowRollupLadderIntegration_PromotesWholeBucketsAndConservesTotals walks
// raw -> 5m -> 1h -> 1d and asserts the two properties the ladder rests on:
// bytes are conserved at every step, and each destination bucket is written
// exactly once however many promotion passes run over it.
func TestFlowRollupLadderIntegration_PromotesWholeBucketsAndConservesTotals(t *testing.T) {
	d := NewIntegrationDB(t)

	// A full UTC day of raw samples, one per minute, all sharing a group key so
	// a split bucket shows up as extra rows rather than different totals.
	day := time.Now().UTC().Add(-100 * 24 * time.Hour).Truncate(24 * time.Hour)
	const perSample = 10
	const samples = 24 * 60
	for i := 0; i < samples; i++ {
		if err := d.Gorm().Create(&models.FlowSample{
			Timestamp: day.Add(time.Duration(i) * time.Minute),
			DeviceID:  1, SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8",
			DstPort: 443, Protocol: 6, Bytes: perSample, Packets: 1, SamplingRate: 1,
		}).Error; err != nil {
			t.Fatalf("seed sample %d: %v", i, err)
		}
	}
	const wantBytes = perSample * samples

	tierBytes := func(interval string) uint64 {
		var n uint64
		d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", interval).
			Select("COALESCE(SUM(bytes_sum),0)").Scan(&n)
		return n
	}
	tierRows := func(interval string) int64 {
		var n int64
		d.Gorm().Model(&models.FlowRollup{}).Where("interval_type = ?", interval).Count(&n)
		return n
	}
	rawBytes := func() uint64 {
		var n uint64
		d.Gorm().Model(&models.FlowSample{}).Select("COALESCE(SUM(bytes),0)").Scan(&n)
		return n
	}

	// Step 1: raw -> 5m, run TWICE with cutoffs landing mid-bucket. The second
	// pass must not re-split a bucket the first one deferred.
	d.aggregateFlowsToRollup(day.Add(12*time.Hour+3*time.Minute), "5m")
	d.aggregateFlowsToRollup(day.Add(36*time.Hour), "5m")
	if got := tierBytes("5m") + rawBytes(); got != wantBytes {
		t.Fatalf("after raw->5m, 5m tier plus surviving raw = %d bytes, want %d", got, wantBytes)
	}
	// A full day at true 5-minute buckets is 288 rows. Minute buckets would give
	// 1440 — which is what SQLite silently produced before v0.11.253.
	if got := tierRows("5m"); got != 288 {
		t.Errorf("5m tier holds %d rows for one day, want 288 (a day at real 5-minute "+
			"buckets). 1440 would mean the bucket expression is truncating to the minute.", got)
	}

	// Step 2: 5m -> 1h, again twice, the first cutoff mid-hour.
	d.aggregateRollupsUp("5m", "1h", day.Add(12*time.Hour+37*time.Minute))
	d.aggregateRollupsUp("5m", "1h", day.Add(36*time.Hour))
	if got := tierBytes("1h") + tierBytes("5m") + rawBytes(); got != wantBytes {
		t.Fatalf("after 5m->1h, the tiers hold %d bytes, want %d", got, wantBytes)
	}
	if got := tierRows("1h"); got != 24 {
		t.Errorf("1h tier holds %d rows for one day, want 24 — a bucket straddling a "+
			"promotion cutoff must be deferred whole, not split into one row per pass.", got)
	}

	// Step 3: 1h -> 1d. This is the window that is scanned in hourly sub-ranges
	// and merged in Go, so it is the one that proves the merge agrees with what a
	// single PostgreSQL GROUP BY would have produced.
	d.aggregateRollupsUp("1h", "1d", day.Add(13*time.Hour))
	if got := tierRows("1d"); got != 0 {
		t.Errorf("1d tier holds %d rows after a cutoff INSIDE the day, want 0", got)
	}
	d.aggregateRollupsUp("1h", "1d", day.Add(48*time.Hour))

	if got := tierRows("1d"); got != 1 {
		t.Errorf("1d tier holds %d rows for one day, want exactly 1 — the 24 hourly "+
			"sub-range scans must merge by group key, not emit a row each.", got)
	}
	if got := tierBytes("1d") + tierBytes("1h") + tierBytes("5m") + rawBytes(); got != wantBytes {
		t.Errorf("after the full ladder the tiers hold %d bytes, want the %d seeded", got, wantBytes)
	}
	if got := tierBytes("1d"); got != wantBytes {
		t.Errorf("the daily row carries %d bytes, want all %d — the sub-range merge "+
			"dropped measures", got, wantBytes)
	}
}

// TestFlowRollupLadderIntegration_MergesSamplingRateByFlowCount pins the
// weighted-mean re-weighting the Go-side merge has to do, on PostgreSQL. A
// single GROUP BY computes this in SQL; sub-ranging moved it into Go, and the
// two must agree.
func TestFlowRollupLadderIntegration_MergesSamplingRateByFlowCount(t *testing.T) {
	d := NewIntegrationDB(t)

	// Hour h carries flow_count h+1 at sampling rate h+1, so the day's
	// flow-count-weighted mean is sum(k^2)/sum(k) over k=1..24 = 4900/300.
	day := time.Now().UTC().Add(-100 * 24 * time.Hour).Truncate(24 * time.Hour)
	for h := 0; h < 24; h++ {
		k := float64(h + 1)
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(h) * time.Hour),
			DeviceID:  1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: int64(h + 1), SamplingRateAvg: k,
		}).Error; err != nil {
			t.Fatalf("seed +%dh: %v", h, err)
		}
	}

	d.aggregateRollupsUp("1h", "1d", day.Add(48*time.Hour))

	var rows []models.FlowRollup
	if err := d.Gorm().Where("interval_type = ?", "1d").Find(&rows).Error; err != nil {
		t.Fatalf("read 1d tier: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("1d rows = %d, want 1", len(rows))
	}
	const want = 4900.0 / 300.0
	if got := rows[0].SamplingRateAvg; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("merged sampling_rate_avg = %v, want %v (flow-count-weighted). A plain "+
			"average gives 12.5 and keeping the first sub-range gives 1.", got, want)
	}
	if rows[0].FlowCount != 300 {
		t.Errorf("merged flow_count = %d, want 300", rows[0].FlowCount)
	}
}
