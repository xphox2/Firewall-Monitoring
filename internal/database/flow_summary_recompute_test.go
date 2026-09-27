package database

import (
	"errors"
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// recomputeFixture resets the recompute step's knobs and hooks around a test.
func recomputeFixture(t *testing.T) *Database {
	t.Helper()
	d := NewDatabaseForTesting(t)
	oldReserve, oldForce, oldHourly := flowSummaryRecomputeReserve, flowSummaryRecomputeForceAfter, flowSummaryRecomputeHourlyRetries
	oldDur := flowSummaryMaxCycleDuration
	t.Cleanup(func() {
		flowSummaryRecomputeReserve, flowSummaryRecomputeForceAfter, flowSummaryRecomputeHourlyRetries = oldReserve, oldForce, oldHourly
		flowSummaryMaxCycleDuration = oldDur
		flowSummaryRecomputeHook, flowSummaryDirtyHook, flowSummaryBucketHook = nil, nil, nil
		recomputeBlockedCycles = 0
	})
	flowSummaryRecomputeReserve = 0 // tests do not wait for real time
	recomputeBlockedCycles = 0
	return d
}

// seedTwoTiers lays down history both summary tiers own: two fully promoted
// days (daily tier) and a few recent hours (hourly tier), all External under
// the old rule, and marks the reclassification complete for revision 1.
func seedTwoTiers(t *testing.T, d *Database) (day time.Time, recent time.Time) {
	t.Helper()
	// Contiguous like production: two promoted days, then the hourly tier's
	// data starting right at the daily floor. (A gap between the tiers makes
	// the hourly backfill restart every cycle — rebuilding everything anyway —
	// which would hide what this step is for.)
	recent = time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)
	floorDay := recent.Truncate(24 * time.Hour)
	day = floorDay.Add(-2 * 24 * time.Hour)
	if err := d.Gorm().Create(&models.FlowRollup{
		Timestamp: floorDay, DeviceID: 1, IntervalType: "1h",
		SrcAddr: "66.179.9.156", DstAddr: "203.0.113.9", DstPort: 51000, Protocol: 6,
		BytesSum: 10, PacketsSum: 1, FlowCount: 1, Direction: classify.DirExternal,
	}).Error; err != nil {
		t.Fatalf("seed 1h: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: day.Add(time.Duration(i) * 24 * time.Hour), DeviceID: 1, IntervalType: "1d",
			SrcAddr: "66.179.9.156", DstAddr: "203.0.113.9", DstPort: 51000, Protocol: 6,
			BytesSum: 1000, PacketsSum: 10, FlowCount: 1, Direction: classify.DirExternal,
		}).Error; err != nil {
			t.Fatalf("seed 1d: %v", err)
		}
	}
	for h := 0; h < 4; h++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: recent.Add(time.Duration(h)*time.Hour + 5*time.Minute), DeviceID: 1, IntervalType: "5m",
			SrcAddr: "66.179.9.156", DstAddr: "203.0.113.9", DstPort: 51000, Protocol: 6,
			BytesSum: 100, PacketsSum: 1, FlowCount: 1, Direction: classify.DirExternal,
		}).Error; err != nil {
			t.Fatalf("seed 5m: %v", err)
		}
	}
	for i := 0; i < 6; i++ {
		d.RunFlowSummaryCycle()
	}
	if !d.summaryBackfillComplete() {
		t.Fatal("precondition: the summary backfill did not complete")
	}
	// The reclassification finished for revision 1 and re-stamped every
	// rollup IN PLACE: the operator's /28 is now internal, so these flows are
	// Outbound. In-place updates are invisible to the summary's id watermark.
	d.Gorm().Create(&models.SystemSetting{Key: FlowReclassDoneRevKey, Value: "1"})
	d.Gorm().Model(&models.FlowRollup{}).Where("1 = 1").Updates(map[string]any{"direction": classify.DirOutbound, "class_rev": 1})
	d.Gorm().Create(&models.SystemSetting{Key: flowSummaryServiceSinceKey, Value: time.Now().UTC().Format(time.RFC3339)})
	return day, recent
}

func postRecomputeRequest(t *testing.T, d *Database, rev uint16, bucket time.Time) {
	t.Helper()
	if err := d.setReclassSetting(flowSummaryRecomputeRequestKey, recomputeMark{rev: rev, bucket: bucket.UTC().Truncate(time.Hour)}.String()); err != nil {
		t.Fatal(err)
	}
}

// cubeBytesByDirection sums the summary cube per direction.
func cubeBytesByDirection(t *testing.T, d *Database) map[uint8]uint64 {
	t.Helper()
	var rows []struct {
		Direction uint8
		Bytes     uint64
	}
	d.Gorm().Model(&models.FlowSummary{}).Select("direction, SUM(bytes_sum) as bytes").Group("direction").Scan(&rows)
	out := map[uint8]uint64{}
	for _, r := range rows {
		out[r.Direction] = r.Bytes
	}
	return out
}

func runCycles(d *Database, n int) {
	for i := 0; i < n; i++ {
		d.RunFlowSummaryCycle()
	}
}

func sinceSet(d *Database) bool {
	_, ok := d.GetSettingValue(flowSummaryServiceSinceKey)
	return ok
}

// TestSummaryRecompute_RebuildsInPlaceUpdates: without a request the summary
// keeps the old direction (the id watermark cannot see in-place updates);
// with one, every bucket in both tiers is rebuilt, the service boundary is
// removed, and the fill markers and watermarks are left alone.
func TestSummaryRecompute_RebuildsInPlaceUpdates(t *testing.T) {
	d := recomputeFixture(t)
	day, _ := seedTwoTiers(t, d)
	runCycles(d, 3)
	if got := cubeBytesByDirection(t, d); got[classify.DirOutbound] != 0 {
		t.Fatalf("precondition: the summary already shows Outbound %v without a request", got)
	}
	marks := map[string]time.Time{"1h": d.summaryFillMarker("1h"), "1d": d.summaryFillMarker("1d")}
	wms := map[string]int64{"1h": d.summaryWatermark("1h"), "1d": d.summaryWatermark("1d")}

	postRecomputeRequest(t, d, 1, day)
	runCycles(d, 10)

	got := cubeBytesByDirection(t, d)
	if got[classify.DirExternal] != 0 || got[classify.DirOutbound] == 0 {
		t.Errorf("summary bytes by direction after the rebuild = %v, want all Outbound", got)
	}
	if sinceSet(d) {
		t.Error("flow_summary_service_since survived a complete rebuild")
	}
	for _, iv := range []string{"1h", "1d"} {
		if !d.summaryFillMarker(iv).Equal(marks[iv]) || d.summaryWatermark(iv) != wms[iv] {
			t.Errorf("%s: the recompute moved the fill marker (%v -> %v) or watermark (%d -> %d)",
				iv, marks[iv], d.summaryFillMarker(iv), wms[iv], d.summaryWatermark(iv))
		}
	}
	if st := d.GetFlowSummaryRecomputeStatus(); st.Active {
		t.Errorf("the rebuild is still reported active: %+v", st)
	}
}

// TestSummaryRecompute_WaitsForTheReclassification: buckets rebuilt while
// history is mid-rewrite would mix classifications, so nothing runs while a
// run is due or in progress.
func TestSummaryRecompute_WaitsForTheReclassification(t *testing.T) {
	d := recomputeFixture(t)
	day, _ := seedTwoTiers(t, d)
	postRecomputeRequest(t, d, 1, day)
	d.saveReclassState(reclassState{Rev: 1, Phase: reclassTableRollups})
	runCycles(d, 4)
	if got := cubeBytesByDirection(t, d); got[classify.DirOutbound] != 0 {
		t.Errorf("the summary was rebuilt while the reclassification ran: %v", got)
	}
	if st := d.GetFlowSummaryRecomputeStatus(); !st.Active || st.WaitingReason == "" {
		t.Errorf("status = %+v, want active and waiting with a reason", st)
	}
	d.deleteSetting(flowReclassStateKey)
	runCycles(d, 10)
	if got := cubeBytesByDirection(t, d); got[classify.DirExternal] != 0 {
		t.Errorf("after the run finished the rebuild did not complete: %v", got)
	}
}

// TestSummaryRecompute_FailingBucketIsRetriedNotSkipped: a failed bucket keeps
// its old rows, so it is retried rather than skipped, the tier is not marked
// done and the service boundary stays until it succeeds.
func TestSummaryRecompute_FailingBucketIsRetriedNotSkipped(t *testing.T) {
	d := recomputeFixture(t)
	day, recent := seedTwoTiers(t, d)
	postRecomputeRequest(t, d, 1, day)
	poison := recent.Add(time.Hour)
	failing := true
	flowSummaryRecomputeHook = func(interval string, b time.Time) error {
		if failing && interval == "1h" && b.Equal(poison) {
			return errors.New("injected")
		}
		return nil
	}
	runCycles(d, 10)
	if !sinceSet(d) {
		t.Fatal("the service boundary was cleared while a bucket had failed to rebuild")
	}
	if _, ok := d.GetSettingValue(recomputeDoneKey("1h")); ok {
		t.Error("the hourly tier was marked done with a bucket still failing")
	}
	st := d.GetFlowSummaryRecomputeStatus()
	if !st.Active || st.Tiers["1h"] == nil || len(st.Tiers["1h"].Failing) != 1 {
		t.Fatalf("status = %+v, want the failing bucket listed", st)
	}
	failing = false
	runCycles(d, 3)
	if sinceSet(d) || len(d.recomputeRetries("1h")) != 0 {
		t.Error("after the bucket recovered the rebuild did not complete")
	}
}

// TestSummaryRecompute_RequestDuringTheWalkIsNotLost: a request posted while
// the walk is under way (from a reclassification that re-stamped older rows)
// moves the cursor back; the older bucket is rebuilt again.
func TestSummaryRecompute_RequestDuringTheWalkIsNotLost(t *testing.T) {
	d := recomputeFixture(t)
	day, recent := seedTwoTiers(t, d)
	postRecomputeRequest(t, d, 1, recent)
	calls := map[time.Time]int{}
	posted := false
	flowSummaryRecomputeHook = func(interval string, b time.Time) error {
		calls[b]++
		if !posted && interval == "1h" {
			posted = true
			postRecomputeRequest(t, d, 1, day) // older rows re-stamped meanwhile
		}
		return nil
	}
	runCycles(d, 10)
	if calls[day] == 0 {
		t.Error("the daily bucket named by the mid-walk request was never rebuilt")
	}
	if sinceSet(d) {
		t.Error("the rebuild did not complete")
	}
}

// TestSummaryRecompute_PendingRequestKeepsTheBoundary: the boundary is removed
// only with no request pending — a request posted between the daily and the
// hourly tier finishing must be served first.
func TestSummaryRecompute_PendingRequestKeepsTheBoundary(t *testing.T) {
	d := recomputeFixture(t)
	day, _ := seedTwoTiers(t, d)
	postRecomputeRequest(t, d, 1, day)
	posted := false
	flowSummaryRecomputeHook = func(interval string, b time.Time) error {
		if !posted && interval == "1h" {
			posted = true
			postRecomputeRequest(t, d, 1, day)
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	for i := 0; i < 10 && posted; i++ {
		if _, pending := d.GetSettingValue(flowSummaryRecomputeRequestKey); pending && !sinceSet(d) {
			t.Fatal("the service boundary was removed while a request was pending")
		}
		d.RunFlowSummaryCycle()
	}
	if sinceSet(d) {
		t.Error("the boundary was never removed")
	}
}

// TestSummaryRecompute_RevisionMerge: a newer revision's request replaces the
// cursor at the earlier bucket and clears the done marks; an older one is
// ignored.
func TestSummaryRecompute_RevisionMerge(t *testing.T) {
	d := recomputeFixture(t)
	a := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	b := a.Add(-10 * 24 * time.Hour)
	d.setReclassSetting(recomputeCursorKey("1d"), recomputeMark{rev: 1, bucket: a}.String())
	d.setReclassSetting(recomputeDoneKey("1h"), "1")
	postRecomputeRequest(t, d, 2, b)
	d.consumeRecomputeRequest()
	if cur, _ := d.recomputeCursor("1d"); cur.rev != 2 || !cur.bucket.Equal(b) {
		t.Errorf("1d cursor = %+v, want rev 2 at %v", cur, b)
	}
	if _, ok := d.GetSettingValue(recomputeDoneKey("1h")); ok {
		t.Error("a newer revision did not clear the done mark")
	}
	postRecomputeRequest(t, d, 1, b.Add(-24*time.Hour))
	d.consumeRecomputeRequest()
	if cur, _ := d.recomputeCursor("1d"); cur.rev != 2 || !cur.bucket.Equal(b) {
		t.Errorf("an older revision's request moved the cursor: %+v", cur)
	}
	if _, ok := d.GetSettingValue(flowSummaryRecomputeRequestKey); ok {
		t.Error("the superseded request was not consumed")
	}
}

// TestSummaryRecompute_EmptyDailyTierFinishes: with nothing in the daily tier
// the rebuild still completes and removes the boundary.
func TestSummaryRecompute_EmptyDailyTierFinishes(t *testing.T) {
	d := recomputeFixture(t)
	recent := time.Now().UTC().Add(-5 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 3; h++ {
		d.Gorm().Create(&models.FlowRollup{Timestamp: recent.Add(time.Duration(h)*time.Hour + 5*time.Minute), DeviceID: 1,
			IntervalType: "5m", SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6, BytesSum: 1, FlowCount: 1})
	}
	runCycles(d, 4)
	d.Gorm().Create(&models.SystemSetting{Key: FlowReclassDoneRevKey, Value: "1"})
	d.Gorm().Create(&models.SystemSetting{Key: flowSummaryServiceSinceKey, Value: time.Now().UTC().Format(time.RFC3339)})
	postRecomputeRequest(t, d, 1, recent)
	runCycles(d, 5)
	if sinceSet(d) {
		t.Error("a rebuild with an empty daily tier never removed the boundary")
	}
}

// TestSummaryRecompute_DroppedRetryOfAPromotedDay: an hour on the retry list
// whose day is then promoted to the daily tier is dropped, not retried — a
// retry through the hourly tier would delete the day's daily rows and write
// one hour back.
func TestSummaryRecompute_DroppedRetryOfAPromotedDay(t *testing.T) {
	d := recomputeFixture(t)
	mk := func(ts time.Time, interval string, bytes uint64) {
		t.Helper()
		if err := d.Gorm().Create(&models.FlowRollup{Timestamp: ts, DeviceID: 1, IntervalType: interval,
			SrcAddr: "66.179.9.156", DstAddr: "203.0.113.9", DstPort: 51000, Protocol: 6, BytesSum: bytes,
			FlowCount: 1, Direction: classify.DirOutbound, ClassRev: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Two promoted days, then day D still at hourly resolution, then today.
	today := time.Now().UTC().Add(-6 * time.Hour).Truncate(24 * time.Hour)
	dayD := today.Add(-24 * time.Hour)
	mk(dayD.Add(-2*24*time.Hour), "1d", 1000)
	mk(dayD.Add(-24*time.Hour), "1d", 1000)
	for h := 0; h < 24; h += 6 {
		mk(dayD.Add(time.Duration(h)*time.Hour), "1h", 250)
	}
	mk(today, "1h", 10)
	runCycles(d, 6)
	d.Gorm().Create(&models.SystemSetting{Key: FlowReclassDoneRevKey, Value: "1"})

	// An hour of day D failed to rebuild earlier and sits on the retry list.
	d.saveRecomputeRetries("1h", []time.Time{dayD.Add(6 * time.Hour)})
	d.setReclassSetting(recomputeCursorKey("1h"), recomputeMark{rev: 1, bucket: today}.String())
	// Then day D is promoted: one daily row replaces its hours.
	d.Gorm().Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1h", dayD, dayD.Add(24*time.Hour)).Delete(&models.FlowRollup{})
	mk(dayD, "1d", 1000)

	calledOnD := false
	flowSummaryRecomputeHook = func(interval string, b time.Time) error {
		if interval == "1h" && !b.Before(dayD) && b.Before(dayD.Add(24*time.Hour)) {
			calledOnD = true
		}
		return nil
	}
	runCycles(d, 6)
	if calledOnD {
		t.Error("an hour of a day now owned by the daily tier was rebuilt through the hourly tier")
	}
	if len(d.recomputeRetries("1h")) != 0 {
		t.Errorf("the retry list still holds %v", d.recomputeRetries("1h"))
	}
	var hourly, dailyBytes int64
	d.Gorm().Model(&models.FlowSummary{}).Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1h", dayD, dayD.Add(24*time.Hour)).Count(&hourly)
	d.Gorm().Model(&models.FlowSummary{}).Where("interval_type = ? AND timestamp = ?", "1d", dayD).Select("COALESCE(SUM(bytes_sum),0)").Scan(&dailyBytes)
	if hourly != 0 || dailyBytes != 1000 {
		t.Errorf("day D: %d hourly summary rows and %d daily bytes, want 0 and 1000", hourly, dailyBytes)
	}
}

// TestSummaryRecompute_SkipsATierWhosePassFailed: when the tier's own pass
// failed before it knew its range, the recompute step leaves it alone.
func TestSummaryRecompute_SkipsATierWhosePassFailed(t *testing.T) {
	d := recomputeFixture(t)
	day, _ := seedTwoTiers(t, d)
	postRecomputeRequest(t, d, 1, day)
	flowSummaryDirtyHook = func(interval string) error {
		if interval == "1h" {
			return errors.New("injected")
		}
		return nil
	}
	hourlyRan := false
	flowSummaryRecomputeHook = func(interval string, b time.Time) error {
		if interval == "1h" {
			hourlyRan = true
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	if hourlyRan {
		t.Error("the recompute step ran for a tier whose pass failed")
	}
	if st := d.GetFlowSummaryRecomputeStatus(); st.Tiers["1h"] == nil || st.Tiers["1h"].State != "waiting" ||
		st.WaitingReason != "the summary pass failed; see the log" {
		t.Errorf("status = %+v (reason %q), want the hourly tier waiting because its pass failed", st.Tiers["1h"], st.WaitingReason)
	}
}

// TestSummaryRecompute_DailyForcedAfterBlockedCycles: when routine work leaves
// no time for a daily bucket, the status says so, and after the configured
// number of blocked cycles one daily bucket runs anyway. The hourly backfill
// keeps up meanwhile, so summary reads stay on.
func TestSummaryRecompute_DailyForcedAfterBlockedCycles(t *testing.T) {
	d := recomputeFixture(t)
	day, recent := seedTwoTiers(t, d)
	flowSummaryRecomputeReserve = time.Hour // never enough time
	flowSummaryRecomputeForceAfter = 3
	postRecomputeRequest(t, d, 1, day)
	dailyCalls := 0
	flowSummaryRecomputeHook = func(interval string, b time.Time) error {
		if interval == "1d" {
			dailyCalls++
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	if st := d.GetFlowSummaryRecomputeStatus(); st.WaitingReason == "" {
		t.Error("a blocked daily rebuild did not say why")
	}
	for i := 0; i < 8; i++ {
		// New traffic every cycle: the hourly fill marker must keep moving.
		d.Gorm().Create(&models.FlowRollup{Timestamp: recent.Add(time.Duration(4+i)*time.Hour + 5*time.Minute), DeviceID: 1,
			IntervalType: "5m", SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6, BytesSum: 1, FlowCount: 1, ClassRev: 1})
		d.RunFlowSummaryCycle()
		if !d.summaryBackfillComplete() {
			t.Fatalf("cycle %d: the hourly backfill fell behind while the daily rebuild waited", i)
		}
	}
	if dailyCalls == 0 {
		t.Error("the daily rebuild never ran despite the forced-bucket rule")
	}
}

// TestSummaryRecompute_OwnershipDriftMidWalk: the hourly cursor sits inside
// day D when D is promoted to the daily tier. D must end up in exactly one
// tier, with the new direction and the source's bytes.
func TestSummaryRecompute_OwnershipDriftMidWalk(t *testing.T) {
	d := recomputeFixture(t)
	mk := func(ts time.Time, interval string, bytes uint64, dir uint8) {
		t.Helper()
		if err := d.Gorm().Create(&models.FlowRollup{Timestamp: ts, DeviceID: 1, IntervalType: interval,
			SrcAddr: "66.179.9.156", DstAddr: "203.0.113.9", DstPort: 51000, Protocol: 6, BytesSum: bytes,
			FlowCount: 1, Direction: dir, ClassRev: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	today := time.Now().UTC().Add(-6 * time.Hour).Truncate(24 * time.Hour)
	dayD := today.Add(-24 * time.Hour)
	mk(dayD.Add(-24*time.Hour), "1d", 1000, classify.DirExternal)
	for h := 0; h < 24; h += 6 {
		mk(dayD.Add(time.Duration(h)*time.Hour), "1h", 250, classify.DirExternal)
	}
	mk(today, "1h", 10, classify.DirExternal)
	runCycles(d, 6)
	d.Gorm().Create(&models.SystemSetting{Key: FlowReclassDoneRevKey, Value: "1"})
	d.Gorm().Model(&models.FlowRollup{}).Where("1 = 1").Update("direction", classify.DirOutbound)
	// The hourly walk is part-way through day D...
	d.setReclassSetting(recomputeCursorKey("1h"), recomputeMark{rev: 1, bucket: dayD.Add(12 * time.Hour)}.String())
	// ...when D is promoted: one daily row replaces its hours.
	d.Gorm().Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1h", dayD, dayD.Add(24*time.Hour)).Delete(&models.FlowRollup{})
	mk(dayD, "1d", 1000, classify.DirOutbound)
	runCycles(d, 6)

	var hourly int64
	var daily []models.FlowSummary
	d.Gorm().Model(&models.FlowSummary{}).Where("interval_type = ? AND timestamp >= ? AND timestamp < ?", "1h", dayD, dayD.Add(24*time.Hour)).Count(&hourly)
	d.Gorm().Where("interval_type = ? AND timestamp = ?", "1d", dayD).Find(&daily)
	var bytes uint64
	for _, r := range daily {
		bytes += r.BytesSum
		if r.Direction != classify.DirOutbound {
			t.Errorf("day D's daily row has direction %s, want Outbound", classify.DirectionName(r.Direction))
		}
	}
	if hourly != 0 || bytes != 1000 {
		t.Errorf("day D: %d hourly rows and %d daily bytes, want 0 and 1000 (exactly one tier)", hourly, bytes)
	}
}
