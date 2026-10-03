package database

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"

	"github.com/jackc/pgx/v5/pgconn"
)

// reclassFixture shrinks the job's tunables so a handful of rows exercises
// multiple slices, windows and passes, and stubs its sleeps.
func reclassFixture(t *testing.T) *Database {
	t.Helper()
	d := NewDatabaseForTesting(t)
	oldLimit, oldWin, oldMax, oldFloor := reclassSliceLimit, reclassInitialWindow, reclassMaxWindow, reclassWriteFloor
	oldSleep, oldRange := reclassSleep, reclassVerifyRange
	reclassSliceLimit, reclassInitialWindow, reclassMaxWindow, reclassWriteFloor = 3, 8, 64, 1
	// Verification counts in id ranges; a tiny range makes every test cross
	// many of them.
	reclassVerifyRange = 5
	reclassSleep = func(time.Duration) {}
	t.Cleanup(func() {
		reclassVerifyRange = oldRange
		reclassSliceLimit, reclassInitialWindow, reclassMaxWindow, reclassWriteFloor = oldLimit, oldWin, oldMax, oldFloor
		reclassSleep = oldSleep
		reclassReadHook, reclassWriteHook, reclassVerifyHook, reclassRearmReadHook = nil, nil, nil, nil
	})
	return d
}

// ownNets is the operator's network used throughout: the /28 a production
// server lives on.
var ownNets = []netip.Prefix{netip.MustParsePrefix("198.19.9.144/28")}

func setForTest(rev uint16) (*classify.InternalSet, error) {
	return classify.NewInternalSet(ownNets, rev), nil
}

// seedReclass lays down old-revision history: server replies and requests
// from the operator's own public range (External under the old rule), plus
// B1-era rollups that already carry an exact service port.
func seedReclass(t *testing.T, d *Database, n int) {
	t.Helper()
	base := time.Now().Add(-30 * time.Minute)
	for i := 0; i < n; i++ {
		if err := d.Gorm().Create(&models.FlowSample{
			Timestamp: base, DeviceID: 1, Protocol: 6,
			SrcAddr: "198.19.9.156", DstAddr: "198.51.100.7", SrcPort: 443, DstPort: uint16(50000 + i),
			Bytes: 100, Packets: 1, Direction: classify.DirExternal,
		}).Error; err != nil {
			t.Fatalf("seed sample: %v", err)
		}
		svc := uint16(0)
		if i%3 == 0 {
			svc = 8443 // a B1-era row: exact, must be kept
		}
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: base.Add(-time.Duration(24+i) * time.Hour), DeviceID: 1, IntervalType: "1h", Protocol: 6,
			SrcAddr: "198.51.100.7", DstAddr: "198.19.9.156", DstPort: 443, ServicePort: svc,
			BytesSum: 100, FlowCount: 1, SamplingRateAvg: 1, Direction: classify.DirExternal,
		}).Error; err != nil {
			t.Fatalf("seed rollup: %v", err)
		}
	}
}

// runReclassToDone runs steps until the target's run completes (or fails the
// test after max steps).
func runReclassToDone(t *testing.T, d *Database, max int) {
	t.Helper()
	for i := 0; i < max; i++ {
		if err := d.RunFlowReclassStep(setForTest, time.Minute); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if _, running := d.loadReclassState(); !running && d.FlowReclassDoneRev() >= d.FlowReclassTargetRev() {
			return
		}
	}
	t.Fatalf("the run did not complete in %d steps (state %+v)", max, d.GetFlowReclassStatus())
}

func assertAllReclassified(t *testing.T, d *Database, rev uint16) {
	t.Helper()
	set := classify.NewInternalSet(ownNets, rev)
	var samples []models.FlowSample
	d.Gorm().Find(&samples)
	for _, s := range samples {
		if s.ClassRev != rev || s.Direction != set.Direction(s.SrcAddr, s.DstAddr) ||
			s.ServicePort != classify.ServicePort(s.Protocol, s.SrcPort, s.DstPort) {
			t.Errorf("sample %d: rev %d dir %d svc %d, want rev %d dir %d svc %d", s.ID, s.ClassRev, s.Direction, s.ServicePort,
				rev, set.Direction(s.SrcAddr, s.DstAddr), classify.ServicePort(s.Protocol, s.SrcPort, s.DstPort))
		}
	}
	var rollups []models.FlowRollup
	d.Gorm().Find(&rollups)
	for _, r := range rollups {
		if r.ClassRev != rev || r.Direction != set.Direction(r.SrcAddr, r.DstAddr) {
			t.Errorf("rollup %d: rev %d dir %d, want rev %d dir %d", r.ID, r.ClassRev, r.Direction, rev, set.Direction(r.SrcAddr, r.DstAddr))
		}
	}
}

// TestFlowReclass_FullRunMatchesIngest: a run re-stamps every old-revision row
// exactly as ingest would classify it now; B1-era exact service ports are
// kept and zeros are inferred from the destination; completion records the
// revision, the rollup floor, the probe starting points and the summary
// rebuild request.
func TestFlowReclass_FullRunMatchesIngest(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 10)
	runReclassToDone(t, d, 20)
	assertAllReclassified(t, d, 1)

	var rollups []models.FlowRollup
	d.Gorm().Order("id").Find(&rollups)
	for i, r := range rollups {
		want := uint16(443) // inferred from dst 443
		if i%3 == 0 {
			want = 8443 // exact B1-era value kept
		}
		if r.ServicePort != want {
			t.Errorf("rollup %d service_port = %d, want %d", r.ID, r.ServicePort, want)
		}
		if r.Direction != classify.DirInbound {
			t.Errorf("rollup %d direction = %s, want Inbound (dst is the operator's own)", r.ID, classify.DirectionName(r.Direction))
		}
	}
	if d.FlowReclassDoneRev() != 1 {
		t.Errorf("done_rev = %d, want 1", d.FlowReclassDoneRev())
	}
	maxRollup, _ := d.tableMaxID(reclassTableRollups)
	if got := d.GetIntSetting(flowReclassRollupFloorKey, -1); int64(got) != maxRollup {
		t.Errorf("rollup floor = %d, want %d", got, maxRollup)
	}
	if req, ok := d.GetSettingValue(flowSummaryRecomputeRequestKey); !ok || req == "" {
		t.Error("no summary recompute request was recorded")
	}
	if st := d.GetFlowReclassStatus(); st.Phase != "done" || !st.VacuumHint || st.Updated != 20 {
		t.Errorf("status = %+v, want done with the vacuum hint and 20 rows updated", st)
	}
}

// TestFlowReclass_ResumesAfterAFailedStep: a step that fails part-way keeps
// its place; the next step continues and the result is identical.
func TestFlowReclass_ResumesAfterAFailedStep(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 10)
	reads := 0
	reclassReadHook = func(table string, lo, hi int64) error {
		reads++
		if reads == 3 {
			return errors.New("injected")
		}
		return nil
	}
	if err := d.RunFlowReclassStep(setForTest, time.Minute); err == nil {
		t.Fatal("the injected failure was not reported")
	}
	st, running := d.loadReclassState()
	if !running || st.Cursor == 0 {
		t.Fatalf("no progress was kept: %+v", st)
	}
	reclassReadHook = nil
	runReclassToDone(t, d, 20)
	assertAllReclassified(t, d, 1)
}

// TestFlowReclass_TargetBumpedMidRunRestarts: a Reapply during a run abandons
// it and re-walks everything under the new revision.
func TestFlowReclass_TargetBumpedMidRunRestarts(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 10)
	bumped := false
	reclassReadHook = func(table string, lo, hi int64) error {
		if !bumped && table == reclassTableRollups {
			bumped = true
			if _, err := d.BumpFlowReclassTargetRev(); err != nil {
				t.Fatalf("bump: %v", err)
			}
		}
		return nil
	}
	runReclassToDone(t, d, 40)
	if d.FlowReclassDoneRev() != 2 {
		t.Fatalf("done_rev = %d, want 2", d.FlowReclassDoneRev())
	}
	assertAllReclassified(t, d, 2)
}

// TestFlowReclass_BumpDuringVerificationKeepsTheOldDone: the revision is
// pinned for a run — a bump while verifying must not mark the NEW revision
// done; the next step starts a full run for it.
func TestFlowReclass_BumpDuringVerificationKeepsTheOldDone(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 4)
	reclassVerifyHook = func() {
		reclassVerifyHook = nil
		if _, err := d.BumpFlowReclassTargetRev(); err != nil {
			t.Fatalf("bump: %v", err)
		}
	}
	for i := 0; i < 20 && d.FlowReclassDoneRev() == 0; i++ {
		if err := d.RunFlowReclassStep(setForTest, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if d.FlowReclassDoneRev() != 1 {
		t.Fatalf("done_rev = %d after the bumped verification, want 1 (the run's pinned revision)", d.FlowReclassDoneRev())
	}
	runReclassToDone(t, d, 40)
	assertAllReclassified(t, d, 2)
}

// TestFlowReclass_WriteRetriesAndSplits: a lock timeout retries the same
// batch; a statement timeout splits it down to the floor.
func TestFlowReclass_WriteRetriesAndSplits(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 6)
	lockFails, splits := 0, 0
	reclassWriteHook = func(table string, n int) error {
		if lockFails < 2 {
			lockFails++
			return &pgconn.PgError{Code: "55P03"}
		}
		if n > 1 {
			splits++
			return &pgconn.PgError{Code: "57014"}
		}
		return nil
	}
	runReclassToDone(t, d, 40)
	assertAllReclassified(t, d, 1)
	if lockFails != 2 || splits == 0 {
		t.Errorf("lock retries %d, splits %d; want 2 and some", lockFails, splits)
	}
}

// TestFlowReclass_ReadTimeoutNarrowsTheWindow over a sparse id space: a read
// timeout narrows the window instead of failing the run.
func TestFlowReclass_ReadTimeoutNarrowsTheWindow(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 6)
	// A sparse id space like production's: a gap of 1,000 ids in the rollups.
	if err := d.Gorm().Create(&models.FlowRollup{ID: 5000, Timestamp: time.Now().Add(-72 * time.Hour), DeviceID: 1, IntervalType: "1h",
		Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 53, BytesSum: 1, FlowCount: 1}).Error; err != nil {
		t.Fatal(err)
	}
	narrowed := false
	reclassReadHook = func(table string, lo, hi int64) error {
		if hi-lo > 16 {
			narrowed = true
			return &pgconn.PgError{Code: "57014"}
		}
		return nil
	}
	runReclassToDone(t, d, 200)
	assertAllReclassified(t, d, 1)
	if !narrowed {
		t.Error("the window never widened past the injected limit")
	}
}

// TestFlowReclass_DiskGuardPauses: below 15% free the job does no work and
// says why.
func TestFlowReclass_DiskGuardPauses(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 3)
	full := 95.0
	if err := d.Gorm().Create(&models.ServerMetric{Timestamp: time.Now(), DataDiskPercent: &full}).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.RunFlowReclassStep(setForTest, time.Minute); err != nil {
		t.Fatal(err)
	}
	var n int64
	d.Gorm().Model(&models.FlowRollup{}).Where("class_rev = 1").Count(&n)
	if n != 0 {
		t.Errorf("%d rows were re-stamped while the disk was full", n)
	}
	if st := d.GetFlowReclassStatus(); st.Phase != "paused" || st.PausedReason == "" {
		t.Errorf("status = %+v, want paused with a reason", st)
	}
}

// TestFlowReclass_VerificationRePassesFromTheLowestOldRow: an old-revision row
// that appears below the walked cursor (an in-flight promotion) is found by
// the locked count and re-walked from just below it — not from 0.
func TestFlowReclass_VerificationRePassesFromTheLowestOldRow(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 4)
	// Rollup ids 1..4 exist; leave a hole at 50 and put rows at 100..103.
	for i := int64(0); i < 4; i++ {
		if err := d.Gorm().Create(&models.FlowRollup{ID: uint(100 + i), Timestamp: time.Now().Add(-48 * time.Hour), DeviceID: 1,
			IntervalType: "1h", Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "198.19.9.150", DstPort: 443, BytesSum: 1, FlowCount: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	inserted := false
	var repassFrom int64 = -1
	reclassReadHook = func(table string, lo, hi int64) error {
		if table != reclassTableRollups {
			return nil
		}
		if !inserted && lo >= 60 {
			inserted = true
			// Promoted mid-walk into the hole already passed, still old-rev.
			if err := d.Gorm().Create(&models.FlowRollup{ID: 50, Timestamp: time.Now().Add(-48 * time.Hour), DeviceID: 1,
				IntervalType: "1h", Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "198.19.9.150", DstPort: 443, BytesSum: 1, FlowCount: 1}).Error; err != nil {
				t.Fatal(err)
			}
		}
		if inserted && repassFrom < 0 && lo < 60 {
			repassFrom = lo
		}
		return nil
	}
	runReclassToDone(t, d, 40)
	assertAllReclassified(t, d, 1)
	if repassFrom != 49 {
		t.Errorf("the re-pass started at %d, want 49 (just below the lowest old-revision row)", repassFrom)
	}
}

// TestFlowReclass_RearmAndProbes: after a run, a re-arm mark (the API stamped
// revision-0 rows) or an old-revision row found by the probes starts an
// incremental run that walks flow_rollups only above the floor.
func TestFlowReclass_RearmAndProbes(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 3)
	runReclassToDone(t, d, 20)
	floor := int64(d.GetIntSetting(flowReclassRollupFloorKey, 0))

	// The API stamped a revision-0 sample and left a mark: an incremental run.
	if err := d.MarkFlowReclassRearm(); err != nil {
		t.Fatal(err)
	}
	if err := d.Gorm().Create(&models.FlowSample{Timestamp: time.Now(), DeviceID: 1, Protocol: 6,
		SrcAddr: "198.19.9.156", DstAddr: "8.8.8.8", SrcPort: 443, DstPort: 51000, Bytes: 1, Packets: 1}).Error; err != nil {
		t.Fatal(err)
	}
	var walkedBelowFloor bool
	markedMidRun := false
	reclassReadHook = func(table string, lo, hi int64) error {
		if table == reclassTableRollups && lo < floor {
			walkedBelowFloor = true
		}
		if !markedMidRun {
			// A second API stamps revision 0 while this run is under way: its
			// mark must survive the run and start another.
			markedMidRun = true
			if err := d.MarkFlowReclassRearm(); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	runReclassToDone(t, d, 20)
	assertAllReclassified(t, d, 1)
	if walkedBelowFloor {
		t.Error("an incremental run walked flow_rollups below the floor")
	}
	if _, ok := d.GetSettingValue(FlowReclassRearmKey); !ok {
		t.Fatal("a mark written during the run was consumed by it")
	}
	reclassReadHook = nil
	if err := d.RunFlowReclassStep(setForTest, time.Minute); err != nil {
		t.Fatal(err)
	}
	if st, running := d.loadReclassState(); !running || !st.Incremental {
		if _, ok := d.GetSettingValue(FlowReclassRearmKey); ok {
			t.Error("the surviving mark did not start another run")
		}
	}
	runReclassToDone(t, d, 20)
	if _, ok := d.GetSettingValue(FlowReclassRearmKey); ok {
		t.Error("the re-arm mark was never consumed")
	}

	// No mark: a stale rollup promoted after the run is found by the probe.
	if err := d.Gorm().Create(&models.FlowRollup{Timestamp: time.Now().Add(-2 * time.Hour), DeviceID: 1, IntervalType: "5m",
		Protocol: 6, SrcAddr: "198.19.9.156", DstAddr: "8.8.8.8", DstPort: 443, BytesSum: 1, FlowCount: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.RunFlowReclassStep(setForTest, time.Minute); err != nil {
		t.Fatal(err)
	}
	runReclassToDone(t, d, 20)
	assertAllReclassified(t, d, 1)
}

// TestFlowReclass_StallWhileTheAPIStampsRevisionZero: rows newer than the
// walk still carrying revision 0 make the job wait (and say so) instead of
// re-walking every few seconds; once they stop, the run completes.
func TestFlowReclass_StallWhileTheAPIStampsRevisionZero(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 3)
	stamped := false
	reclassVerifyHook = func() {
		if stamped {
			return
		}
		stamped = true
		if err := d.Gorm().Create(&models.FlowSample{Timestamp: time.Now(), DeviceID: 1, Protocol: 6,
			SrcAddr: "198.19.9.156", DstAddr: "8.8.8.8", SrcPort: 443, DstPort: 51001, Bytes: 1, Packets: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	sawWaiting := false
	rollupsFromStart := 0
	reclassReadHook = func(table string, lo, hi int64) error {
		if table == reclassTableRollups && lo == 0 {
			rollupsFromStart++
		}
		return nil
	}
	for i := 0; i < 30; i++ {
		if err := d.RunFlowReclassStep(setForTest, time.Minute); err != nil {
			t.Fatal(err)
		}
		if d.GetFlowReclassStatus().Phase == "waiting" {
			sawWaiting = true
		}
		if d.FlowReclassDoneRev() == 1 {
			break
		}
	}
	if !sawWaiting {
		t.Error("the job never reported waiting while revision-0 rows kept arriving")
	}
	assertAllReclassified(t, d, 1)
	// A samples re-pass returns to verification; it must not fall through
	// into another walk of flow_rollups from the start (138M rows in
	// production, on every tick an API stamps revision 0).
	if rollupsFromStart != 1 {
		t.Errorf("flow_rollups was walked from the start %d times, want once", rollupsFromStart)
	}
}

// TestFlowReclass_UpdatedCountsRowsActuallyRestamped: a row deleted between
// the read and the write (a promotion, retention) is not counted.
func TestFlowReclass_UpdatedCountsRowsActuallyRestamped(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 3)
	deleted := false
	reclassWriteHook = func(table string, n int) error {
		if !deleted && table == reclassTableRollups {
			deleted = true
			var first models.FlowRollup
			d.Gorm().Order("id").First(&first)
			d.Gorm().Delete(&first)
		}
		return nil
	}
	runReclassToDone(t, d, 20)
	if st := d.GetFlowReclassStatus(); st.Updated != 5 {
		t.Errorf("updated = %d, want 5 (6 rows read, 1 deleted before its write)", st.Updated)
	}
}

// TestFlowReclass_StaleDiskMetricDoesNotPause: a disk figure older than the
// poller's cadence says nothing about now; the job proceeds.
func TestFlowReclass_StaleDiskMetricDoesNotPause(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 2)
	full := 95.0
	if err := d.Gorm().Create(&models.ServerMetric{Timestamp: time.Now().Add(-time.Hour), DataDiskPercent: &full}).Error; err != nil {
		t.Fatal(err)
	}
	runReclassToDone(t, d, 20)
	assertAllReclassified(t, d, 1)
}

// TestBumpFlowReclassTargetRev_Concurrent: concurrent Reapply presses each
// count — the compare-and-swap never loses one.
func TestBumpFlowReclassTargetRev_Concurrent(t *testing.T) {
	d := NewDatabaseForTesting(t)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := d.BumpFlowReclassTargetRev()
			errs <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := d.FlowReclassTargetRev(); got != 3 {
		t.Errorf("target after two concurrent bumps = %d, want 3", got)
	}
}

// TestBumpFlowReclassTargetRev: absent and garbage values count as 1; two
// bumps give exactly +2; the limit refuses rather than wrapping.
func TestBumpFlowReclassTargetRev(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if v, err := d.BumpFlowReclassTargetRev(); err != nil || v != 2 {
		t.Fatalf("first bump = %d %v, want 2", v, err)
	}
	if v, err := d.BumpFlowReclassTargetRev(); err != nil || v != 3 {
		t.Fatalf("second bump = %d %v, want 3", v, err)
	}
	d.Gorm().Model(&models.SystemSetting{}).Where(`"key" = ?`, FlowReclassTargetRevKey).Update("value", "garbage")
	if v, err := d.BumpFlowReclassTargetRev(); err != nil || v != 2 {
		t.Fatalf("bump from garbage = %d %v, want 2", v, err)
	}
	d.Gorm().Model(&models.SystemSetting{}).Where(`"key" = ?`, FlowReclassTargetRevKey).Update("value", "65535")
	if _, err := d.BumpFlowReclassTargetRev(); !errors.Is(err, ErrReclassRevLimit) {
		t.Fatalf("bump at the limit = %v, want ErrReclassRevLimit", err)
	}
}

// TestFlowReclass_RearmMarkWrittenDuringConsumeSurvives: the mark is deleted
// only if it still holds the value read. A mark written by another API in the
// instant between the read and the delete is unique, so it survives and
// starts the next run.
func TestFlowReclass_RearmMarkWrittenDuringConsumeSurvives(t *testing.T) {
	d := reclassFixture(t)
	seedReclass(t, d, 2)
	if err := d.MarkFlowReclassRearm(); err != nil {
		t.Fatal(err)
	}
	var newer string
	reclassRearmReadHook = func() {
		reclassRearmReadHook = nil
		time.Sleep(time.Millisecond) // distinct nanosecond stamp
		if err := d.MarkFlowReclassRearm(); err != nil {
			t.Fatal(err)
		}
		newer, _ = d.GetSettingValue(FlowReclassRearmKey)
	}
	if err := d.RunFlowReclassStep(setForTest, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, ok := d.GetSettingValue(FlowReclassRearmKey); !ok || got != newer {
		t.Errorf("mark after consumption = %q (%v), want the newer mark %q to survive", got, ok, newer)
	}
}

// TestReclassVerify_ChunkedCountAcrossRanges: the locked count runs in id
// ranges; the count, lowest and highest old-revision ids must span them all —
// the re-pass starts from the lowest.
func TestReclassVerify_ChunkedCountAcrossRanges(t *testing.T) {
	d := reclassFixture(t) // verification range 5
	for _, r := range []struct {
		id  uint
		rev uint16
	}{{3, 1}, {12, 0}, {27, 1}, {41, 0}, {44, 0}, {58, 1}} {
		if err := d.Gorm().Create(&models.FlowRollup{ID: r.id, ClassRev: r.rev, Timestamp: time.Now().Add(-48 * time.Hour),
			DeviceID: 1, IntervalType: "1h", Protocol: 6, SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443}).Error; err != nil {
			t.Fatal(err)
		}
	}
	res, err := d.reclassVerify(reclassTableRollups, 0, 1, "300s")
	if err != nil {
		t.Fatal(err)
	}
	if !res.acquired || res.count != 3 || res.minID != 12 || res.maxID != 44 || res.tableMax != 58 {
		t.Errorf("verify = %+v, want count 3, min 12, max 44, table max 58", res)
	}
	if res, _ := d.reclassVerify(reclassTableRollups, 20, 1, "300s"); res.count != 2 || res.minID != 41 {
		t.Errorf("verify above floor 20 = %+v, want count 2 from id 41", res)
	}
}

// TestFlowReclass_FullRunWithNoRollupsStillRequestsTheRebuild: the first run
// on an install whose flow_rollups held no old-revision row (empty at the
// time) re-stamps nothing there, so no earliest rollup timestamp exists. It
// used to post no summary rebuild request — and the service-port boundary
// (flow_summary_service_since) is cleared only once the rebuild has marked
// both tiers done for the revision, so it never cleared. The run now requests
// the rebuild from its own start, which finishes trivially.
func TestFlowReclass_FullRunWithNoRollupsStillRequestsTheRebuild(t *testing.T) {
	d := reclassFixture(t)
	base := time.Now().Add(-30 * time.Minute)
	for i := 0; i < 4; i++ {
		if err := d.Gorm().Create(&models.FlowSample{
			Timestamp: base, DeviceID: 1, Protocol: 6,
			SrcAddr: "198.19.9.156", DstAddr: "198.51.100.7", SrcPort: 443, DstPort: uint16(50000 + i),
			Bytes: 100, Packets: 1, Direction: classify.DirExternal,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Gorm().Create(&models.SystemSetting{Key: flowSummaryServiceSinceKey, Value: time.Now().UTC().Format(time.RFC3339)}).Error; err != nil {
		t.Fatal(err)
	}
	runReclassToDone(t, d, 20)

	raw, ok := d.GetSettingValue(flowSummaryRecomputeRequestKey)
	if !ok || raw == "" {
		t.Fatal("a full run that re-stamped no rollup posted no summary rebuild request; the service boundary would never clear")
	}
	req, ok := parseRecomputeMark(raw)
	if !ok || req.rev != 1 {
		t.Fatalf("request %q, want revision 1", raw)
	}
	// The rebuild has nothing to do and clears the boundary.
	for i := 0; i < 6; i++ {
		d.RunFlowSummaryCycle()
	}
	if _, held := d.GetSettingValue(flowSummaryServiceSinceKey); held {
		t.Error("the service-port boundary is still set after the rebuild")
	}
}
