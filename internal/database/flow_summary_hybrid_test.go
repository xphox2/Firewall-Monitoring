package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// The hybrid read (flow_summary_hybrid.go). The measure of correctness
// throughout is the live read: for the same data, a hybrid response must be
// the live response — every panel, every flag — and a refused request must be
// the live read itself.

// hybridFixture is 31 hours of 5-minute rollups, the newest hour being the one
// two hours before the current hour, with the summary built over them.
type hybridFixture struct {
	d *Database
	// newest is the hour of the newest rollup row; hour(n) is n hours before it.
	newest time.Time
	// probe owns device 1 (and not device 2).
	probe uint
}

func (f hybridFixture) hour(back int) time.Time {
	return f.newest.Add(-time.Duration(back) * time.Hour)
}

// hybridRow is one rollup row in the given hour. Rows differ by slot so that
// every 5-minute position is filled — including minute 0, the row stamped
// exactly on an hour boundary, which is the row an off-by-one bound loses or
// counts twice.
func hybridRow(hour time.Time, slot int, device uint, bytes uint64) models.FlowRollup {
	countries := []string{"US", "DE", "FR"}
	return models.FlowRollup{
		Timestamp: hour.Add(time.Duration(slot) * 5 * time.Minute), DeviceID: device, IntervalType: "5m",
		SrcAddr: fmt.Sprintf("10.0.%d.%d", device, slot%5+1), DstAddr: fmt.Sprintf("192.0.2.%d", slot%7+1),
		DstPort: uint16(443 + slot%3), ServicePort: uint16(443 + slot%3), Protocol: uint8(6 + 11*(slot%2)),
		AppCategory: uint8(1 + slot%3), Direction: uint8(1 + slot%2), DstCountry: countries[slot%3],
		DstASN: uint32(64500 + slot%4), ScopeLocal: slot%6 == 5,
		BytesSum: bytes, PacketsSum: bytes / 100, FlowCount: 1 + int64(slot%2), SamplingRateAvg: float64(1 + slot%2*1023),
	}
}

func newHybridFixture(t *testing.T, d *Database) hybridFixture {
	t.Helper()
	f := hybridFixture{d: d, newest: time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)}
	var rows []models.FlowRollup
	for back := 30; back >= 0; back-- {
		for slot := 0; slot < 12; slot++ {
			for device := uint(1); device <= 2; device++ {
				r := hybridRow(f.hour(back), slot, device, uint64(1000*(back+1)+100*slot+int(device)))
				if back == 5 && slot == 3 && device == 1 {
					// A sampling rate found nowhere else, in an hour that is
					// always in the middle: the window's range is right only
					// if the middle's own sampling panel ran.
					r.SamplingRateAvg = 4096
				}
				rows = append(rows, r)
			}
		}
	}
	if err := d.Gorm().CreateInBatches(&rows, 200).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Devices 1 and 2, the first owned by probe 1, so a probe filter selects
	// exactly device 1's rows.
	site := models.Site{Name: "hybrid-site"}
	if err := d.Gorm().Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	probe := models.Probe{Name: "hybrid-probe", RegistrationKey: "hybrid-probe-key", SiteID: site.ID}
	if err := d.Gorm().Create(&probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	one := probe.ID
	f.probe = probe.ID
	for i, probe := range []*uint{&one, nil} {
		dev := models.Device{Name: fmt.Sprintf("hybrid-%d", i+1), IPAddress: fmt.Sprintf("192.0.2.%d", 201+i), Vendor: "fortigate", ProbeID: probe}
		if err := d.Gorm().Create(&dev).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
		if dev.ID != uint(i+1) {
			t.Fatalf("precondition: seeded device got id %d, want %d", dev.ID, i+1)
		}
	}
	f.build(t)
	return f
}

// build runs the summariser until the hourly tier has caught up.
func (f hybridFixture) build(t *testing.T) {
	t.Helper()
	for i := 0; i < 5; i++ {
		f.d.RunFlowSummaryCycle()
	}
	if !f.d.summaryBackfillComplete() {
		t.Fatal("precondition: the summary did not finish building")
	}
}

// useHybridKnobs restores every package-level knob and hook these tests move,
// and FREEZES the request clock for the test.
//
// Every comparison here reads the same window twice. Each read takes its
// cutoff from the clock, and the fixture has a row on every 5-minute stamp —
// so with a running clock, a 5-minute mark passing between the two reads puts
// one row in the first window and not the second, and the comparison fails
// for a reason that has nothing to do with the code.
func useHybridKnobs(t *testing.T) {
	t.Helper()
	enabled, tail, chunk, topN := flowHybridEnabled, flowHybridMaxTail, flowSummaryDirtyScanChunk, flowSummaryTopN
	clock, frozen := flowStatsNow, time.Now().UTC()
	flowStatsNow = func() time.Time { return frozen }
	// And pins the process zone to UTC. SQLite compares timestamps as text,
	// and the summariser cuts its buckets with UTC bounds, so on SQLite the
	// summary — and therefore anything compared against it — is only right
	// in UTC. That is a property of the unit lane, which CI runs in UTC, not
	// of PostgreSQL, which compares instants; without the pin these tests
	// would fail on a laptop east of Greenwich for a reason that is not theirs.
	zone := time.Local
	time.Local = time.UTC
	t.Cleanup(func() {
		time.Local = zone
		flowStatsNow = clock
		flowHybridEnabled, flowHybridMaxTail, flowSummaryDirtyScanChunk, flowSummaryTopN = enabled, tail, chunk, topN
		flowStatsBeforeRawHook, flowHybridPlanHook, flowStatsJobHook = nil, nil, nil
		flowSummarySettingsHook, flowSummaryBucketHook = nil, nil
	})
}

// statsJSON is a response with the two fields that NAME the read removed, so
// two reads of the same data can be compared whole.
func statsJSON(t *testing.T, res *FlowStatsResult) string {
	t.Helper()
	c := *res
	c.ServedFrom, c.SummaryBypassReason = "", ""
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// liveStats is the live read of the window: the hybrid read switched off.
func liveStats(t *testing.T, d *Database, hours int, filter FlowStatsFilter) *FlowStatsResult {
	t.Helper()
	was := flowHybridEnabled
	flowHybridEnabled = false
	defer func() { flowHybridEnabled = was }()
	res, err := d.GetFlowStats(hours, filter)
	if err != nil {
		t.Fatalf("live GetFlowStats: %v", err)
	}
	if res.ServedFrom != FlowServedLive || res.SummaryBypassReason != "" {
		t.Fatalf("precondition: the reference read was served from %q (%q), want a plain live read", res.ServedFrom, res.SummaryBypassReason)
	}
	return res
}

// assertHybridEqualsLive runs the window both ways and requires the hybrid
// read to have SERVED it (an always-refusing reader would otherwise pass every
// equality here) and to match the live read in every panel and flag.
func assertHybridEqualsLive(t *testing.T, d *Database, hours int, filter FlowStatsFilter, when string) *FlowStatsResult {
	t.Helper()
	got, err := d.GetFlowStats(hours, filter)
	if err != nil {
		t.Fatalf("%s: GetFlowStats: %v", when, err)
	}
	if got.ServedFrom != FlowServedHybrid {
		t.Fatalf("%s: served from %q (%q), want hybrid", when, got.ServedFrom, got.SummaryBypassReason)
	}
	want := liveStats(t, d, hours, filter)
	if g, w := statsJSON(t, got), statsJSON(t, want); g != w {
		t.Fatalf("%s: hybrid differs from live:\nlive:   %s\nhybrid: %s", when, w, g)
	}
	if got.TotalBytes == 0 || len(got.TopSources) == 0 || len(got.BytesOverTime) == 0 {
		t.Fatalf("%s: the window is empty, so the comparison proves nothing", when)
	}
	if got.SamplingRateMax != 4096 {
		// Only for windows that reach the fixture's marked middle hour.
		if hours >= 12 && filter.DeviceID != 2 {
			t.Fatalf("%s: sampling range tops out at %v, want the middle hour's 4096", when, got.SamplingRateMax)
		}
	}
	return got
}

// assertRefused requires the request to have been read live for the given
// reason, and to equal the plain live read.
func assertRefused(t *testing.T, d *Database, hours int, reason, when string) {
	t.Helper()
	got, err := d.GetFlowStats(hours, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("%s: GetFlowStats: %v", when, err)
	}
	if got.ServedFrom != FlowServedLive || got.SummaryBypassReason != reason {
		t.Fatalf("%s: served from %q with reason %q, want live with %q", when, got.ServedFrom, got.SummaryBypassReason, reason)
	}
	if g, w := statsJSON(t, got), statsJSON(t, liveStats(t, d, hours, FlowStatsFilter{})); g != w {
		t.Fatalf("%s: a refused request differs from the live read:\nlive:    %s\nrefused: %s", when, w, g)
	}
}

// TestFlowHybrid_EqualsLive: several windows and filters, with a row on every
// 5-minute position of every hour (so both the head/middle and middle/tail
// boundaries have a row stamped exactly on them), two devices, and a daily
// summary row planted inside the window that the hourly-only middle must not
// read.
func TestFlowHybrid_EqualsLive(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	f := newHybridFixture(t, d)
	// A coarser copy of traffic the hourly rows already hold, stamped inside
	// the middle of every window below (a real daily row sits at midnight;
	// what matters here is only that the middle does not read the tier).
	if err := d.Gorm().Create(&models.FlowSummary{Timestamp: f.hour(5), IntervalType: "1d",
		DeviceID: 1, Protocol: 6, BytesSum: 987654321, PacketsSum: 1, FlowCount: 1}).Error; err != nil {
		t.Fatalf("plant daily row: %v", err)
	}

	for _, hours := range []int{7, 12, 24, 30} {
		assertHybridEqualsLive(t, d, hours, FlowStatsFilter{}, fmt.Sprintf("%d h", hours))
	}
	assertHybridEqualsLive(t, d, 24, FlowStatsFilter{DeviceID: 2}, "24 h, one device")
	// Device 1 belongs to probe 1; device 2 to none.
	one := assertHybridEqualsLive(t, d, 24, FlowStatsFilter{ProbeID: f.probe}, "24 h, one probe")
	if all := liveStats(t, d, 24, FlowStatsFilter{}); one.TotalBytes == 0 || one.TotalBytes >= all.TotalBytes {
		t.Fatalf("the probe filter selected %d of %d bytes: it does not narrow the window", one.TotalBytes, all.TotalBytes)
	}
}

// TestFlowHybrid_UnsummarisedRowsComeFromTheTail: rows the summariser has not
// folded in yet — in the newest hour and two hours back — are read from the
// rollup rows themselves. This is the gap the plain summary read has between
// a rollup cycle's commit and the next summary pass.
func TestFlowHybrid_UnsummarisedRowsComeFromTheTail(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	f := newHybridFixture(t, d)
	before := liveStats(t, d, 24, FlowStatsFilter{}).TotalBytes

	// The third row is unsummarised too, but 28 hours back — outside the
	// window. It must not drag the tail back (and so refuse the request).
	late := []models.FlowRollup{hybridRow(f.hour(0), 7, 1, 5_000_000), hybridRow(f.hour(2), 3, 2, 7_000_000),
		hybridRow(f.hour(28), 3, 2, 11_000_000)}
	if err := d.Gorm().Create(&late).Error; err != nil {
		t.Fatal(err)
	}
	got := assertHybridEqualsLive(t, d, 24, FlowStatsFilter{}, "with rows the summary has not seen")
	if got.TotalBytes != before+12_000_000 {
		t.Fatalf("total = %d, want %d: the unsummarised rows were not counted once each", got.TotalBytes, before+12_000_000)
	}
}

// TestFlowHybrid_HeldWatermarkKeepsTheBucketInTheTail: a bucket the summariser
// FAILED to rebuild holds the watermark, so its rows stay above it and the
// tail keeps reading that hour live. Had the watermark advanced, the stale
// bucket would be served from the middle.
func TestFlowHybrid_HeldWatermarkKeepsTheBucketInTheTail(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	f := newHybridFixture(t, d)
	bad := f.hour(1)
	if err := d.Gorm().Create(&[]models.FlowRollup{hybridRow(bad, 4, 1, 9_000_000)}).Error; err != nil {
		t.Fatal(err)
	}
	flowSummaryBucketHook = func(interval string, b time.Time) error {
		if interval == "1h" && b.Equal(bad) {
			return errors.New("poison bucket")
		}
		return nil
	}
	d.RunFlowSummaryCycle()
	flowSummaryBucketHook = nil
	if want, got := summaryBucketBytes(d, bad); got == want {
		t.Fatal("precondition: the failed bucket was rebuilt anyway")
	}
	assertHybridEqualsLive(t, d, 24, FlowStatsFilter{}, "with a bucket the summariser failed on")
}

// TestFlowHybrid_PlansAfterTheRawRead: a rollup cycle that commits while the
// request is running moves rows into an hour the summary has already built.
// The plan is made after the raw read, so it sees those rows above the
// watermark and reads their hour from the tail. A plan made when the request
// is set up — before the hook, which fires just ahead of the first query —
// would have put that hour in the middle and the rows would be in no source
// at all. (What this cannot tell apart is a plan made between the hook and
// the last raw read; the code makes it in flushRollups, after all of them.)
func TestFlowHybrid_PlansAfterTheRawRead(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	f := newHybridFixture(t, d)
	before := liveStats(t, d, 24, FlowStatsFilter{}).TotalBytes

	fired := 0
	flowStatsBeforeRawHook = func() {
		if fired++; fired > 1 {
			return
		}
		if err := d.Gorm().Create(&[]models.FlowRollup{hybridRow(f.hour(2), 9, 1, 3_000_000)}).Error; err != nil {
			t.Errorf("commit during the request: %v", err)
		}
	}
	got, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got.ServedFrom != FlowServedHybrid {
		t.Fatalf("served from %q (%q), want hybrid", got.ServedFrom, got.SummaryBypassReason)
	}
	if got.TotalBytes != before+3_000_000 {
		t.Fatalf("total = %d, want %d: the row committed during the request is missing", got.TotalBytes, before+3_000_000)
	}
}

// TestFlowHybrid_Refusals: every reason the plan has for not trusting the
// summary, each ending in the live read.
func TestFlowHybrid_Refusals(t *testing.T) {
	set := func(t *testing.T, d *Database, key, value string) {
		t.Helper()
		if err := d.UpsertSetting(&models.SystemSetting{Key: key, Value: value, Category: "system", Type: "string"}); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		reason string
		break_ func(t *testing.T, f hybridFixture)
	}{
		{"a row the summary has not seen, ten hours back", flowHybridRefusedTail, func(t *testing.T, f hybridFixture) {
			if err := f.d.Gorm().Create(&[]models.FlowRollup{hybridRow(f.hour(10), 2, 1, 1_000_000)}).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{"more unsummarised ids than one scan piece", flowHybridRefusedBacklog, func(t *testing.T, f hybridFixture) {
			var rows []models.FlowRollup
			for i := 0; i < 5; i++ {
				rows = append(rows, hybridRow(f.hour(0), i, 1, 1000))
			}
			if err := f.d.Gorm().Create(&rows).Error; err != nil {
				t.Fatal(err)
			}
			flowSummaryDirtyScanChunk = 3
		}},
		{"a fill marker short of the middle", flowHybridRefusedNotBuilt, func(t *testing.T, f hybridFixture) {
			f.d.setSummaryFillMarker("1h", f.hour(12))
		}},
		{"a blank fill marker", flowHybridRefusedNotBuilt, func(t *testing.T, f hybridFixture) {
			f.d.clearSummaryFillMarker("1h")
		}},
		{"no watermark", flowHybridRefusedNotBuilt, func(t *testing.T, f hybridFixture) {
			set(t, f.d, flowSummaryWatermarkKeyPrefix+"1h", "0")
		}},
		{"settings that cannot be read", flowHybridRefusedSettings, func(t *testing.T, f hybridFixture) {
			flowSummarySettingsHook = func(keys []string) error {
				if settingKeyIn(keys, FlowSummaryRetentionKey) { // the plan's read, not the summariser's
					return errors.New("connection reset")
				}
				return nil
			}
		}},
		{"a watermark that does not parse", flowHybridRefusedSettings, func(t *testing.T, f hybridFixture) {
			set(t, f.d, flowSummaryWatermarkKeyPrefix+"1h", "12x")
		}},
		{"a plan query that fails", flowHybridRefusedProbe, func(t *testing.T, f hybridFixture) {
			flowHybridPlanHook = func() error { return errors.New("canceling statement due to statement timeout") }
		}},
		{"a reclassification in progress", flowHybridRefusedRebuild, func(t *testing.T, f hybridFixture) {
			set(t, f.d, flowReclassStateKey, `{"rev":3}`)
		}},
		{"a recompute requested", flowHybridRefusedRebuild, func(t *testing.T, f hybridFixture) {
			set(t, f.d, flowSummaryRecomputeRequestKey, "3|2026-01-01T00:00:00Z")
		}},
		{"a recompute walking the hourly tier", flowHybridRefusedRebuild, func(t *testing.T, f hybridFixture) {
			set(t, f.d, recomputeCursorKey("1h"), "3|2026-01-01T00:00:00Z")
		}},
		{"recompute buckets waiting to be retried", flowHybridRefusedRebuild, func(t *testing.T, f hybridFixture) {
			set(t, f.d, recomputeRetryKey("1h"), "2026-01-01T00:00:00Z")
		}},
		{"summary retention of one day", flowHybridRefusedRetention, func(t *testing.T, f hybridFixture) {
			set(t, f.d, FlowSummaryRetentionKey, "1")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			useHybridKnobs(t)
			f := newHybridFixture(t, d)
			c.break_(t, f)
			assertRefused(t, d, 24, c.reason, c.name)
		})
	}
}

// TestFlowHybrid_RollupsThatDoNotReachTheWindow: when the 5-minute tier ends
// before the window's head hour does, there is no tail to speak of — a tail
// starting at the newest rollup hour would begin before the cutoff, or lie on
// top of the head and count it twice.
func TestFlowHybrid_RollupsThatDoNotReachTheWindow(t *testing.T) {
	for _, c := range []struct {
		name   string
		newest func(headHour time.Time) time.Time // the newest rollup row, given the hour the cutoff falls in
	}{
		{"newest rollup before the cutoff", func(head time.Time) time.Time { return head.Add(-2 * time.Hour) }},
		{"newest rollup inside the head hour", func(head time.Time) time.Time { return head.Add(55 * time.Minute) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := NewDatabaseForTesting(t)
			useHybridKnobs(t)
			newest := c.newest(time.Now().UTC().Add(-7 * time.Hour).Truncate(time.Hour))
			var rows []models.FlowRollup
			for i := 0; i < 40; i++ { // 40 five-minute rows ending at `newest`
				ts := newest.Add(-time.Duration(i) * 5 * time.Minute)
				r := hybridRow(ts.Truncate(time.Hour), int(ts.Sub(ts.Truncate(time.Hour))/(5*time.Minute)), 1, uint64(1000+i))
				rows = append(rows, r)
			}
			if err := d.Gorm().Create(&rows).Error; err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 5; i++ {
				d.RunFlowSummaryCycle()
			}
			assertRefused(t, d, 7, flowHybridRefusedNoRollups, c.name)
		})
	}
}

// TestFlowHybrid_KeysThatOutliveARunDoNotRefuse: the reclassification's
// status and done-markers stay in the settings table for good. Gating on any
// of them would switch the hybrid read off permanently after the first run.
// And default retention (a year) is not "short".
func TestFlowHybrid_KeysThatOutliveARunDoNotRefuse(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	newHybridFixture(t, d)
	for key, value := range map[string]string{
		"flow_reclass_status":                `{"phase":"done"}`,
		"flow_reclass_done_rev":              "3",
		flowSummaryRecomputeStatusKey:        `{"rev":3}`,
		recomputeDoneKey("1h"):               "3",
		FlowSummaryRetentionKey:              "365",
		recomputeCursorKey("1d"):             "3|2026-01-01T00:00:00Z", // the DAILY tier's walk is not this window's concern
		flowSummaryWatermarkKeyPrefix + "1d": "1",
	} {
		if err := d.UpsertSetting(&models.SystemSetting{Key: key, Value: value, Category: "system", Type: "string"}); err != nil {
			t.Fatal(err)
		}
	}
	assertHybridEqualsLive(t, d, 24, FlowStatsFilter{}, "with the keys a finished run leaves behind")
}

// TestFlowHybridEligible: which requests may use the hybrid read at all.
func TestFlowHybridEligible(t *testing.T) {
	useHybridKnobs(t)
	proto := uint8(6)
	for _, c := range []struct {
		hours  int
		filter FlowStatsFilter
		want   bool
	}{
		{1, FlowStatsFilter{}, false},
		{6, FlowStatsFilter{}, false}, // 5-minute chart buckets
		{7, FlowStatsFilter{}, true},
		{24, FlowStatsFilter{}, true},
		{48, FlowStatsFilter{}, true},
		{49, FlowStatsFilter{}, false}, // the window reaches the hourly rollup tier: the summary read's
		{168, FlowStatsFilter{}, false},
		{24, FlowStatsFilter{DeviceID: 3}, true},
		{24, FlowStatsFilter{SiteID: 3}, true},
		{24, FlowStatsFilter{Protocol: &proto}, false}, // a cube dimension: top-N lists cannot honour it
		{24, FlowStatsFilter{SrcAddr: "10.0.0.1"}, false},
	} {
		if got := flowHybridEligible(c.hours, c.filter); got != c.want {
			t.Errorf("eligible(%d h, %+v) = %v, want %v", c.hours, c.filter, got, c.want)
		}
	}
	// Never eligible where the live read would use more than the 5-minute
	// tier — asked of the function that owns that boundary, at every width.
	for hours := 1; hours <= 24*100; hours++ {
		tiers := rollupIntervalsForWindow(hours)
		if flowHybridEligible(hours, FlowStatsFilter{}) && (len(tiers) != 1 || tiers[0] != "5m") {
			t.Fatalf("%d h is hybrid-eligible but the live read uses tiers %v", hours, tiers)
		}
	}
	flowHybridEnabled = false
	if flowHybridEligible(24, FlowStatsFilter{}) {
		t.Error("eligible with the hybrid read switched off")
	}
}

// TestFlowHybrid_ARefusedRequestIsTheLiveRead in the two respects equality of
// the response does not show: it reads the raw samples ONCE (a refusal is not
// a second attempt, which would spend a second budget), and it reports the
// same number of progress steps (so no hybrid-only panel ran). The response
// itself is compared with a service boundary inside the window, which badges
// Top services on the live read and must do exactly that here.
func TestFlowHybrid_ARefusedRequestIsTheLiveRead(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	f := newHybridFixture(t, d)
	if err := d.UpsertSetting(&models.SystemSetting{Key: flowSummaryServiceSinceKey, Value: f.hour(5).Format(time.RFC3339), Category: "system", Type: "string"}); err != nil {
		t.Fatal(err)
	}
	steps := func(hybrid bool) (int, *FlowStatsResult) {
		t.Helper()
		was := flowHybridEnabled
		flowHybridEnabled = hybrid
		defer func() { flowHybridEnabled = was }()
		n := 0
		res, err := d.GetFlowStatsOpts(24, FlowStatsFilter{}, FlowStatsOptions{Progress: func(FlowStatsProgress) { n++ }})
		if err != nil {
			t.Fatal(err)
		}
		return n, res
	}
	liveSteps, live := steps(false)
	if len(live.PartialBlocks) == 0 {
		t.Fatal("precondition: the service boundary did not badge a panel on the live read")
	}

	rawReads := 0
	flowStatsBeforeRawHook = func() { rawReads++ }
	flowHybridPlanHook = func() error { return errors.New("statement timeout") }
	refusedSteps, refused := steps(true)
	if refused.ServedFrom != FlowServedLive || refused.SummaryBypassReason != flowHybridRefusedProbe {
		t.Fatalf("precondition: not refused (%q, %q)", refused.ServedFrom, refused.SummaryBypassReason)
	}
	if rawReads != 1 {
		t.Fatalf("a refused request read the raw samples %d times, want once", rawReads)
	}
	if refusedSteps != liveSteps {
		t.Fatalf("a refused request reported %d progress steps against the live read's %d", refusedSteps, liveSteps)
	}
	if g, w := statsJSON(t, refused), statsJSON(t, live); g != w {
		t.Fatalf("a refused request differs from the live read:\nlive:    %s\nrefused: %s", w, g)
	}

	// And served: the hybrid read badges the same panel and runs one more
	// step, the middle's sampling range.
	flowHybridPlanHook = nil
	servedSteps, served := steps(true)
	if served.ServedFrom != FlowServedHybrid || servedSteps != liveSteps+1 {
		t.Fatalf("served from %q with %d steps, want hybrid with %d", served.ServedFrom, servedSteps, liveSteps+1)
	}
	if g, w := statsJSON(t, served), statsJSON(t, live); g != w {
		t.Fatalf("hybrid differs from live with a service boundary in the window:\nlive:   %s\nhybrid: %s", w, g)
	}
}

// TestFlowHybrid_UniqueTileFailureIsPartialNotDegraded: the unique-address
// scans are the only full-window scans the hybrid read keeps, so they are the
// likeliest thing on the page to run out of time. On a hybrid response that
// costs their own tile; it must not put the "partial result" banner over a
// page whose other panels are complete. On the live read nothing changes.
func TestFlowHybrid_UniqueTileFailureIsPartialNotDegraded(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	newHybridFixture(t, d)
	flowStatsJobHook = func(block string) error {
		if block == "unique_src_addr" {
			return errors.New("canceling statement due to statement timeout")
		}
		return nil
	}
	got, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got.ServedFrom != FlowServedHybrid {
		t.Fatalf("served from %q (%q), want hybrid", got.ServedFrom, got.SummaryBypassReason)
	}
	if got.Degraded || len(got.DegradedBlocks) != 0 {
		t.Fatalf("a failed unique tile degraded the page: %v", got.DegradedBlocks)
	}
	if got.PartialReasons["unique_src_addr"] != flowPartialTimedOut {
		t.Fatalf("the tile is not marked partial: blocks %v reasons %v", got.PartialBlocks, got.PartialReasons)
	}
	if got.UniqueDests == 0 || got.TotalBytes == 0 {
		t.Fatal("the other panels did not complete")
	}

	flowHybridEnabled = false
	live, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if !live.Degraded {
		t.Fatal("on the live read a failed unique scan no longer degrades the page")
	}
}

// TestFlowHybrid_TopNStaysWithinTheBound: with the per-bucket lists cut to two
// entries the merge is visibly lossy, and it must still be the documented kind
// of lossy — every key it shows is a real one and is never shown above its
// true total. (How far BELOW it may fall — the sum of the middle buckets' cut
// values — is the summary read's existing bound and is not re-measured here.)
// The edges contribute exact totals, so a value that lives only at an edge is
// exact.
func TestFlowHybrid_TopNStaysWithinTheBound(t *testing.T) {
	d := NewDatabaseForTesting(t)
	useHybridKnobs(t)
	flowSummaryTopN = 2
	f := newHybridFixture(t, d)
	// One source that exists only in the newest hour, larger than anything.
	edgeOnly := hybridRow(f.hour(0), 1, 1, 900_000_000)
	edgeOnly.SrcAddr = "10.9.9.9"
	if err := d.Gorm().Create(&[]models.FlowRollup{edgeOnly}).Error; err != nil {
		t.Fatal(err)
	}

	got, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got.ServedFrom != FlowServedHybrid {
		t.Fatalf("served from %q (%q), want hybrid", got.ServedFrom, got.SummaryBypassReason)
	}
	// The true totals, with no cut anywhere.
	cutoff := flowStatsNow().Add(-24 * time.Hour)
	var truth []struct {
		SrcAddr string
		Total   int64
	}
	if err := d.Gorm().Model(&models.FlowRollup{}).Where("timestamp > ? AND scope_local = ?", cutoff, false).
		Select("src_addr, SUM(bytes_sum) as total").Group("src_addr").Scan(&truth).Error; err != nil {
		t.Fatal(err)
	}
	trueTotal := map[string]int64{}
	for _, r := range truth {
		trueTotal[r.SrcAddr] = r.Total
	}
	if len(got.TopSources) == 0 {
		t.Fatal("no top sources")
	}
	for _, kc := range got.TopSources {
		want, real := trueTotal[kc.Key]
		if !real {
			t.Errorf("top source %q does not exist in the window", kc.Key)
		}
		if kc.Count > want {
			t.Errorf("top source %q shown at %d, above its true total %d", kc.Key, kc.Count, want)
		}
	}
	if top := got.TopSources[0]; top.Key != "10.9.9.9" || top.Count != trueTotal["10.9.9.9"] {
		t.Fatalf("the edge-only source is %q at %d, want 10.9.9.9 at exactly %d", top.Key, top.Count, trueTotal["10.9.9.9"])
	}
	// Totals are not a top-N: they stay exact whatever the cut.
	if live := liveStats(t, d, 24, FlowStatsFilter{}); got.TotalBytes != live.TotalBytes || got.TotalFlows != live.TotalFlows {
		t.Fatalf("totals differ under a top-N cut: %d/%d against %d/%d", got.TotalBytes, got.TotalFlows, live.TotalBytes, live.TotalFlows)
	}
}
