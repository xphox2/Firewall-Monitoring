package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// seedReadPath lays down rolled-up traffic across several hours for one device,
// mixing scope-local and routed flows, two protocols, two countries and enough
// distinct addresses that the top-N panels have something to rank.
func seedReadPath(t *testing.T, d *Database, base time.Time) {
	t.Helper()
	var rows []models.FlowRollup
	for h := 0; h < 6; h++ {
		ts := base.Add(time.Duration(h)*time.Hour + 5*time.Minute)
		rows = append(rows,
			models.FlowRollup{
				Timestamp: ts, DeviceID: 1, IntervalType: "5m",
				SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
				AppCategory: 1, Direction: 1, DstCountry: "US", DstASN: 15169,
				BytesSum: uint64(1000 * (h + 1)), PacketsSum: 10, FlowCount: 2, SamplingRateAvg: 1,
			},
			models.FlowRollup{
				Timestamp: ts, DeviceID: 1, IntervalType: "5m",
				SrcAddr: "10.0.0.2", DstAddr: "1.1.1.1", DstPort: 53, Protocol: 17,
				AppCategory: 2, Direction: 1, DstCountry: "DE", DstASN: 13335,
				BytesSum: 500, PacketsSum: 5, FlowCount: 1, SamplingRateAvg: 1024,
			},
			models.FlowRollup{
				Timestamp: ts, DeviceID: 1, IntervalType: "5m",
				SrcAddr: "169.254.0.1", DstAddr: "224.0.0.1", DstPort: 0, Protocol: 2,
				ScopeLocal: true,
				BytesSum:   300, PacketsSum: 3, FlowCount: 1, SamplingRateAvg: 1,
			},
		)
	}
	if err := d.Gorm().Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// statsBothWays runs the same window through the summary and the live path.
func statsBothWays(t *testing.T, d *Database, hours int, filter FlowStatsFilter) (summary, live *FlowStatsResult) {
	t.Helper()
	orig := flowSummaryMinHours

	flowSummaryMinHours = 1 // any window qualifies
	s, err := d.GetFlowStats(hours, filter)
	if err != nil {
		t.Fatalf("GetFlowStats via summary: %v", err)
	}

	flowSummaryMinHours = 1 << 30 // no window qualifies
	l, err := d.GetFlowStats(hours, filter)
	if err != nil {
		t.Fatalf("GetFlowStats via live path: %v", err)
	}

	flowSummaryMinHours = orig
	return s, l
}

// TestFlowSummaryRead_AgreesWithTheLivePath is the acceptance test for the whole
// read path. The summary is only worth having if it answers the same question:
// a faster wrong number is worse than a slow right one, and this page has
// already shipped both.
//
// Totals must be EXACT. Only the top-N lists may differ, and only by the
// per-bucket merge bound — on data this small they should not differ at all.
func TestFlowSummaryRead_AgreesWithTheLivePath(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	seedReadPath(t, d, base)
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}

	summary, live := statsBothWays(t, d, 24, FlowStatsFilter{})

	// The unique-address panels ARE expected to degrade: summing per-bucket
	// distinct counts is a different quantity, not an approximation of the union,
	// so the summary declines to publish them. Nothing else may degrade.
	for _, b := range summary.DegradedBlocks {
		if b != "unique_src_addr" && b != "unique_dst_addr" {
			t.Fatalf("the summary path degraded %q; only the unique-address panels should (%v)",
				b, summary.DegradedBlocks)
		}
	}
	if summary.TotalBytes != live.TotalBytes {
		t.Errorf("TotalBytes: summary %d, live %d", summary.TotalBytes, live.TotalBytes)
	}
	if summary.TotalPackets != live.TotalPackets {
		t.Errorf("TotalPackets: summary %d, live %d", summary.TotalPackets, live.TotalPackets)
	}
	if summary.TotalFlows != live.TotalFlows {
		t.Errorf("TotalFlows: summary %d, live %d", summary.TotalFlows, live.TotalFlows)
	}
	if summary.LocalTraffic.Bytes != live.LocalTraffic.Bytes {
		t.Errorf("LocalTraffic.Bytes: summary %d, live %d",
			summary.LocalTraffic.Bytes, live.LocalTraffic.Bytes)
	}
	if summary.BitsPerSecond != live.BitsPerSecond {
		t.Errorf("BitsPerSecond: summary %v, live %v", summary.BitsPerSecond, live.BitsPerSecond)
	}
	if summary.SamplingRateMax != live.SamplingRateMax {
		t.Errorf("SamplingRateMax: summary %v, live %v (the cube has no sampling column, so this "+
			"comes from the per-bucket table)", summary.SamplingRateMax, live.SamplingRateMax)
	}
	if live.TotalBytes == 0 {
		t.Fatal("the seed produced no bytes; the comparison proves nothing")
	}

	// SYMMETRIC on purpose. An earlier version only looked up the live keys in
	// the summary map, so a summary list containing extra or invented entries
	// compared equal — a mutation that appended a bogus key to every summary
	// panel passed the whole suite.
	sameKeys := func(name string, summaryList, liveList []KeyCount) {
		t.Helper()
		sm := map[string]int64{}
		for _, k := range summaryList {
			sm[k.Key] = k.Count
		}
		lm := map[string]int64{}
		for _, k := range liveList {
			lm[k.Key] = k.Count
		}
		for k, v := range lm {
			if sm[k] != v {
				t.Errorf("%s[%q]: summary %d, live %d", name, k, sm[k], v)
			}
		}
		for k, v := range sm {
			if _, ok := lm[k]; !ok {
				t.Errorf("%s[%q]=%d is in the summary but not the live result", name, k, v)
			}
		}
	}
	sameKeys("ByProtocol", summary.ByProtocol, live.ByProtocol)
	sameKeys("ByCategory", summary.ByCategory, live.ByCategory)
	sameKeys("ByDirection", summary.ByDirection, live.ByDirection)
	sameKeys("TopCountries", summary.TopCountries, live.TopCountries)
	sameKeys("TopSources", summary.TopSources, live.TopSources)
	sameKeys("TopDestinations", summary.TopDestinations, live.TopDestinations)
	sameKeys("TopPorts", summary.TopPorts, live.TopPorts)
	sameKeys("TopASNs", summary.TopASNs, live.TopASNs)

	if len(summary.TopConversations) == 0 {
		t.Error("TopConversations is empty on the summary path")
	} else if len(live.TopConversations) > 0 {
		s0, l0 := summary.TopConversations[0], live.TopConversations[0]
		if s0.SrcAddr != l0.SrcAddr || s0.DstAddr != l0.DstAddr || s0.DstPort != l0.DstPort || s0.Bytes != l0.Bytes {
			t.Errorf("top conversation differs: summary %s->%s:%d (%d bytes), live %s->%s:%d (%d bytes)",
				s0.SrcAddr, s0.DstAddr, s0.DstPort, s0.Bytes, l0.SrcAddr, l0.DstAddr, l0.DstPort, l0.Bytes)
		}
	}
}

// TestFlowSummaryRead_HonoursCubeDimensionFilters pins the reason the cube keeps
// the full cross product rather than one row per dimension: any COMBINATION of
// those columns must still be answerable, including the protocol pill row.
func TestFlowSummaryRead_HonoursCubeDimensionFilters(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	seedReadPath(t, d, base)
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}

	tcp := uint8(6)
	summary, live := statsBothWays(t, d, 24, FlowStatsFilter{Protocol: &tcp})

	if summary.TotalBytes != live.TotalBytes {
		t.Errorf("protocol-filtered TotalBytes: summary %d, live %d", summary.TotalBytes, live.TotalBytes)
	}
	if summary.TotalBytes == 0 {
		t.Fatal("the protocol filter matched nothing; the test proves nothing")
	}
	// And the filter must actually narrow, or the comparison above is vacuous.
	unfiltered, _ := statsBothWays(t, d, 24, FlowStatsFilter{})
	if summary.TotalBytes >= unfiltered.TotalBytes {
		t.Errorf("the protocol filter did not narrow: filtered %d, unfiltered %d",
			summary.TotalBytes, unfiltered.TotalBytes)
	}
}

// TestFlowSummaryRead_FallsBackWhenTheSummaryDoesNotCover is the guard that
// keeps a running backfill from being reported as fact. Until the summary
// reaches back to the window start, reading it would silently show a fraction of
// the range — the exact failure this programme exists to remove.
func TestFlowSummaryRead_FallsBackWhenTheSummaryDoesNotCover(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	seedReadPath(t, d, base)
	// Deliberately NOT summarised: the tables are empty.

	orig := flowSummaryMinHours
	flowSummaryMinHours = 1
	defer func() { flowSummaryMinHours = orig }()

	res, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}

	var want uint64
	d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp > ?", time.Now().Add(-24*time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
	if res.TotalBytes != want {
		t.Errorf("with an empty summary the result holds %d bytes against %d in the rollups; the "+
			"read path must fall back rather than report a fraction of the window", res.TotalBytes, want)
	}
}

// TestFlowSummaryRead_DegradesTopPanelsUnderADimensionFilter pins the one thing
// the summary genuinely cannot do. The top-N lists are computed per bucket
// across all protocols and categories, so under a cube filter they would be
// unfiltered talkers sitting beside filtered totals. Saying so is the point.
func TestFlowSummaryRead_DegradesTopPanelsUnderADimensionFilter(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	seedReadPath(t, d, base)
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}

	orig := flowSummaryMinHours
	flowSummaryMinHours = 1
	defer func() { flowSummaryMinHours = orig }()

	tcp := uint8(6)
	res, err := d.GetFlowStats(24, FlowStatsFilter{Protocol: &tcp})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if !res.Degraded {
		t.Error("a dimension-filtered summary read was not marked degraded; the top-talker panels " +
			"cannot honour that filter and must say so")
	}
	named := map[string]bool{}
	for _, b := range res.DegradedBlocks {
		named[b] = true
	}
	for _, want := range []string{"top_sources", "top_destinations", "top_ports", "top_asns", "top_conversations"} {
		if !named[want] {
			t.Errorf("DegradedBlocks does not name %q (got %v)", want, res.DegradedBlocks)
		}
	}
}

// TestFlowSummaryRead_HonoursTheProbeFilter pins a defect the summary path
// reintroduced one table over from where v0.11.247 fixed it.
//
// The cube base built its filters with applyCommonFilters alone, which does NOT
// carry the probe filter — the raw base applies it by column and the rollup base
// by device subquery. So a probe-filtered wide window served EVERY device's
// traffic, exactly the "picked the only probe and the numbers changed" trap the
// original fix existed to close.
func TestFlowSummaryRead_HonoursTheProbeFilter(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)

	probeA, probeB := uint(1), uint(2)
	for _, dev := range []struct {
		name  string
		ip    string
		probe *uint
	}{{"fw-a", "192.0.2.1", &probeA}, {"fw-b", "192.0.2.2", &probeB}} {
		if err := d.Gorm().Create(&models.Device{
			Name: dev.name, IPAddress: dev.ip, Vendor: "fortigate", ProbeID: dev.probe,
		}).Error; err != nil {
			t.Fatalf("seed device %s: %v", dev.name, err)
		}
	}
	var devs []models.Device
	if err := d.Gorm().Order("id").Find(&devs).Error; err != nil || len(devs) < 2 {
		t.Fatalf("load devices: %v (%d found)", err, len(devs))
	}

	for i, dev := range devs {
		for h := 0; h < 4; h++ {
			if err := d.Gorm().Create(&models.FlowRollup{
				Timestamp: base.Add(time.Duration(h)*time.Hour + 5*time.Minute),
				DeviceID:  dev.ID, IntervalType: "5m",
				SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
				BytesSum: uint64(1000 * (i + 1)), PacketsSum: 1, FlowCount: 1,
			}).Error; err != nil {
				t.Fatalf("seed rollup: %v", err)
			}
		}
	}
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}

	summary, live := statsBothWays(t, d, 24, FlowStatsFilter{ProbeID: probeA})
	if summary.TotalBytes != live.TotalBytes {
		t.Errorf("probe-filtered TotalBytes: summary %d, live %d. The cube base must apply the "+
			"probe filter; applyCommonFilters does not carry it.", summary.TotalBytes, live.TotalBytes)
	}
	unfiltered, _ := statsBothWays(t, d, 24, FlowStatsFilter{})
	if summary.TotalBytes >= unfiltered.TotalBytes {
		t.Errorf("the probe filter did not narrow on the summary path: filtered %d, unfiltered %d",
			summary.TotalBytes, unfiltered.TotalBytes)
	}
}

// TestFlowSummaryRead_DoesNotPublishInflatedUniqueCounts pins why the unique
// panels degrade rather than reporting a number.
//
// Summing per-bucket exact distinct counts is not the same approximation the
// live path makes when it sums two tiers: a 90-day window has roughly 850
// (bucket x device x scope) rows, so an address present throughout is counted
// hundreds of times. That is a different quantity, and calling it approximate
// would not make it honest.
func TestFlowSummaryRead_DoesNotPublishInflatedUniqueCounts(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-8 * time.Hour).Truncate(time.Hour)
	seedReadPath(t, d, base)
	for i := 0; i < 4; i++ {
		d.RunFlowSummaryCycle()
	}

	orig := flowSummaryMinHours
	flowSummaryMinHours = 1
	defer func() { flowSummaryMinHours = orig }()

	res, err := d.GetFlowStats(24, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}

	named := map[string]bool{}
	for _, b := range res.DegradedBlocks {
		named[b] = true
	}
	for _, want := range []string{"unique_src_addr", "unique_dst_addr"} {
		if !named[want] {
			t.Errorf("DegradedBlocks does not name %q (got %v); the summary must decline to "+
				"publish a sum of per-bucket distinct counts", want, res.DegradedBlocks)
		}
	}
	// The seed has 3 distinct sources across 6 buckets. A summed-per-bucket
	// figure would be around 18; the raw-only count must be far below that.
	if res.UniqueSources > 6 {
		t.Errorf("UniqueSources is %d; the seed has 3 distinct sources, so anything near "+
			"buckets x sources means the per-bucket sum is being published", res.UniqueSources)
	}
}

// TestFlowSummaryRead_FallsBackWhileTheBackfillIsIncomplete pins the guard that
// an earlier version got exactly backwards.
//
// That version compared the summary's OLDEST bucket against the window cutoff
// and called it coverage. The backfill walks oldest-first, so after its very
// first cycle the summary's oldest bucket already equals the rollups' oldest and
// the check passes while nearly all of history is still missing — a 45-day
// window reported a fifth of the truth, not degraded, silently. The guard now
// requires each tier's CONTIGUOUS fill marker to have reached its newest owned
// bucket.
func TestFlowSummaryRead_FallsBackWhileTheBackfillIsIncomplete(t *testing.T) {
	d := NewDatabaseForTesting(t)
	base := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Hour)
	for h := 0; h < 24; h++ {
		if err := d.Gorm().Create(&models.FlowRollup{
			Timestamp: base.Add(time.Duration(h)*time.Hour + 5*time.Minute),
			DeviceID:  1, IntervalType: "5m",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: 1000, PacketsSum: 1, FlowCount: 1,
		}).Error; err != nil {
			t.Fatalf("seed hour %d: %v", h, err)
		}
	}

	// Exactly ONE bucket per pass, so a single cycle leaves the backfill far from
	// done while the summary's oldest bucket already matches the rollups'.
	origTiers := flowSummaryTiers
	flowSummaryTiers = []flowSummaryTier{{
		interval:     "1h",
		rangeSources: []string{"5m", "1h"},
		sumSources:   []string{"5m", "1h", "1d"},
		width:        time.Hour,
		bucketOf:     func(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) },
		maxPerPass:   1,
	}}
	defer func() { flowSummaryTiers = origTiers }()
	d.RunFlowSummaryCycle()

	var summarised int64
	d.Gorm().Model(&models.FlowSummary{}).Distinct("timestamp").Count(&summarised)
	if summarised == 0 || summarised >= 24 {
		t.Fatalf("precondition: %d buckets summarised, wanted a partial backfill", summarised)
	}

	orig := flowSummaryMinHours
	flowSummaryMinHours = 1
	defer func() { flowSummaryMinHours = orig }()

	res, err := d.GetFlowStats(48, FlowStatsFilter{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	var want uint64
	d.Gorm().Model(&models.FlowRollup{}).
		Where("timestamp > ?", time.Now().Add(-48*time.Hour)).
		Select("COALESCE(SUM(bytes_sum),0)").Scan(&want)
	if res.TotalBytes != want {
		t.Errorf("with a partial backfill the result holds %d bytes against %d in the rollups. "+
			"Coverage must be judged by the contiguous fill marker, not by the oldest bucket — "+
			"the backfill walks oldest-first, so the oldest bucket matches almost immediately.",
			res.TotalBytes, want)
	}
}
