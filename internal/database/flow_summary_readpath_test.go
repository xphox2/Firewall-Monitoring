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

	if summary.Degraded {
		t.Fatalf("the summary path reported degraded: %v", summary.DegradedBlocks)
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

	sameKeys := func(name string, a, b []KeyCount) {
		t.Helper()
		am := map[string]int64{}
		for _, k := range a {
			am[k.Key] = k.Count
		}
		for _, k := range b {
			if am[k.Key] != k.Count {
				t.Errorf("%s[%q]: summary %d, live %d", name, k.Key, am[k.Key], k.Count)
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
