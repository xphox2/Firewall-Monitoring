package report

import (
	"strings"
	"testing"
)

// TestRenderReportText pins the text/plain alternative: model-generated (no
// HTML), carries the verdict + KPIs + per-device lines, CRLF line endings.
func TestRenderReportText(t *testing.T) {
	m := ReportModel{
		Period: "Daily", Date: "July 18, 2026", Timezone: "UTC",
		GeneratedAt: "2026-07-18 06:00", Version: "0.11.117",
		TotalDevices: 3, OnlineDevices: 2, OfflineDevices: 1,
		TotalAlerts: 7, CriticalAlerts: 2, FleetUptimePct: 98.6,
		StatusHeadline: "Attention needed", StatusDetail: "1 device offline",
		PeakThroughput: "842.0 Mbps", TotalTransfer: "1.2 TB",
		TopTalkers:  []TopTalker{{DeviceName: "fw-01", IfaceName: "wan1", TotalHuman: "900 GB", PeakHuman: "842.0 Mbps", BarPct: 100}},
		SpikeGroups: []SpikeGroup{{DeviceName: "fw-01", Interface: "wan1", Count: 4, PeakHuman: "900 Mbps", WorstSev: "critical"}},
		SpikeTotal:  4, SpikeCritical: 1, SpikeIfaceCount: 1,
		Ops: &OpsStats{Days: 30, MTTAMinutes: 12, MTTRMinutes: 45, AckedCount: 9, ResolvedCount: 8,
			Noise: []NoiseRow{{AlertType: "CPU_HIGH", DeviceName: "fw-01", Count: 5, Suppressed: 2}}},
		Devices: []DeviceCard{
			{Name: "fw-01", IPAddress: "10.0.0.1", Online: true, CPUMax: 91, MemMax: 60, UptimePct: 99.9, AlertCount: 5},
			{Name: "fw-02", IPAddress: "10.0.0.2", Online: false, UptimePct: 42.1},
		},
	}
	text := RenderReportText(m)

	if strings.ContainsAny(text, "<>") {
		t.Fatal("plaintext contains angle brackets — must never carry HTML")
	}
	for _, want := range []string{
		"DAILY REPORT", "ATTENTION NEEDED", "1 device offline",
		"2 / 3", "98.6%", "7 (2 critical)", "842.0 Mbps", "1.2 TB",
		"TOP TALKERS", "fw-01", "TRAFFIC SPIKES: 4 events (1 critical)",
		"OPERATIONS (LAST 30 DAYS)", "MTTA 12 min", "MTTR 45 min",
		"CPU_HIGH", "OFFLINE", "10.0.0.2", "v0.11.117",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("plaintext missing %q", want)
		}
	}
	if !strings.Contains(text, "\r\n") || strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\n") {
		t.Error("plaintext must use CRLF line endings exclusively (QP body of a MIME part)")
	}
}
