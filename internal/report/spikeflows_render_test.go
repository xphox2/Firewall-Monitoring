package report

import (
	"strings"
	"testing"
)

// TestReportRendersSpikeFlows verifies the per-device "Top Flows During Spikes"
// block renders when SpikeFlows are present and is absent otherwise.
func TestReportRendersSpikeFlows(t *testing.T) {
	m := ReportModel{
		Period: "Daily", Date: "Thursday, June 18, 2026", Timezone: "UTC",
		GeneratedAt: "2026-06-18 09:00 UTC", Hours: 24,
		Devices: []DeviceCard{{
			Name: "fw-core-01", IPAddress: "10.0.0.1", Online: true, Timezone: "UTC",
			SpikeFlows: []SpikeFlow{
				{Src: "10.0.0.5", Dst: "203.0.113.9:443", Protocol: "TCP", BytesHuman: "12.0 KB"},
			},
		}},
	}
	m.computeStatusVerdict()

	html, err := RenderReportHTML(m)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"Top Flows During Spikes", "10.0.0.5", "203.0.113.9:443", "TCP", "12.0 KB"} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered report missing %q", want)
		}
	}

	m.Devices[0].SpikeFlows = nil
	html2, err := RenderReportHTML(m)
	if err != nil {
		t.Fatalf("render (empty): %v", err)
	}
	if strings.Contains(html2, "Top Flows During Spikes") {
		t.Error("spike-flows section should be absent when there are no SpikeFlows")
	}
}
