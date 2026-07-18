package report

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// TestReport_OpsSection_Renders: with OpsStats attached the report carries
// the Operations section (MTTA/MTTR + noise table); with nil it is omitted.
func TestReport_OpsSection_Renders(t *testing.T) {
	ops := &OpsStats{
		Days: 30, MTTAMinutes: 15, MTTRMinutes: 90,
		AckedCount: 4, ResolvedCount: 6,
		Noise: []NoiseRow{{AlertType: "CPU_HIGH", DeviceName: "fw-a", Count: 12, Suppressed: 3}},
	}
	_, html, _, err := BuildReportWithOps([]models.Device{}, nil, "UTC", 24, "Daily", "test", false, ops, ThemeByName(""))
	if err != nil {
		t.Fatalf("BuildReportWithOps: %v", err)
	}
	for _, want := range []string{"Operations (30 days)", "15 min", "1.5 h", "CPU_HIGH", "fw-a", "12"} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}

	_, html2, err := BuildReport([]models.Device{}, nil, "UTC", 24, "Daily", "test", false)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if strings.Contains(html2, "Operations (30 days)") {
		t.Error("nil ops must omit the section")
	}
}
