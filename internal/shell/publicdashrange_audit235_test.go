package shell

import (
	"os"
	"strings"
	"testing"
)

// AUDIT-235: public-dashboard.js parsed the dashboard range with parseInt, which
// truncated the 15m (0.25) and 30m (0.5) options to 0. On the server, ParseHours
// (integer Atoi) fell back to 24h for the status/CPU history and the interface
// chart's Atoi fallback dropped to 1h — so the sub-hour ranges silently showed
// the wrong window. The client fix is parseFloat; the server must ALSO honor the
// fractional value end to end, or the wrong window still renders.
func TestPublicDashRange_ClientUsesParseFloat_AUDIT235(t *testing.T) {
	js := readJS(t, "public-dashboard.js")

	if strings.Contains(js, "dashRange = parseInt(e.target.value)") {
		t.Error("AUDIT-235 regression: dashRange is parsed with parseInt again — 0.25/0.5 (15m/30m) truncate to 0")
	}
	if !strings.Contains(js, "dashRange = parseFloat(e.target.value)") {
		t.Error("AUDIT-235 regression: dashRange must be parsed with parseFloat so 0.25/0.5 survive")
	}
}

func TestPublicDashRange_ServerHonorsFractional_AUDIT235(t *testing.T) {
	b, err := os.ReadFile("../../internal/api/handlers/handlers_dashboard.go")
	if err != nil {
		t.Fatalf("read handlers_dashboard.go: %v", err)
	}
	src := string(b)

	// Interface chart: the numeric fallback must ParseFloat (not Atoi) and route
	// sub-hour values through an explicit duration cutoff.
	if strings.Contains(src, "strconv.Atoi(rangeStr)") {
		t.Error("AUDIT-235 regression: GetPublicInterfaceChart uses strconv.Atoi(rangeStr) again — fractional ranges fall back to 1h")
	}
	if !strings.Contains(src, "strconv.ParseFloat(rangeStr, 64)") {
		t.Error("AUDIT-235 regression: GetPublicInterfaceChart no longer ParseFloats the range — 0.25/0.5 can't survive")
	}
	if !strings.Contains(src, "subHour") {
		t.Error("AUDIT-235 regression: the sub-hour cutoff handling was removed from GetPublicInterfaceChart")
	}

	// Status/CPU history: sub-hour hours must be honored, not collapsed to the
	// ParseHours 24h default. Since v0.11.259 it resolves `hours` through the
	// same publicChartLookback as the bandwidth tiles (which ParseFloats, per
	// above). Scoped to the function body: publicChartLookback( also appears in
	// GetPublicInterfaceChart, so a file-wide check would pass without it.
	const head = "func (h *Handler) GetPublicStatusHistory("
	i := strings.Index(src, head)
	if i < 0 {
		t.Fatal("GetPublicStatusHistory not found in handlers_dashboard.go")
	}
	body := src[i+len(head):]
	if j := strings.Index(body, "\nfunc "); j >= 0 {
		body = body[:j]
	}
	if !strings.Contains(body, "publicChartLookback(") {
		t.Error("AUDIT-235 regression: GetPublicStatusHistory no longer resolves `hours` through publicChartLookback — 15m/30m can show 24h")
	}
	if strings.Contains(body, "httputil.ParseHours(c)") {
		t.Error("AUDIT-235 regression: GetPublicStatusHistory parses `hours` with the integer-only ParseHours again — 15m/30m show 24h")
	}
}
