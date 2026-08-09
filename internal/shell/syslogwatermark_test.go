package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestSyslogAggregationWatermarkIsUnfiltered pins the fix for the production
// syslog-aggregation crash loop.
//
// aggregateSyslogToSummary and promoteSyslogSummaries each open with a MAX(id)
// watermark. Both used to attach the pass's own predicates to it:
//
//	SELECT COALESCE(MAX(id),0) FROM syslog_messages
//	WHERE timestamp < ? AND severity = ?
//
// PostgreSQL rewrites MAX(id) into a backward walk of the primary key that stops
// at the first row passing the filter, and prices it by expected-rows-until-
// first-match. Since the newest ids all fail `timestamp < cutoff`, that walk
// crossed most of the table while the planner still estimated single-digit cost.
// Measured on a 92M-row production table it exceeded 120s against the DSN's 30s
// statement_timeout, so every 5-minute cycle aborted and retried forever and
// syslog_summaries stayed empty. Unfiltered, the same rewrite stops on the first
// tuple: 0.5ms.
//
// This is a STATIC guard because the defect is a planner choice. The unit tests
// run on SQLite, where re-attaching the filter is merely equivalent-and-slower,
// so no behavioural test in the default suite can catch a regression here.
//
// Note an index on (severity, timestamp, id) is NOT the fix and must not be
// offered as one: for a severity holding most of the table the planner prices
// the pkey walk in single digits and keeps choosing it, so such an index would
// pass tests on the small severities and still fail on the one with the volume.
func TestSyslogAggregationWatermarkIsUnfiltered(t *testing.T) {
	const path = "../../internal/database/syslog_agg.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("syslog_agg.go not found at %s: %v", path, err)
	}
	body := string(data)

	// Both watermark reads must survive, so this test fails loudly if the
	// selects are renamed or restructured rather than silently passing.
	const watermarkSelect = `Select("COALESCE(MAX(id), 0)")`
	if n := strings.Count(body, watermarkSelect); n != 2 {
		t.Fatalf("found %d %s calls, want 2 (aggregateSyslogToSummary and "+
			"promoteSyslogSummaries). If the watermark was restructured, update "+
			"this guard deliberately — do not delete it.", n, watermarkSelect)
	}

	// The failure mode: a Where(...) chained onto the statement that produces the
	// watermark. Look at the call site rather than the whole function, since both
	// functions legitimately use the same predicates on their SELECT and DELETE.
	reWatermark := regexp.MustCompile(`(?s)var watermark int64\n(.*?)Scan\(&watermark\)`)
	sites := reWatermark.FindAllStringSubmatch(body, -1)
	if len(sites) != 2 {
		t.Fatalf("found %d watermark assignment sites, want 2", len(sites))
	}
	for i, m := range sites {
		if strings.Contains(m[1], "Where(") {
			t.Errorf("watermark site %d attaches a Where(...) to the MAX(id) query:\n%s\n"+
				"The watermark must stay UNFILTERED. It is only an upper bound that "+
				"excludes rows arriving mid-pass, so any bound >= every id in the "+
				"target set is correct; the predicates belong on the SELECT and the "+
				"DELETE, which already carry them. Filtering it reintroduces the "+
				"pkey-backward-walk timeout that stopped all aggregation in production.",
				i+1, strings.TrimSpace(m[1]))
		}
	}

	// The work probe replaces the `watermark == 0` early-exit that an unfiltered
	// bound can no longer provide. Without it an idle severity does a paged scan
	// every 5 minutes.
	if !strings.Contains(body, "work probe") {
		t.Error("syslog_agg.go no longer has a work probe: an unfiltered watermark is " +
			"non-zero whenever the table holds any row, so `watermark == 0` cannot " +
			"signal 'nothing to aggregate' on its own.")
	}
}
