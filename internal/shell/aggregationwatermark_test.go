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
// Both aggregation pipelines are covered. syslog_agg.go's own header calls the
// shape "shared with the flow rollups", and that is exactly how the first fix
// missed half the defect: syslog_agg.go was repaired while flows.go kept the
// filtered watermark and went on timing out in production on the very next
// cycle. Any new pipeline that adopts this shape belongs in this table.
func TestAggregationWatermarksAreUnfiltered(t *testing.T) {
	for _, f := range []struct {
		path  string
		sites int
		what  string
	}{
		{"../../internal/database/syslog_agg.go", 2, "aggregateSyslogToSummary and promoteSyslogSummaries"},
		{"../../internal/database/flows.go", 2, "RunFlowRollupCycle's 5m pass and promoteFlowRollups"},
	} {
		data, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("%s not found: %v", f.path, err)
		}
		body := string(data)

		// Every watermark read must survive, so this fails loudly if one is
		// renamed or restructured rather than silently passing.
		const watermarkSelect = `Select("COALESCE(MAX(id), 0)")`
		if n := strings.Count(body, watermarkSelect); n != f.sites {
			t.Errorf("%s: found %d %s calls, want %d (%s). If a watermark was "+
				"restructured, update this guard deliberately — do not delete it.",
				f.path, n, watermarkSelect, f.sites, f.what)
			continue
		}

		// The failure mode: a Where(...) chained onto the statement producing the
		// watermark. Inspect the call site, not the whole function — these
		// functions legitimately use the same predicates on their reads and delete.
		reWatermark := regexp.MustCompile(`(?s)var watermark int64\n(.*?)Scan\(&watermark\)`)
		sites := reWatermark.FindAllStringSubmatch(body, -1)
		if len(sites) != f.sites {
			t.Errorf("%s: found %d watermark assignment sites, want %d", f.path, len(sites), f.sites)
			continue
		}
		for i, m := range sites {
			if strings.Contains(m[1], "Where(") {
				t.Errorf("%s: watermark site %d attaches a Where(...) to the MAX(id) query:\n%s\n"+
					"The watermark must stay UNFILTERED. It is only an upper bound "+
					"excluding rows that arrive mid-pass, so any bound >= every id in "+
					"the target set is correct; the predicates belong on the reads and "+
					"the DELETE, which already carry them. Filtering it reintroduces "+
					"the pkey-backward-walk timeout that stopped aggregation in "+
					"production (syslog_agg.go) and flow rollups (flows.go).",
					f.path, i+1, strings.TrimSpace(m[1]))
			}
		}

		// The work probe replaces the `watermark == 0` early-exit that an
		// unfiltered bound can no longer provide.
		if !strings.Contains(body, "work probe") {
			t.Errorf("%s no longer has a work probe: an unfiltered watermark is "+
				"non-zero whenever the table holds any row, so `watermark == 0` "+
				"cannot signal 'nothing to do' on its own.", f.path)
		}
	}
}
