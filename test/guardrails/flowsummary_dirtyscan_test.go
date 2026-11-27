package guardrails

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestFlowSummaryDirtyScanIsBoundedPerStatement pins the fix for the flow
// summary's month-long production stall (found a month after 2026-10-25).
//
// The summariser finds the buckets that changed since its last pass by reading
// the flow_rollups ids above its watermark. That used to be ONE statement:
//
//	SELECT DISTINCT timestamp FROM flow_rollups
//	WHERE interval_type IN (...) AND id > <watermark> AND id <= <ceiling>
//
// Its cost grows with how far behind the tier is, and a statement that hits the
// 30s statement_timeout leaves the watermark where it was — so the next cycle
// issues a larger one. One slow cycle (a cold cache after a database crash, at
// the midnight promotion) became a permanent failure: the range reached 245M
// ids, the hourly tier emptied, and every long Flows window fell back to a live
// path it cannot finish.
//
// This is a STATIC guard because the defect is a cost shape. The unit tests run
// on SQLite with a few dozen rows, where one statement over the whole range is
// merely equivalent; they pin the piece-by-piece behaviour, and this pins that
// nobody reassembles the single statement beside it.
func TestFlowSummaryDirtyScanIsBoundedPerStatement(t *testing.T) {
	const path = "../../internal/database/flow_summary.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s not found: %v", path, err)
	}
	body := string(data)

	// 1. No single Where(...) takes both ends of the backlog. Matched across
	// lines: the ownership probe legitimately spans two and takes the watermark
	// alone.
	reWhere := regexp.MustCompile(`(?s)Where\((.*?)\)\.`)
	for _, m := range reWhere.FindAllStringSubmatch(body, -1) {
		// Only an id-range predicate counts: the lazy match can run on through
		// unrelated code and comments that merely mention both words.
		if !strings.Contains(m[1], "id >") && !strings.Contains(m[1], "id <=") {
			continue
		}
		if strings.Contains(m[1], "watermark") && strings.Contains(m[1], "ceiling") {
			t.Errorf("%s: a Where(...) is bounded by the watermark and the ceiling together:\n%s\n"+
				"That is one statement over the tier's whole backlog — the shape that stalled "+
				"production. Read the range in pieces (dirtyBuckets / dirtyChunkStamps).", path, m[0])
		}
	}

	// 2. The id-range statement exists exactly once, inside dirtyChunkStamps,
	// whose bounds are one piece (lo, hi].
	const idRange = `id > ? AND id <= ?`
	// Counted in code only, so describing the statement in a comment is free.
	code := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(body, "")
	if n := strings.Count(code, idRange); n != 1 {
		t.Errorf("%s: found %d statements with %q, want exactly 1 (in dirtyChunkStamps). "+
			"If the scan was restructured, update this guard deliberately — do not delete it.",
			path, n, idRange)
	}
	reHelper := regexp.MustCompile(`(?s)\nfunc dirtyChunkStamps\(h \*gorm\.DB, sources \[\]string, lo, hi int64\).*?\n}\n`)
	helper := reHelper.FindString(body)
	if helper == "" {
		t.Fatalf("%s: dirtyChunkStamps(h, sources, lo, hi) not found; the guard anchors on it", path)
	}
	if !strings.Contains(helper, idRange) || !strings.Contains(helper, "sources, lo, hi)") {
		t.Errorf("%s: dirtyChunkStamps no longer issues the id-range statement over (lo, hi]", path)
	}

	// 3. dirtyBuckets sizes its pieces from the chunk setting.
	reBuckets := regexp.MustCompile(`(?s)\nfunc \(d \*Database\) dirtyBuckets\(.*?\n}\n`)
	buckets := reBuckets.FindString(body)
	if buckets == "" {
		t.Fatalf("%s: dirtyBuckets not found", path)
	}
	// The call must pass the piece's own bounds: handing the helper the
	// watermark or the ceiling rebuilds the single statement through it.
	if n := strings.Count(body, "dirtyChunkStamps("); n != 2 {
		t.Errorf("%s: dirtyChunkStamps appears %d times, want 2 (its definition and one call "+
			"from dirtyBuckets)", path, n)
	}
	for _, want := range []string{"chunk := flowSummaryDirtyScanChunk\n", "tier.sumSources, lo, hi)", "hi = lo + chunk"} {
		if !strings.Contains(buckets, want) {
			t.Errorf("%s: dirtyBuckets no longer contains %q; the scan must advance in "+
				"fixed-width id pieces", path, want)
		}
	}
}
