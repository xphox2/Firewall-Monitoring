package httputil

import (
	"testing"

	"github.com/gin-gonic/gin"
)

// TestParsePaginationMax pins the ceiling split: the Flows CSV export asks for
// limit=10000 and must get it from an endpoint that passes 10000, while the
// 500-capped ParsePagination used by every JSON list keeps ignoring it (the
// default 100 applies, as it always has). Pre-change the export could only
// ever receive 100 rows — the 500 cap was hard-wired.
func TestParsePaginationMax(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		query      string
		max        int
		wantLimit  int
		wantOffset int
	}{
		{"export ceiling honours 10000", "limit=10000", 10000, 10000, 0},
		{"export ceiling rejects above max", "limit=10001", 10000, 100, 0},
		{"export ceiling keeps small limits", "limit=25&offset=50", 10000, 25, 50},
		{"list ceiling still caps at 500", "limit=10000", 500, 100, 0},
		{"list ceiling accepts 500", "limit=500", 500, 500, 0},
		{"zero and negative fall back", "limit=0&offset=-1", 10000, 100, 0},
		{"non-numeric falls back", "limit=abc", 10000, 100, 0},
		{"absent uses defaults", "", 10000, 100, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			limit, offset := ParsePaginationMax(ctxWithQuery(tc.query), tc.max)
			if limit != tc.wantLimit || offset != tc.wantOffset {
				t.Errorf("ParsePaginationMax(%q, %d) = (%d, %d), want (%d, %d)",
					tc.query, tc.max, limit, offset, tc.wantLimit, tc.wantOffset)
			}
		})
	}

	// ParsePagination is the 500-capped wrapper; a 10000 request must not leak
	// through it.
	if limit, _ := ParsePagination(ctxWithQuery("limit=10000")); limit != 100 {
		t.Errorf("ParsePagination(limit=10000) = %d, want 100 (500 cap unchanged)", limit)
	}
}
