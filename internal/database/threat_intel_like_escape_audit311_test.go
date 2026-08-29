package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestSearchThreatIntel_LikeWildcardsAreLiteral (AUDIT-311): the operator's
// search query is embedded in a LIKE pattern, so an unescaped % or _ acted as
// a SQL wildcard — querying "10_0" matched "10.0" and "1000", returning a
// misleading result set. The query must now match those characters literally.
func TestSearchThreatIntel_LikeWildcardsAreLiteral(t *testing.T) {
	d := NewDatabaseForTesting(t)

	rows := []models.ThreatIntel{
		{CIDR: "10.0.0.0/24", Source: "feedA", Category: "scanner"},
		{CIDR: "1000::/64", Source: "feedA", Category: "scanner"},
		{CIDR: "10_0-tagged/32", Source: "feedA", Category: "scanner"}, // literal underscore
		{CIDR: "50%25-list/32", Source: "feedA", Category: "scanner"},  // literal percent
	}
	if err := d.UpsertThreatIntelBatch(rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// "_" must not act as a single-char wildcard: only the literal-underscore
	// row may match.
	got, total, err := d.SearchThreatIntel(ThreatIntelFilter{Query: "10_0"}, 0, 100)
	if err != nil {
		t.Fatalf("search 10_0: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].CIDR != "10_0-tagged/32" {
		t.Errorf("query %q matched %d rows (%v), want exactly the literal-underscore row", "10_0", total, cidrsOf(got))
	}

	// "%" must not act as an any-string wildcard: unescaped, "0%2" ("0", then
	// anything, then "2") matched 10.0.0.0/24, 10_0-tagged/32 AND the literal
	// row; escaped, only the row containing the literal substring "0%2" matches.
	got, total, err = d.SearchThreatIntel(ThreatIntelFilter{Query: "0%2"}, 0, 100)
	if err != nil {
		t.Fatalf("search 0%%2: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].CIDR != "50%25-list/32" {
		t.Errorf("query %q matched %d rows (%v), want exactly the literal-percent row", "0%2", total, cidrsOf(got))
	}

	// A plain substring query still works as a substring search.
	_, total, err = d.SearchThreatIntel(ThreatIntelFilter{Query: "10"}, 0, 100)
	if err != nil {
		t.Fatalf("search 10: %v", err)
	}
	if total != 3 {
		t.Errorf("query %q matched %d rows, want 3 (10.0…, 1000…, 10_0…)", "10", total)
	}
}

func cidrsOf(rows []models.ThreatIntel) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.CIDR)
	}
	return out
}
