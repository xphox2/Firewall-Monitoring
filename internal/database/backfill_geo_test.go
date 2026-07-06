package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestBackfillFlowGeo verifies the historical geo backfill: it fills only public,
// still-empty endpoints, skips private and already-populated ones, and a re-run
// is a no-op.
func TestBackfillFlowGeo(t *testing.T) {
	db := NewDatabaseForTesting(t)
	now := time.Now().UTC()
	seed := []models.FlowSample{
		{Timestamp: now, SrcAddr: "8.8.8.8", DstAddr: "1.1.1.1"},                                                      // both public, empty
		{Timestamp: now, SrcAddr: "10.0.0.5", DstAddr: "10.0.0.6"},                                                    // both private → skip
		{Timestamp: now, SrcAddr: "9.9.9.9", DstAddr: "1.1.1.1", SrcCountry: "US", SrcASN: 19281, SrcASNOrg: "Quad9"}, // src filled, dst empty
	}
	for i := range seed {
		if err := db.db.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	resolve := func(ip string) (string, uint32, string) {
		switch ip {
		case "8.8.8.8":
			return "US", 15169, "Google LLC"
		case "1.1.1.1":
			return "AU", 13335, "Cloudflare"
		case "9.9.9.9":
			return "US", 19281, "Quad9"
		}
		return "", 0, ""
	}

	res, err := db.BackfillFlowGeo(resolve, 0, 100, 0, nil)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.Scanned != 3 {
		t.Errorf("scanned = %d, want 3", res.Scanned)
	}
	// row1 (both endpoints) + row3 (dst only) get updated; row2 (private) does not.
	if res.Updated != 2 {
		t.Errorf("updated = %d, want 2", res.Updated)
	}

	var r1 models.FlowSample
	db.db.First(&r1, seed[0].ID)
	if r1.SrcCountry != "US" || r1.SrcASN != 15169 || r1.SrcASNOrg != "Google LLC" ||
		r1.DstCountry != "AU" || r1.DstASN != 13335 || r1.DstASNOrg != "Cloudflare" {
		t.Errorf("row1 not fully enriched: %+v", r1)
	}
	var r2 models.FlowSample
	db.db.First(&r2, seed[1].ID)
	if r2.SrcCountry != "" || r2.SrcASN != 0 || r2.DstCountry != "" {
		t.Errorf("private row was enriched: %+v", r2)
	}
	var r3 models.FlowSample
	db.db.First(&r3, seed[2].ID)
	if r3.SrcASN != 19281 || r3.DstCountry != "AU" || r3.DstASN != 13335 {
		t.Errorf("row3 dst not enriched / src clobbered: %+v", r3)
	}

	// Idempotent: a second run changes nothing.
	res2, err := db.BackfillFlowGeo(resolve, 0, 100, 0, nil)
	if err != nil {
		t.Fatalf("backfill re-run: %v", err)
	}
	if res2.Updated != 0 {
		t.Errorf("re-run updated = %d, want 0 (no-op)", res2.Updated)
	}
}
