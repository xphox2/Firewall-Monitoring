package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// v44 migration: an active Silence-Source row becomes a temporary flow_security
// suppress Event Rule; re-running the migration is idempotent (no duplicate).
func TestMigrateSilencesToTempRules(t *testing.T) {
	db := NewDatabaseForTesting(t)
	until := time.Now().Add(12 * time.Hour)
	if err := db.db.Create(&models.FlowSourceSuppression{
		SrcAddr: "198.51.100.9", SuppressedUntil: until, SuppressedBy: "op", SuppressedReason: "scanner",
	}).Error; err != nil {
		t.Fatalf("seed silence: %v", err)
	}
	// An already-expired silence must NOT be carried forward.
	if err := db.db.Create(&models.FlowSourceSuppression{
		SrcAddr: "203.0.113.1", SuppressedUntil: time.Now().Add(-time.Hour),
	}).Error; err != nil {
		t.Fatalf("seed expired silence: %v", err)
	}

	if err := db.migrateEventRuleExpiryAndSilences(); err != nil {
		t.Fatalf("migration: %v", err)
	}

	var rules []models.EventRule
	db.db.Where("source = ?", "flow_security").Find(&rules)
	if len(rules) != 1 {
		t.Fatalf("expected 1 migrated temp rule (only the active silence), got %d", len(rules))
	}
	r := rules[0]
	if r.Action != "suppress" || r.ExpiresAt == nil || r.Name != "Silenced 198.51.100.9" {
		t.Fatalf("bad migrated rule: %+v", r)
	}
	if r.MatchJSON != `{"op":"eq","field":"source_ip","value":"198.51.100.9"}` {
		t.Fatalf("bad match_json: %s", r.MatchJSON)
	}

	// Idempotent: re-running must not duplicate.
	if err := db.migrateEventRuleExpiryAndSilences(); err != nil {
		t.Fatalf("migration re-run: %v", err)
	}
	var n int64
	db.db.Model(&models.EventRule{}).Where("source = ?", "flow_security").Count(&n)
	if n != 1 {
		t.Fatalf("re-run must be idempotent, got %d rules", n)
	}
}

// PruneExpiredEventRules deletes past-expiry temp rules and leaves permanent +
// future-expiry rules untouched.
func TestPruneExpiredEventRules(t *testing.T) {
	db := NewDatabaseForTesting(t)
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	mk := func(name string, exp *time.Time) {
		if err := db.CreateEventRule(&models.EventRule{Name: name, Enabled: true, Source: "flow_security", Action: "suppress", ExpiresAt: exp}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("expired", &past)
	mk("future", &future)
	mk("permanent", nil)

	if err := db.PruneExpiredEventRules(); err != nil {
		t.Fatalf("prune: %v", err)
	}
	var names []string
	db.db.Model(&models.EventRule{}).Order("name").Pluck("name", &names)
	// "expired" gone; "future" + "permanent" remain (plus any shipped seeds).
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	if got["expired"] {
		t.Error("expired temp rule should have been pruned")
	}
	if !got["future"] || !got["permanent"] {
		t.Errorf("future/permanent rules must survive; names=%v", names)
	}
}
