package database

import (
	"testing"
)

// TestAutovacuumTables_AUDIT147 pins that the default autovacuum set now
// covers the heaviest time-series writers the original hard-coded list
// omitted (interface_stats, system_status), and that DB_AUTOVACUUM_TABLES
// overrides the whole set (with blank-entry trimming and a safe fallback).
func TestAutovacuumTables_AUDIT147(t *testing.T) {
	// Default must include the previously-missing high-volume tables.
	def := autovacuumTables()
	for _, must := range []string{"interface_stats", "system_status"} {
		if !contains(def, must) {
			t.Errorf("default autovacuum tables missing %q (AUDIT-147): it's one of the heaviest time-series writers and must be tuned.", must)
		}
	}
	// And keep the original ones.
	for _, must := range []string{"syslog_messages", "flow_samples", "alerts"} {
		if !contains(def, must) {
			t.Errorf("default autovacuum tables dropped the original entry %q (AUDIT-147).", must)
		}
	}

	// Env override replaces the whole set and trims blanks.
	t.Setenv("DB_AUTOVACUUM_TABLES", " foo , ,bar ")
	got := autovacuumTables()
	if len(got) != 2 || got[0] != "foo" || got[1] != "bar" {
		t.Errorf("DB_AUTOVACUUM_TABLES override = %v, want [foo bar] (AUDIT-147: comma-split, trimmed, blanks dropped).", got)
	}

	// An all-blank override falls back to the default rather than tuning nothing.
	t.Setenv("DB_AUTOVACUUM_TABLES", "  , ,")
	if fb := autovacuumTables(); len(fb) != len(def) {
		t.Errorf("all-blank override should fall back to the default set (AUDIT-147); got %d tables, want %d.", len(fb), len(def))
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
