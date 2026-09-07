package database

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// deviceKeyColumns are the column names that make a table "device-keyed":
// deleting a device must clear rows carrying its id in any of them.
var deviceKeyColumns = map[string]bool{
	"device_id":        true,
	"source_device_id": true,
	"dest_device_id":   true,
	"a_device_id":      true,
	"b_device_id":      true,
}

// purgeCoveredElsewhere are device-keyed tables that the purge handles WITHOUT
// an entry in devicePurgeTables, with the reason. Anything else with a device
// key must be in the slice.
var purgeCoveredElsewhere = map[string]string{
	// Cleared by DeleteDevice, the plan's final step (both directions).
	"device_connections": "DeleteDevice",
	// The job queue itself: keyed by device_id so the latest-job lookup works;
	// terminal rows are the audit trail (30-day retention), never purged.
	"device_purge_jobs": "audit trail",
}

// deviceKeyedTables reflects over the given model lists and returns, per table
// name, the device-keyed columns it declares (incl. *uint ones).
func deviceKeyedTables(t *testing.T, lists ...[]interface{}) map[string][]string {
	t.Helper()
	var cache sync.Map
	out := map[string][]string{}
	seen := map[string]bool{}
	for _, list := range lists {
		for _, m := range list {
			s, err := schema.Parse(m, &cache, schema.NamingStrategy{})
			if err != nil {
				t.Fatalf("schema.Parse(%T): %v", m, err)
			}
			if seen[s.Table] {
				continue
			}
			seen[s.Table] = true
			for _, f := range s.Fields {
				if deviceKeyColumns[f.DBName] {
					out[s.Table] = append(out[s.Table], f.DBName)
				}
			}
		}
	}
	return out
}

// TestDevicePurgeTables_CoverEveryDeviceKeyedModel is the guard that keeps the
// purge plan complete: every model in baselineModels or testModels with a
// device-keyed column must have an entry in devicePurgeTables naming every one
// of those columns (or be in purgeCoveredElsewhere with a reason), and every
// slice entry must name a real table and real device-keyed columns of it.
func TestDevicePurgeTables_CoverEveryDeviceKeyedModel(t *testing.T) {
	keyed := deviceKeyedTables(t, baselineModels, testModels)
	if len(keyed) < 30 {
		t.Fatalf("reflection found only %d device-keyed tables — the model lists or the column scan are broken", len(keyed))
	}

	planned := map[string]map[string]bool{}
	for _, pt := range devicePurgeTables {
		if _, dup := planned[pt.table]; dup {
			t.Errorf("devicePurgeTables lists %s twice", pt.table)
		}
		if pt.orderBy == "" {
			t.Errorf("devicePurgeTables[%s] has no orderBy", pt.table)
		}
		cols := map[string]bool{}
		for _, c := range pt.columns {
			cols[c] = true
		}
		planned[pt.table] = cols
		real, ok := keyed[pt.table]
		if !ok {
			t.Errorf("devicePurgeTables names %s, which is not a device-keyed table of any model in baselineModels/testModels", pt.table)
			continue
		}
		realCols := map[string]bool{}
		for _, c := range real {
			realCols[c] = true
		}
		for _, c := range pt.columns {
			if !realCols[c] {
				t.Errorf("devicePurgeTables[%s] uses column %s, which the model does not declare (declared: %v)", pt.table, c, real)
			}
		}
	}

	for table, cols := range keyed {
		if why, ok := purgeCoveredElsewhere[table]; ok {
			if _, alsoPlanned := planned[table]; alsoPlanned {
				t.Errorf("%s is both in devicePurgeTables and purgeCoveredElsewhere (%s)", table, why)
			}
			continue
		}
		plan, ok := planned[table]
		if !ok {
			t.Errorf("device-keyed table %s (columns %v) has NO devicePurgeTables entry — a purge would leave its rows behind", table, cols)
			continue
		}
		for _, c := range cols {
			if !plan[c] {
				t.Errorf("devicePurgeTables[%s] does not delete on column %s", table, c)
			}
		}
	}
}

// TestDevicePurgeTables_LiteralsOnly pins the SQL-injection boundary: every
// table/column/orderBy string is a plain identifier (letters, digits,
// underscores) — batchedDeleteWhere splices them into SQL unquoted.
func TestDevicePurgeTables_LiteralsOnly(t *testing.T) {
	ident := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return false
			}
		}
		return true
	}
	for _, pt := range devicePurgeTables {
		if !ident(pt.table) || !ident(pt.orderBy) {
			t.Errorf("devicePurgeTables entry %q / orderBy %q is not a bare identifier", pt.table, pt.orderBy)
		}
		for _, c := range pt.columns {
			if !ident(c) || !deviceKeyColumns[c] {
				t.Errorf("devicePurgeTables[%s] column %q is not one of the device-key columns", pt.table, c)
			}
		}
	}
}
