package models

import (
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm/schema"
)

// TestAudit281ColumnPins verifies the three acronym-heavy fields carry an
// explicit gorm column: tag pinning the EXISTING GORM-mangled physical column
// name (prod's AutoMigrate already created these). The pin locks the schema
// against future NamingStrategy drift WITHOUT requiring a migration — which
// holds only while the pinned name equals what the default strategy currently
// generates. Both invariants are asserted:
//
//  1. the field has the explicit column: pin (fails if the pin is reverted), and
//  2. the pinned name equals the default NamingStrategy output (proves no
//     column rename / migration is introduced).
func TestAudit281ColumnPins(t *testing.T) {
	ns := schema.NamingStrategy{}
	cases := []struct {
		typ    reflect.Type
		field  string
		wantDB string
	}{
		{reflect.TypeOf(SystemStatus{}), "IPSVersion", "ip_s_version"},
		{reflect.TypeOf(SecurityStats{}), "WFHTTPSBlocked", "wf_http_s_blocked"},
		{reflect.TypeOf(TrapEvent{}), "TrapOID", "trap_o_id"},
	}
	for _, c := range cases {
		f, ok := c.typ.FieldByName(c.field)
		if !ok {
			t.Fatalf("%s.%s not found", c.typ.Name(), c.field)
		}
		// (1) explicit pin present — this is what a revert removes.
		gormTag := f.Tag.Get("gorm")
		if !strings.Contains(gormTag, "column:"+c.wantDB) {
			t.Errorf("%s.%s: gorm tag %q missing pin column:%s (AUDIT-281 pin reverted?)", c.typ.Name(), c.field, gormTag, c.wantDB)
		}
		// (2) pin equals the current default mangled name → no migration needed.
		if got := ns.ColumnName("", c.field); got != c.wantDB {
			t.Errorf("%s.%s: default NamingStrategy now produces %q, pin is %q — pin no longer matches prod's physical column", c.typ.Name(), c.field, got, c.wantDB)
		}
	}
}
