package relay

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// TestSchemaVersionBounds locks the handshake-constant invariants. These MUST
// stay in lockstep with the Firewall-Collector repo; a bad edit here (Min > Max,
// or a non-positive floor) would make the server reject every probe with HTTP
// 426 or accept versions it can't speak.
func TestSchemaVersionBounds(t *testing.T) {
	if SchemaVersionMin < 1 {
		t.Errorf("SchemaVersionMin = %d, must be >= 1", SchemaVersionMin)
	}
	if SchemaVersionMin > SchemaVersionMax {
		t.Errorf("SchemaVersionMin (%d) > SchemaVersionMax (%d)", SchemaVersionMin, SchemaVersionMax)
	}
}

// TestNoDriftingTelemetryDTOs guards the AUDIT-211 decision: the telemetry
// wire-contract types (FlowSample, SyslogMessage, TrapEvent, PingResult,
// registration/heartbeat DTOs, …) live in internal/models on the server side
// and in the Firewall-Collector repo on the sender side — NOT here. This
// package holds ONLY the schema-version handshake consts and the v4
// command-channel DTOs the server actually consumes. Re-adding a telemetry
// struct here would resurrect the drifting duplicate this audit removed, so
// this test fails if relay.go declares any type other than the two survivors.
func TestNoDriftingTelemetryDTOs(t *testing.T) {
	allowed := map[string]bool{
		"PendingCommand":       true,
		"CommandResultRequest": true,
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "relay.go", nil, 0)
	if err != nil {
		t.Fatalf("parse relay.go: %v", err)
	}

	var declared []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			declared = append(declared, ts.Name.Name)
			if !allowed[ts.Name.Name] {
				t.Errorf("relay.go declares type %q — telemetry/wire DTOs belong in "+
					"internal/models (server) and the Firewall-Collector repo, not "+
					"internal/relay; only the command-channel DTOs may live here", ts.Name.Name)
			}
		}
	}

	sort.Strings(declared)
	if len(declared) != len(allowed) {
		t.Errorf("relay.go declares types %v; expected exactly the 2 command-channel DTOs", declared)
	}
}
