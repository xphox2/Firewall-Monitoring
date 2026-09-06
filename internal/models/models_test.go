package models

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// AUDIT-117: first tests for internal/models. The package is mostly struct
// definitions, but the GORM TableName() methods are copy-paste-prone — a
// duplicated or mistyped table name silently points two models at the same
// table (data corruption) or breaks migration. This test pins every model's
// table name to be unique and snake_case, and exercises the one ToJSON helper.

// tabler is the GORM interface every model's TableName() satisfies.
type tabler interface {
	TableName() string
}

// allTablers lists every model that declares an explicit TableName(). When you
// add a model with a TableName() method, add it here so the uniqueness guard
// keeps covering it — TestTableNames_CoversEveryModel_AUDIT207 FAILS the build
// if this list ever drifts from the set of TableName() methods in the package,
// so a new model with a colliding or mis-cased table name cannot slip past.
func allTablers() []tabler {
	return []tabler{
		ProcessorStats{}, AlertPolicy{}, AlertRule{}, DeviceAlertConfig{},
		SiteAlertConfig{}, MaintenanceWindow{}, SchemaMigration{}, SystemStatus{},
		InterfaceStats{}, VPNStatus{}, HAStatus{}, SecurityStats{}, SDWANHealth{},
		LicenseInfo{}, HardwareSensor{}, TrapEvent{}, Alert{}, UptimeRecord{},
		ProcessedBatch{}, LoginAttempt{}, Device{}, DeviceTunnel{}, DeviceConnection{},
		InterfaceAddress{}, SystemSetting{}, Admin{}, Site{}, Probe{}, ProbeApproval{},
		ProbeHeartbeat{}, PingResult{}, PingStats{}, SyslogMessage{}, SyslogSummary{}, SyslogIngestHourly{},
		FlowSample{}, FlowRollup{}, SiteDatabase{}, SiteDevice{}, SiteSystemStatus{},
		SiteInterfaceStats{}, SiteTrapEvent{}, SiteAlert{}, SitePingResult{},
		SitePingStats{}, IRCServer{}, IRCChannel{}, IRCCommand{}, IRCMessageLog{},
		SiteSyslogMessage{},
		// AUDIT-207: the 20 models the hand-list previously omitted.
		ServerMetric{}, EventRule{}, EventRuleProfile{}, EventRuleProfileToggle{},
		Incident{}, DiskUsage{}, LoadAverage{}, TopologyEntry{}, TopologyNeighbor{},
		AdminRecoveryCode{}, ApiToken{}, ProbeCommand{}, IPSecTunnel{}, DeniedEvent{},
		ThreatIntel{}, ThreatFeedStatus{}, FlowSourceSuppression{}, FlowInterfaceCounter{},
		AgentDrops{}, FlowDetection{},
	}
}

var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func TestTableNames_UniqueAndSnakeCase_AUDIT117(t *testing.T) {
	t.Parallel()
	seen := map[string]string{} // table name -> first model type that claimed it
	for _, m := range allTablers() {
		name := m.TableName()
		typeName := fmt.Sprintf("%T", m)

		if name == "" {
			t.Errorf("%s.TableName() is empty", typeName)
			continue
		}
		if !snakeCase.MatchString(name) {
			t.Errorf("%s.TableName() = %q is not snake_case", typeName, name)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("duplicate table name %q claimed by both %s and %s", name, prev, typeName)
			continue
		}
		seen[name] = typeName
	}
}

// tableNameReceiversFromSource parses the package's own source and returns the
// set of type names that declare a `func (T) TableName() string` method. This is
// the canonical, self-maintaining enumeration: it needs no hand-edit when a
// model is added, so it cannot silently drift the way the old 49-entry slice did.
func tableNameReceiversFromSource(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	// Test CWD is the package directory. Parse only the non-test sources.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	recvs := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Name.Name != "TableName" {
				continue
			}
			expr := fn.Recv.List[0].Type
			if star, ok := expr.(*ast.StarExpr); ok { // pointer receiver
				expr = star.X
			}
			if id, ok := expr.(*ast.Ident); ok {
				recvs[id.Name] = true
			}
		}
	}
	return recvs
}

// TestTableNames_CoversEveryModel_AUDIT207 makes the completeness check
// self-maintaining. It cross-checks the hand-maintained allTablers() slice
// against the canonical set of TableName() receivers discovered by parsing the
// package source, and fails on ANY divergence in either direction. A new model
// with a TableName() method that is not added to allTablers() fails here (and so
// escapes the uniqueness/snake_case guard no longer — the whole point of
// AUDIT-207, since 20 models were previously unchecked). A stale entry in
// allTablers() also fails, so the list cannot rot.
func TestTableNames_CoversEveryModel_AUDIT207(t *testing.T) {
	t.Parallel()
	source := tableNameReceiversFromSource(t)

	listed := map[string]bool{}
	for _, m := range allTablers() {
		listed[reflect.TypeOf(m).Name()] = true
	}

	var missing, stale []string
	for name := range source {
		if !listed[name] {
			missing = append(missing, name)
		}
	}
	for name := range listed {
		if !source[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)

	if len(source) == 0 {
		t.Fatal("no TableName() receivers discovered from source — parser regression")
	}
	if len(missing) > 0 {
		t.Errorf("allTablers() is missing %d model(s) that declare TableName(): %v\n"+
			"add them so the uniqueness/snake_case guard covers every table", len(missing), missing)
	}
	if len(stale) > 0 {
		t.Errorf("allTablers() lists %d name(s) with no TableName() method in source: %v", len(stale), stale)
	}
	if len(source) != len(listed) {
		t.Errorf("count mismatch: %d TableName() methods in source, %d in allTablers()", len(source), len(listed))
	}
}

func TestSystemStatus_ToJSON_AUDIT117(t *testing.T) {
	t.Parallel()
	s := &SystemStatus{DeviceID: 42, CPUUsage: 17.5, MemoryUsage: 60}
	out := s.ToJSON()

	if out == "" || out == "{}" {
		t.Fatalf("ToJSON returned empty/degraded output: %q", out)
	}
	// Must be valid JSON that round-trips the key fields.
	var back SystemStatus
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("ToJSON produced invalid JSON: %v\n%s", err, out)
	}
	if back.DeviceID != 42 || back.CPUUsage != 17.5 || back.MemoryUsage != 60 {
		t.Errorf("ToJSON round-trip mismatch: %+v", back)
	}
}
