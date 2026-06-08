package models

import (
	"encoding/json"
	"fmt"
	"regexp"
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
// keeps covering it.
func allTablers() []tabler {
	return []tabler{
		ProcessorStats{}, AlertPolicy{}, AlertRule{}, DeviceAlertConfig{},
		SiteAlertConfig{}, MaintenanceWindow{}, SchemaMigration{}, SystemStatus{},
		InterfaceStats{}, VPNStatus{}, HAStatus{}, SecurityStats{}, SDWANHealth{},
		LicenseInfo{}, HardwareSensor{}, TrapEvent{}, Alert{}, UptimeRecord{},
		ProcessedBatch{}, LoginAttempt{}, Device{}, DeviceTunnel{}, DeviceConnection{},
		InterfaceAddress{}, SystemSetting{}, Admin{}, Site{}, Probe{}, ProbeApproval{},
		ProbeHeartbeat{}, PingResult{}, PingStats{}, SyslogMessage{}, SyslogSummary{},
		FlowSample{}, FlowRollup{}, SiteDatabase{}, SiteDevice{}, SiteSystemStatus{},
		SiteInterfaceStats{}, SiteTrapEvent{}, SiteAlert{}, SitePingResult{},
		SitePingStats{}, IRCServer{}, IRCChannel{}, IRCCommand{}, IRCMessageLog{},
		SiteSyslogMessage{},
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
