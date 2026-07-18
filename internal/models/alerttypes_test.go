package models

import (
	"os"
	"regexp"
	"testing"
)

// TestAllAlertTypes_CoverEveryAlertType is the registry guardrail: it parses
// every AlertType constant out of models.go (same regex discipline as
// alerts.TestRuleSource_CoversEveryAlertType) and asserts set-equality with
// AllAlertTypes(), minus the single documented exclusion. A new alert type
// added without a registry entry — or a registry entry for a type that no
// longer exists — fails CI here, which is what keeps the toggle matrix and
// the auto-push-down promise honest.
func TestAllAlertTypes_CoverEveryAlertType(t *testing.T) {
	data, err := os.ReadFile("models.go")
	if err != nil {
		// Fatal, not Skip: a rename/move of models.go must not silently vacate
		// the guardrail.
		t.Fatalf("models.go not readable (guardrail must not be skipped): %v", err)
	}
	re := regexp.MustCompile(`AlertType\s*=\s*"([A-Z0-9_]+)"`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	if len(matches) < 20 {
		t.Fatalf("suspiciously few AlertType constants parsed (%d) — regex or file moved?", len(matches))
	}
	// TEST_ALERT is a wiring probe, never operator-tunable. *_RESOLVED
	// companions are not constants in models.go, so they need no exclusion.
	excluded := map[string]bool{"TEST_ALERT": true}

	registry := map[AlertType]AlertTypeInfo{}
	for _, info := range AllAlertTypes() {
		if info.Family == "" || info.Description == "" {
			t.Errorf("registry entry %s missing family or description", info.Type)
		}
		if _, dup := registry[info.Type]; dup {
			t.Errorf("registry lists %s twice", info.Type)
		}
		registry[info.Type] = info
	}

	constants := map[AlertType]bool{}
	for _, m := range matches {
		name := AlertType(m[1])
		constants[name] = true
		if excluded[string(name)] {
			if _, present := registry[name]; present {
				t.Errorf("excluded type %s must NOT appear in the registry", name)
			}
			continue
		}
		if _, present := registry[name]; !present {
			t.Errorf("alert type %s missing from AllAlertTypes() — every new type must be registered (family + description) so the toggle matrix and rule builder see it", name)
		}
	}
	for at := range registry {
		if !constants[at] {
			t.Errorf("registry entry %s has no matching AlertType constant in models.go — remove or fix it", at)
		}
	}
}

func TestTogglableAlertType(t *testing.T) {
	if !TogglableAlertType(AlertTypeDeviceOffline) {
		t.Error("DEVICE_OFFLINE must be togglable")
	}
	if TogglableAlertType(AlertTypeTestAlert) {
		t.Error("TEST_ALERT must not be togglable")
	}
	if TogglableAlertType(AlertType("NOT_A_REAL_TYPE")) {
		t.Error("unknown types must not be togglable")
	}
}
