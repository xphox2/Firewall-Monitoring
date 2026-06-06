package shell

import (
	"encoding/json"
	"os"
	"testing"
)

// TestPackageJsonNoStaleVersion_AUDIT134 pins that package.json no longer
// carries a hard-coded version field (it was stale at 0.10.157 and read by
// nothing — Tailwind tooling doesn't use it). The package is marked private
// instead, so npm needs no version and none can go stale. The app version
// lives in cmd/api/main.go ServerVersion.
func TestPackageJsonNoStaleVersion_AUDIT134(t *testing.T) {
	const path = "../../package.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("package.json not found at %s; err: %v", path, err)
	}

	var pkg map[string]any
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatalf("package.json is not valid JSON (AUDIT-134): %v", err)
	}

	if _, ok := pkg["version"]; ok {
		t.Errorf("package.json still has a \"version\" field (AUDIT-134): it's unused and goes stale — remove it. The app version lives in cmd/api/main.go ServerVersion.")
	}
	if priv, _ := pkg["private"].(bool); !priv {
		t.Error("package.json should be marked \"private\": true (AUDIT-134) so npm needs no version field.")
	}
}
