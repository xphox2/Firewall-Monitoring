package shell

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestGoModDepMinimums_AUDIT018 pins the security-relevant dependency floors
// bumped for AUDIT-018 so a future change can't silently downgrade them back to
// CVE-affected versions. The live gate is the `govulncheck` job in ci.yml; this
// is a fast static backstop that names the audit and fails loudly on a
// regression (e.g. a careless `go get -u` that reverts a pin).
func TestGoModDepMinimums_AUDIT018(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	body := string(data)
	mins := map[string]string{
		"github.com/gin-gonic/gin":     "1.10.1", // 1.9.1 had CVEs
		"github.com/golang-jwt/jwt/v5": "5.2.2",  // 5.2.0 missing CVE fixes
		"github.com/gosnmp/gosnmp":     "1.40.0",
		"golang.org/x/net":             "0.53.0", // GO-2026-4918 (v0.10.385); was 0.38.0 floor
	}
	for mod, min := range mins {
		got := modVersion(body, mod)
		if got == "" {
			t.Errorf("%s not found in go.mod (AUDIT-018 floor v%s)", mod, min)
			continue
		}
		if semverLess(got, min) {
			t.Errorf("%s = v%s, below the AUDIT-018 floor v%s — do not downgrade (CVE-affected)", mod, got, min)
		}
	}
}

// TestGoDirectiveMinimum_AUDIT018 pins the `go` directive floor. govulncheck
// evaluates stdlib CVEs against the Go version the module declares, so a
// downgrade of this directive silently re-introduces dozens of "affected by Go
// standard library" findings and re-reds the govulncheck CI job (v0.10.385).
func TestGoDirectiveMinimum_AUDIT018(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	re := regexp.MustCompile(`(?m)^go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	m := re.FindStringSubmatch(string(data))
	if len(m) < 2 {
		t.Fatal("no `go` directive found in go.mod")
	}
	got := m[1]
	if strings.Count(got, ".") < 2 {
		got += ".0" // normalize `go 1.25` → 1.25.0 for the 3-part compare
	}
	const min = "1.25.0" // patched stdlib floor for govulncheck (v0.10.385)
	if semverLess(got, min) {
		t.Errorf("go directive = %s, below the govulncheck stdlib floor %s — a downgrade re-reds the govulncheck CI job (AUDIT-018/v0.10.385)", m[1], min)
	}
}

func modVersion(goMod, module string) string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(module) + `\s+v([0-9]+\.[0-9]+\.[0-9]+)`)
	m := re.FindStringSubmatch(goMod)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func semverLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		ai, _ := strconv.Atoi(pa[i])
		bi, _ := strconv.Atoi(pb[i])
		if ai != bi {
			return ai < bi
		}
	}
	return false
}
