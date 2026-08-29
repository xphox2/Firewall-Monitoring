package shell

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// allowedUndocumentedEnvKeys are env keys config.go reads that are DELIBERATELY
// absent from config.env.example, each with the reason it has no line there.
// Keep this list as small as possible — the default is that every key config.go
// reads gets a documented line.
var allowedUndocumentedEnvKeys = map[string]string{
	// CONFIG_FILE is the bootstrap pointer AT this file. The file's header says
	// it "cannot be set inside this file itself", so it has no KEY= line here.
	"CONFIG_FILE": "bootstrap: names this file; cannot be set inside it",
}

// TestConfigEnvExample_DocumentsEveryConfigGoKey guards AUDIT-240 and enforces
// config.env.example's own promise to document every variable the server reads:
// every environment key internal/config/config.go reads must appear in
// config.env.example (a commented-out `# KEY=` line counts as documented).
// Pre-fix the file was missing ~22 live keys — PUBLIC_BASE_URL,
// SPIKE_MIN_THROUGHPUT_MBPS, RETENTION_DENIED_EVENT_DAYS, and the whole
// DETECT_DDOS_* / DETECT_DENY_STORM_* / DETECT_DENIED_THEN_ALLOWED_* /
// DETECT_SAMPLING_RATE_CHANGE_* families — while claiming to be a complete
// inventory. This is the highest-value anti-drift guard: a new config knob can
// no longer ship without a line in this file.
func TestConfigEnvExample_DocumentsEveryConfigGoKey(t *testing.T) {
	cfgSrc, err := os.ReadFile("../config/config.go")
	if err != nil {
		t.Fatalf("read internal/config/config.go: %v", err)
	}
	example, err := os.ReadFile("../../config.env.example")
	if err != nil {
		t.Fatalf("read config.env.example: %v", err)
	}
	body := string(example)

	// Capture the first (key) argument of every env read: the getXxxEnv helper
	// family (getEnv/getIntEnv/getFloatEnv/getBoolEnv/getDurationEnv) plus the
	// raw os.Getenv / os.LookupEnv calls. Helper bodies read os.Getenv(key) with
	// a variable, not a string literal, so they never match.
	keyRe := regexp.MustCompile(`(?:get(?:Int|Float|Bool|Duration)?Env|os\.Getenv|os\.LookupEnv)\("([A-Z][A-Z0-9_]*)"`)
	matches := keyRe.FindAllStringSubmatch(string(cfgSrc), -1)
	if len(matches) == 0 {
		t.Fatal("found no env-var reads in config.go — the capture regex likely broke")
	}

	seen := map[string]bool{}
	var missing []string
	for _, m := range matches {
		key := m[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, ok := allowedUndocumentedEnvKeys[key]; ok {
			continue
		}
		// Every documented key appears as `KEY=` (bare, or after `# ` when
		// commented). The trailing `=` prevents a shorter key from matching
		// inside a longer one (e.g. DETECT_DENY_STORM_MIN_DENIES vs
		// DETECT_DENY_STORM_MIN_DENIES_INTERNAL).
		if !strings.Contains(body, key+"=") {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("config.env.example is missing %d env key(s) that config.go reads (AUDIT-240): %s\n"+
			"Add a documented `KEY=<default>` line for each, or add it to allowedUndocumentedEnvKeys with a reason.",
			len(missing), strings.Join(missing, ", "))
	}
}
