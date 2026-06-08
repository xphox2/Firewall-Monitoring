package shell

import (
	"os"
	"strings"
	"testing"
)

// TestStructuredLogging_FoundationExists_AUDIT076 pins the slog adoption:
// the `internal/logging` package must install slog as the default logger AND
// bridge the legacy `log` package through it (via slog.SetDefault). That bridge
// is the zero-churn mechanism the audit relies on — it upgrades all ~460 legacy
// log.Printf sites to structured output at once. If a future change drops the
// SetDefault call, the bridge silently breaks and every legacy log line goes
// back to an unstructured stderr write.
func TestStructuredLogging_FoundationExists_AUDIT076(t *testing.T) {
	const path = "../logging/logging.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("internal/logging/logging.go not found at %s; err: %v", path, err)
	}
	body := string(data)

	for _, want := range []string{"slog.SetDefault", "ReplaceAttr", "redactSecrets"} {
		if !strings.Contains(body, want) {
			t.Errorf("internal/logging/logging.go no longer references %q (AUDIT-076); the structured-logging foundation (slog default + stdlib bridge + credential redaction) must stay intact.", want)
		}
	}
}

// TestStructuredLogging_ChokepointsUseSlog_AUDIT076 guards the two hot logging
// chokepoints. httputil.InternalError (every handler 500) and
// middleware.RequestLogger (every failed request) were converted from a flat
// log.Printf to native slog records with queryable attributes. A regression to
// log.Printf there would re-flatten the highest-volume structured signals.
func TestStructuredLogging_ChokepointsUseSlog_AUDIT076(t *testing.T) {
	checks := []struct {
		path    string
		mustHave string
		marker   string // a snippet that must NOT reappear as a log.Printf
	}{
		{"../httputil/httputil.go", "slog.LogAttrs", `log.Printf("HTTP 500`},
		{"../api/middleware/middleware.go", "slog.LogAttrs", `log.Printf("[%s] req=`},
	}
	for _, c := range checks {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Skipf("%s not found; err: %v", c.path, err)
			continue
		}
		body := string(data)
		if !strings.Contains(body, c.mustHave) {
			t.Errorf("%s no longer calls %s (AUDIT-076); the chokepoint must emit a native slog record.", c.path, c.mustHave)
		}
		if strings.Contains(body, c.marker) {
			t.Errorf("%s reverted a chokepoint to %q (AUDIT-076); it must use slog, not a flat log.Printf.", c.path, c.marker)
		}
	}
}
