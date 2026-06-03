package shell

import (
	"os"
	"strings"
	"testing"
)

// TestIRCIife_Wrapped_AUDIT050 is a static regression for the audit:
// `cmd/api/static/js/admin-irc.js` was NOT IIFE-wrapped, so its module state
// (`let servers/channels/commands`) and every function leaked onto the global
// window object — inconsistent with every other admin-*.js file and the
// lessons.md "Blank Admin Pages" guidance. The fix wraps the whole file in an
// IIFE with 'use strict' and converts the top-level declarations to `var`.
// (Full ES6->ES5 body conversion is tracked separately as AUDIT-131.)
func TestIRCIife_Wrapped_AUDIT050(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-irc.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-irc.js not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// The top-level `let` leak must be gone.
	if strings.Contains(body, "\nlet servers = []") {
		t.Errorf("admin-irc.js still declares `let servers` at top level (AUDIT-050): module state must live inside the IIFE as `var`, not leak to window.")
	}
	for _, sig := range []string{
		"AUDIT-050",          // traceability
		"(function () {",     // IIFE open
		"'use strict';",      // strict mode
		"var servers = [];",  // converted top-level state
		"})(); // AUDIT-050", // IIFE close marker
	} {
		if !strings.Contains(body, sig) {
			t.Errorf("admin-irc.js missing the %q signal (AUDIT-050): the file must be IIFE-wrapped so nothing leaks to the global scope.", sig)
		}
	}
}
