package shell

import (
	"os"
	"strings"
	"testing"
)

// TestAdminCommon_FormatBytesHandlesNaN_AUDIT133 is a static
// regression for the audit: `formatBytes` in admin-common.js used to
// fall through to `Math.log(NaN) / Math.log(1024) = NaN` and the
// chart then rendered "NaN.0 undefined" — a real failure mode when
// a misbehaving device's interface byte count, or a freshly-reset
// probe that hasn't reported yet, returns a non-finite value.
//
// The fix: `if (!isFinite(bytes) || bytes == null) return '—';` at
// the top of the function. The em-dash is consistent with the
// "no data" rendering style used elsewhere in the dashboards.
//
// This test pins three things:
//  1. The fix is in the canonical `formatBytes` in admin-common.js
//     (not a copy-paste in some other file that also defines one).
//  2. The `isFinite` guard is present (so the NaN class of input
//     is rejected before `Math.log` runs).
//  3. The em-dash is the chosen fallback (so a future agent who
//     "fixes" the test by changing the return value to "0 B" or
//     "N/A" or "?" fails the test — the em-dash matches the
//     existing dashboard no-data convention).
func TestAdminCommon_FormatBytesHandlesNaN_AUDIT133(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-common.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-common.js not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// (1) The fix must be in the file the audit identified. We
	// don't assert "this is the only formatBytes" because
	// admin-connection-detail.js has a separate local copy with
	// a different (and safe) algorithm; the audit was specific to
	// admin-common.js.
	if !strings.Contains(body, "function formatBytes(bytes)") {
		t.Fatalf("admin-common.js no longer defines a `function formatBytes(bytes)`; the canonical home of this helper is here per the audit, and the function shouldn't be moved without updating the test")
	}

	// (2) The isFinite guard must be present. We accept either
	// `!isFinite(bytes)` (strict) or `!isFinite(bytes) || bytes == null`
	// (broader, also catches null) — both shapes guard the NaN
	// path the audit called out.
	if !strings.Contains(body, "!isFinite(bytes)") {
		t.Errorf("admin-common.js formatBytes is missing the `!isFinite(bytes)` guard (AUDIT-133). Add it at the top of the function so NaN/Infinity inputs return the em-dash fallback instead of rendering as 'NaN.0 undefined'.")
	}

	// (3) The em-dash is the chosen fallback. The em-dash is U+2014
	// (—, three bytes in UTF-8: 0xE2 0x80 0x94). Accepting only the
	// literal "—" string pins the design choice: a future agent
	// who "improves" the fallback to "0 B" or "N/A" or "?" would
	// break the "no data" rendering convention the rest of the
	// dashboard uses.
	if !strings.Contains(body, "return '—'") {
		t.Errorf("admin-common.js formatBytes is not returning the em-dash '—' for non-finite inputs (AUDIT-133). The em-dash is the chosen 'no data' marker; using '0 B' or 'N/A' would conflict with the rest of the dashboard's no-data rendering.")
	}
}
