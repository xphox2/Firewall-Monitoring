package shell

import (
	"os"
	"strings"
	"testing"
)

// TestFormatDate_LocaleAware_AUDIT128 is a static regression
// for the audit: `formatDate` and `formatDateShort` in
// `admin-common.js` used to hardcode `toLocaleString('en-US', ...)`,
// which made the admin UI display US-format dates (MM/DD/YYYY,
// 12-hour AM/PM) to every operator regardless of their actual
// locale. The fix uses the browser's `navigator.language` with
// a fallback to `'en-US'`. The format is preserved; only the
// locale-awareness changes.
//
// The test pins four invariants:
//  1. The hardcoded `'en-US'` argument to `toLocaleString` is
//     gone from both `formatDate` and `formatDateShort`.
//  2. A `getBrowserLocale()` helper exists and is the source
//     of the locale argument.
//  3. The audit ID is referenced in a comment (so the fix
//     rationale is documented).
func TestFormatDate_LocaleAware_AUDIT128(t *testing.T) {
	const path = "../../cmd/api/static/js/admin-common.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("admin-common.js not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// 1. The hardcoded 'en-US' first-arg to toLocaleString is gone.
	// We look for `toLocaleString('en-US',` exactly — a future
	// agent who copy-pastes a pre-fix-style call fails here.
	if strings.Contains(body, "toLocaleString('en-US',") {
		t.Errorf("admin-common.js still has `toLocaleString('en-US', ...)` calls (AUDIT-128: the audit's fix is to use `getBrowserLocale()` so the date format follows the browser's language).")
	}

	// 2. The getBrowserLocale helper exists.
	if !strings.Contains(body, "function getBrowserLocale") {
		t.Errorf("admin-common.js is missing the `getBrowserLocale()` helper (AUDIT-128: the helper is the source-of-truth for the locale; without it, a future refactor that adds another toLocaleString call would have to re-derive the locale logic).")
	}
	// And the helper is actually used by the formatDate functions.
	if !strings.Contains(body, "d.toLocaleString(getBrowserLocale(),") {
		t.Errorf("admin-common.js defines getBrowserLocale() but doesn't use it in toLocaleString; the helper exists but the audit's fix is not wired up.")
	}

	// 3. The audit ID is referenced.
	if !strings.Contains(body, "AUDIT-128") {
		t.Errorf("admin-common.js's getBrowserLocale comment no longer references AUDIT-128; the locale-awareness rationale is undocumented.")
	}
}
