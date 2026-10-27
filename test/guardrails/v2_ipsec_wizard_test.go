package guardrails

import (
	"regexp"
	"strings"
	"testing"
)

// The IPSec wizard is the LAST critical parity gap: the V2 console could list,
// deploy, roll back and delete a tunnel, but not AUTHOR one, so a tunnel could
// never be provisioned from it at all.
//
// The tests below pin the two things that go wrong most easily in a form that
// talks to a server-owned contract:
//
//   - the ENDPOINTS it calls. A wizard that posts to the wrong path, or
//     forgets the preview, either fails at runtime or silently writes an
//     invalid intent.
//   - the FIELDS it sends. `enabled` omitted is FALSE, so a tunnel would be
//     saved DISABLED; `dpd` and `mss_clamp` omitted raise spurious warnings;
//     and the mode must come from the vendors' INTERSECTION, because OPNsense
//     is policy-based only and a hardcoded "route-based" is wrong for every
//     OPNsense pair.
//
// The field rules are unit-tested in ui-v2/src/lib/ipsec.test.ts. These guard
// the WIRING, which a unit test cannot see.

// TestV2IpsecWizardCallsTheRightEndpoints pins the wizard's HTTP calls.
func TestV2IpsecWizardCallsTheRightEndpoints(t *testing.T) {
	wizard := readV2(t, "components/topology/ipsec-wizard.tsx")

	for _, needle := range []string{
		// The stateless preview of the unsaved intent.
		"'/admin/api/ipsec/preview'",
		// The capabilities of the vendor PAIR, which is what limits the
		// crypto options and the mode.
		"/admin/api/ipsec/capabilities?a=",
		// The device's real interfaces, addresses and suggestions.
		"/ipsec-hints",
		// Create and update.
		"'/admin/api/ipsec/tunnels'",
		"/admin/api/ipsec/tunnels/${tunnelId}",
	} {
		if !strings.Contains(wizard, needle) {
			t.Errorf("the IPSec wizard does not call %q — the endpoint the server exposes for it", needle)
		}
	}

	// The preview is a POST, and the create is a POST while the update is a
	// PUT. A wizard that POSTs the update would create a second tunnel.
	if !regexp.MustCompile(`const body = buildIntent\(form\);\s*const res = await apiFetch<PreviewResponse>\('/admin/api/ipsec/preview',\s*\{\s*method:\s*'POST',\s*body,`).MatchString(wizard) {
		t.Error("the IPSec wizard does not POST the built intent to the preview endpoint")
	}
	// Save needs a preview of THIS design. The tabs are free, and an edit
	// made after a clean preview was once saved on the old preview's
	// strength - the intent the server stored was never validated.
	code := stripComments(wizard)
	if !strings.Contains(code, "setPreviewedIntent(JSON.stringify(body))") ||
		!strings.Contains(code, "previewedIntent === currentIntent") ||
		!strings.Contains(code, "disabled={saving || !previewIsCurrent || blocking.length > 0}") {
		t.Error("the IPSec wizard's Save is not gated on a preview of the CURRENT intent — a stale preview can stand in for a changed design")
	}
	if !regexp.MustCompile(`method:\s*'PUT',\s*body\s*\}`).MatchString(wizard) {
		t.Error("the IPSec wizard does not PUT the built intent to the update endpoint - POSTing it would create a second tunnel")
	}
}

// TestV2IpsecWizardTakesTheModeFromTheIntersection pins the mode.
//
// The vendors' INTERSECTION is the authority (GET /admin/api/ipsec/capabilities
// returns `allowed`, whose `modes` is the intersection). OPNsense supports
// policy-based only, so a hardcoded default is wrong for every OPNsense pair.
func TestV2IpsecWizardTakesTheModeFromTheIntersection(t *testing.T) {
	wizard := readV2(t, "components/topology/ipsec-wizard.tsx")
	// The MODE SELECT is what the operator chooses from, so that is what has
	// to be driven by the intersection. Matching the bare `allowed?.modes`
	// anywhere would be satisfied by the code that reads the capabilities,
	// and the select could still offer a hardcoded list.
	if !regexp.MustCompile(`\(\s*caps\?\.allowed\?\.modes\s*\?\?`).MatchString(wizard) {
		t.Error("the IPSec wizard's mode select is not driven by the allowed modes from the capability intersection - the mode must come from the vendors' intersection, not a hardcoded list")
	}
}

// TestV2IpsecWizardPreservesTheStoredPsk pins the PSK round-trip.
//
// The mask means two OPPOSITE things on the same token: on create it means
// "generate one", on edit it means "unchanged". An edit that replaced the
// mask with an empty string still means "unchanged" (the server folds the
// stored key back), but an edit that dropped the stored PSK from the form
// would send an empty one — which on a CREATE means "generate", so a copy of
// an existing tunnel would silently get a new key.
func TestV2IpsecWizardPreservesTheStoredPsk(t *testing.T) {
	wizard := readV2(t, "components/topology/ipsec-wizard.tsx")
	if !strings.Contains(wizard, "PSK_MASK") {
		t.Error("the IPSec wizard does not handle the PSK mask - an edit that dropped it would send an empty PSK, which on a create means 'generate a new key'")
	}
	lib := readV2(t, "lib/ipsec.ts")
	if !strings.Contains(lib, "PSK_MASK = '********'") {
		t.Error("lib/ipsec.ts does not define the server's PSK mask - the server's mask is exactly \"********\" and a different string would be sent as a NEW key")
	}
}

// TestV2IpsecWizardRendersTheStepCount pins the preview's `steps`.
//
// The preview's per-end `steps` is an integer COUNT of the apply steps, not
// the steps themselves - the rendered steps carry the plaintext PSK and are
// never returned. A wizard that rendered it as a list would show a number
// where config belongs.
// TestV2IpsecWizardCanonicalisesThePathKeys pins the path keys.
//
// The server compares the stored disabled-path key EXACTLY against its own
// canonical form, and a key it does not recognise is a SILENT FAIL-OPEN: the
// path stays ENABLED even though the operator turned it off, and the server
// raises only a warning. The console's paths table therefore has to build
// the key with the shared canonicaliser, not from the raw subnet strings.
func TestV2IpsecWizardCanonicalisesThePathKeys(t *testing.T) {
	wizard := readV2(t, "components/topology/ipsec-wizard.tsx")
	if !strings.Contains(wizard, "pathKey(aNet, bNet)") {
		t.Error("the IPSec wizard's paths table does not build the key with pathKey - a raw key is a silent fail-open, because the server compares the stored key exactly against its own canonical form")
	}
	if regexp.MustCompile(`aNet\}\|\$\{bNet`).MatchString(wizard) {
		t.Error("the IPSec wizard's paths table builds a path key from the raw subnet strings - that key would never match the server's canonical form")
	}
}

// TestV2IpsecWizardRestoresTheProfileUnconditionally pins the profile
// reconstruction.
//
// The intent stores the RESOLVED crypto, not the profile's name, so the edit
// path has to infer it. The inference has to be applied INCLUDING the Custom
// case: leaving the profile alone showed "Modern" for a Custom tunnel, and
// the save then silently replaced its crypto with the Modern preset.
func TestV2IpsecWizardRestoresTheProfileUnconditionally(t *testing.T) {
	wizard := readV2(t, "components/topology/ipsec-wizard.tsx")
	if !strings.Contains(wizard, "restoreCrypto(") {
		t.Error("the IPSec wizard does not infer the profile from the stored crypto")
	}
	// The assignment must not be conditional on the result NOT being custom.
	// Any mention of the condition at all is the bug: the correct code
	// assigns the inferred profile unconditionally.
	if strings.Contains(wizard, "!restored.custom") {
		t.Error("the IPSec wizard only assigns the profile when it is NOT custom - a Custom tunnel would be shown as a preset and silently rewritten on save")
	}
	if !strings.Contains(wizard, "next.profile = restored.profile") {
		t.Error("the IPSec wizard does not assign the inferred profile - a Custom tunnel would keep the previous session's profile and be silently rewritten on save")
	}
	// The inference must run on EDIT ONLY. The create form's custom crypto is
	// an EMPTY placeholder, which matches no preset, so running the
	// inference there flipped the default profile to "Custom" with empty
	// selectors - and the operator never touched the dropdown.
	if !regexp.MustCompile(`isEdit\s*&&\s*next\.profiles\.length\s*>\s*0`).MatchString(wizard) {
		t.Error("the IPSec wizard reconstructs the profile on CREATE as well as on edit - the create form's empty custom crypto matches no preset, so the profile would flip to Custom with empty selectors")
	}
}

func TestV2IpsecWizardRendersTheStepCount(t *testing.T) {
	wizard := readV2(t, "components/topology/ipsec-wizard.tsx")
	if !strings.Contains(wizard, "end.steps") {
		t.Error("the IPSec wizard does not render the preview's step count - `steps` is an integer COUNT, not the step list")
	}
	if !strings.Contains(wizard, "end.preview") {
		t.Error("the IPSec wizard does not render the preview's configuration text - `preview` is the rendered native config")
	}
}

// TestV2IpsecWizardReadsTheFindingEndCorrectly pins the finding scope.
//
// `end` is a POINTER on the server: it is ABSENT for a tunnel-wide finding and
// 0 for the FIRST end. A plain `if (finding.end)` drops end A, because 0 is
// falsy in JavaScript.
func TestV2IpsecWizardReadsTheFindingEndCorrectly(t *testing.T) {
	wizard := readV2(t, "components/topology/ipsec-wizard.tsx")
	// Any TRUTHINESS test on the end pointer drops end A, because 0 is
	// falsy in JavaScript. A comparison (`=== 0`) is fine; `&&` and `?` on
	// the bare value are not.
	if regexp.MustCompile(`\.end\s*(&&|\?)`).MatchString(wizard) {
		t.Error("the IPSec wizard tests the finding's end for truthiness - end 0 is the FIRST end, and 0 is falsy in JavaScript, so end A's findings would be dropped")
	}
	if !strings.Contains(wizard, "findingScope") {
		t.Error("the IPSec wizard does not use the shared findingScope helper, which reads the end pointer correctly")
	}
}

// TestV2IpsecWizardGatesEditOnTheServerRule pins the edit gate.
//
// A tunnel with a deploy record cannot be edited until it is rolled back: the
// server answers 409. The list response states that per row as `editable`, so
// the button can follow the SERVER's rule rather than approximating it from
// the status.
func TestV2IpsecWizardGatesEditOnTheServerRule(t *testing.T) {
	workspace := readV2(t, "pages/TopologyWorkspace.tsx")
	if !strings.Contains(workspace, "editable === false") {
		t.Error("the IPSec tab does not gate the Edit button on the server's `editable` rule - a tunnel with a deploy record answers 409 until it is rolled back")
	}
}
