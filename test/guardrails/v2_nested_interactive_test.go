package guardrails

import (
	"strings"
	"testing"
)

// The mobile card must not be a control that CONTAINS controls.
//
// The card used to carry role="button" itself, which made it a button
// that held the row's own buttons - a control inside a control. A screen
// reader announces the card as a button and the buttons inside it live
// inside another button; axe's nested-interactive rule catches it, and it
// is a real defect rather than a rule artefact.
//
// The fix is the stretched-button pattern: the action is a real <button>
// that is a SIBLING of the card's content, and the content's own controls
// sit above it.
//
// This was found by walking the REAL console against a copy of the
// production database - the mocked suite never renders the card's
// buttons, so it never saw it.

// TestV2TheMobileCardIsNotAControlThatContainsControls pins the shape.
func TestV2TheMobileCardIsNotAControlThatContainsControls(t *testing.T) {
	view := readV2(t, "components/ui/responsive-data-view.tsx")
	code := stripComments(view)

	// The card container must not be a button role.
	if strings.Contains(code, `role={onRowClick ? 'button' : undefined}`) {
		t.Error("the mobile card is role=\"button\" - a control that contains the row's own buttons is a control inside a control (axe's nested-interactive rule), and a screen reader announces the card as a button with the buttons inside it")
	}
	if strings.Contains(code, `role="button"`) {
		t.Error("the mobile card carries role=\"button\" - the action must be a real <button> that is a SIBLING of the card's content")
	}

	// The action must be a real button, and it must be a sibling: it is
	// rendered next to the content, not around it.
	if !strings.Contains(code, "<button") {
		t.Error("the mobile card has no real <button> - the action must be a real control")
	}
	if !strings.Contains(code, "aria-label=") {
		t.Error("the mobile card's action has no accessible name - a button with no name is not a control")
	}

	// The content's own controls must still be reachable: the content is
	// pointer-events-none so a press lands on the stretched button, and the
	// controls inside it are put back.
	if !strings.Contains(code, "pointer-events-none") {
		t.Error("the mobile card's content is not pointer-events-none - the press would not reach the action button")
	}
	for _, control := range []string{"[&_button]:pointer-events-auto", "[&_input]:pointer-events-auto", "[&_select]:pointer-events-auto"} {
		if !strings.Contains(code, control) {
			t.Errorf("the mobile card's content does not put %s back - a control inside the card would be unclickable", control)
		}
	}
}

// TestV2TheMobileCardActionHasAName pins that the action is named.
//
// The card's content is caller-provided and may hold its own buttons
// ("Edit"), so the action cannot be named by the whole card text. It is
// named from the row's identity instead.
func TestV2TheMobileCardActionHasAName(t *testing.T) {
	view := readV2(t, "components/ui/responsive-data-view.tsx")
	code := stripComments(view)

	if !strings.Contains(code, "defaultRowLabel") {
		t.Error("the mobile card's action has no name - the row's identity is what names it")
	}
	// The name has to come from a field that identifies the row.
	for _, field := range []string{"name", "device_name", "hostname", "username"} {
		if !strings.Contains(code, "'"+field+"'") {
			t.Errorf("the card's label does not consider the %q field - a row with no name would be announced as \"row 3\"", field)
		}
	}
	// And a caller must be able to override it.
	if !strings.Contains(code, "rowLabel") {
		t.Error("the card has no rowLabel prop - a caller whose rows are named differently cannot name the action")
	}
}
