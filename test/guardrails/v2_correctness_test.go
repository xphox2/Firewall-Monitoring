package guardrails

import (
	"regexp"
	"strings"
	"testing"
)

// The remaining correctness gaps, pinned.
//
// Each of these was a real defect: a control that could not do its job, a
// save that half-applied, or a number that did not tell the truth.

// TestV2ASecretCanBeCleared pins that a stored credential can be REMOVED.
//
// The secret handling is deliberately conservative: a masked or empty value
// means "leave unchanged", because a client that loads a device and saves it
// back resends the mask, and writing the mask over the real secret
// silently breaks SNMP polling.
//
// That left an operator with NO way to remove a credential — an API token
// they no longer want, an SSH password that should not be stored. So
// clearing is an EXPLICIT opt-in, and both halves have to exist: the server
// has to accept it, and the console has to offer it.
func TestV2ASecretCanBeCleared(t *testing.T) {
	// Comments stripped: a comment that names clear_secrets must not satisfy
	// a check that the code sends it.
	server := stripComments(readRepoFile(t, "internal/api/handlers/handlers_devices.go"))
	if !strings.Contains(server, "clear_secrets") {
		t.Error("the server does not accept a clear_secrets opt-in — a stored credential can never be removed, because an empty value means 'leave unchanged'")
	}
	// And the opt-in must be a LIST of names, not a value: it is applied
	// after the mask-or-empty rules, so it cannot be a value.
	if !strings.Contains(server, "clearableDeviceSecrets") {
		t.Error("the server has no allow-list of clearable secrets — the opt-in could name an arbitrary column")
	}

	console := stripComments(readV2(t, "pages/DevicesWorkspace.tsx"))
	if !strings.Contains(console, "body.clear_secrets = pendingClearSecrets") {
		t.Error("the console never sends clear_secrets — the server can clear a credential, but nothing asks it to")
	}
	// EVERY clearable credential is a DeviceSecretField, which is what
	// carries the Clear control. snmp_community was once a hand-rolled input
	// with no Clear and its Reveal button inside the <label>.
	for _, field := range []string{"snmp_community", "snmpv3_auth_pass", "snmpv3_priv_pass", "ssh_password", "api_token"} {
		if !strings.Contains(console, `field="`+field+`"`) {
			t.Errorf("%s is not a DeviceSecretField — it has no Clear control", field)
		}
		if !strings.Contains(console, "onChange={editSecret('"+field+"')}") {
			t.Errorf("%s is not edited through editSecret — a revealed value freezes and a pending Clear survives a new value", field)
		}
	}
}

// TestV2APendingClearBelongsToOneDevice pins that a confirmed Clear is
// forgotten whenever the editor changes hands.
//
// It was once kept across the editor's sessions: a Clear asked for on device
// A - even one followed by Cancel - was sent with the next save of device B,
// and the server wiped B's credential.
func TestV2APendingClearBelongsToOneDevice(t *testing.T) {
	console := stripComments(readV2(t, "pages/DevicesWorkspace.tsx"))
	if !strings.Contains(console, "setPendingClearSecrets([])") {
		t.Fatal("nothing ever empties the pending clears")
	}
	for _, opener := range []string{"const openCreateDrawer = () => {", "const openEditDrawer = (dev: DeviceRecord) => {"} {
		i := strings.Index(console, opener)
		if i < 0 {
			t.Fatalf("%q is gone — re-point this guardrail", opener)
		}
		body := console[i:]
		if end := strings.Index(body, "\n  };"); end > 0 {
			body = body[:end]
		}
		if !strings.Contains(body, "resetSecretState()") {
			t.Errorf("%q does not reset the credential state — a Clear from the previous device would ride along", opener)
		}
	}
	// A Reveal keeps the credential, so it withdraws a pending Clear for
	// that field: the field shows the value, and the save must not remove it.
	if !strings.Contains(console, "setPendingClearSecrets((current) => current.filter((f) => f !== revealField))") {
		t.Error("a Reveal does not withdraw a pending Clear — the field shows the credential while the save removes it")
	}
	// And a revealed credential counts as a stored one, so the Clear control
	// comes back after Clear -> Reveal without reopening the editor.
	hasStored := regexp.MustCompile(`const hasStored =[^;]*;`).FindString(console)
	if !strings.Contains(hasStored, "revealed !== undefined") {
		t.Error("the Clear control ignores a revealed credential — after Clear then Reveal it stays hidden until the editor is reopened")
	}
	// And a credential the device held when the editor OPENED is still held
	// after the operator deletes its mask (an empty value leaves it in place):
	// the Clear control stays and the field reads "Unchanged".
	if !strings.Contains(hasStored, "keptAsIs") || !strings.Contains(console, "hasStoredCredential((openedDevice as Record<string, unknown>)[field])") {
		t.Error("an emptied field on a device that held the credential loses its Clear control — the save leaves the credential in place")
	}
	// Every CLOSE goes through the resetting setter, not the raw one.
	if strings.Contains(console, "onOpenChange={setEditorOpen}") || strings.Contains(console, "setEditorOpen(false)") {
		t.Error("the editor is closed through the raw setter somewhere — that path keeps a pending Clear")
	}
}

// TestV2TheAlertConfigOverrideIsOneWrite pins that the alert config and
// the event profile are written TOGETHER.
//
// They used to be two requests: the console committed the config, then
// assigned the profile. A failure between them left HALF an override
// applied, with a save that reported failure.
func TestV2TheAlertConfigOverrideIsOneWrite(t *testing.T) {
	console := readV2(t, "components/devices/alert-config-drawer.tsx")
	// The profile rides in the alert-config body.
	if !strings.Contains(console, "event_profile_id") {
		t.Error("the alert-config save does not carry the event profile — it is still a second request, so a failure between them leaves half an override applied")
	}
	// And the second request is gone. The check is on the CALL, not on the
	// string: a comment that names the endpoint would otherwise satisfy it.
	if strings.Contains(stripComments(console), "/event-profile") {
		t.Error("the console still writes the event profile through its own endpoint — the two writes are not atomic")
	}

	server := readRepoFile(t, "internal/api/handlers/handlers_alert_policies.go")
	if !strings.Contains(server, "UpsertDeviceAlertConfigWithProfile") {
		t.Error("the server does not write the config and the profile in one transaction")
	}
	// Assigning a profile is admin-only, so the combined write must be
	// gated: a non-admin asking for one is refused, not silently ignored.
	if !strings.Contains(server, "Only admins can assign an event profile") {
		t.Error("the combined alert-config write does not gate the event profile - assigning one is admin-only")
	}
}

// TestV2ThePurgeEstimateIsTruthful pins that the estimate says what it
// knows.
//
// A per-table count is capped, so when any table is capped the TOTAL is a
// LOWER BOUND - the dialog rendered "of 100,000" for a table that holds
// 134 million rows. And the purge refuses a deploying tunnel and a device
// that already has a queued job: the estimate is what the operator reads
// BEFORE they commit, so those blockers belong there.
func TestV2ThePurgeEstimateIsTruthful(t *testing.T) {
	store := readRepoFile(t, "internal/database/purge_jobs.go")
	if !strings.Contains(store, "Capped bool") {
		t.Error("the estimate has no top-level capped flag - a capped per-table count makes the TOTAL a lower bound, and the dialog says so")
	}
	if !strings.Contains(store, "Blockers") {
		t.Error("the estimate has no blockers - the operator only finds out about a refused purge after typing the device's name")
	}

	handler := readRepoFile(t, "internal/api/handlers/handlers_devices_purge.go")
	if !strings.Contains(handler, "est.Blockers") {
		t.Error("the estimate endpoint does not report the blockers")
	}

	console := readV2(t, "components/devices/purge-device-dialog.tsx")
	if !strings.Contains(console, "estimate.capped") {
		t.Error("the purge dialog does not show that the total is a lower bound")
	}
	if !strings.Contains(console, "estimate.blockers") {
		t.Error("the purge dialog does not show the blockers")
	}
}

// TestV2TheToastIsAnnouncedOnce pins that a toast is announced once.
//
// Each toast carries `role="status"`, which is itself a polite live
// region. A live region INSIDE a live region announces the message TWICE:
// once for the container seeing new content, and once for the toast's own
// region.
func TestV2TheToastIsAnnouncedOnce(t *testing.T) {
	toast := readV2(t, "components/ui/toast.tsx")
	if !strings.Contains(toast, `role="status"`) {
		t.Error("the toast does not carry role=\"status\" - it would not be announced at all")
	}
	// The CONTAINER must not be a live region as well.
	if strings.Contains(toast, `aria-live="polite"`) {
		t.Error("the toast container is a live region AND each toast is one - a message in a live region inside a live region is announced TWICE")
	}
}

// TestV2TheMapFallbackFollowsTheTheme pins that the graph's fallback
// colours are the THEME's.
//
// The fallback is used only when the DOM cannot be read, and the old one
// was the dark theme's - so in light mode a read failure painted the whole
// graph dark on a white card.
func TestV2TheMapFallbackFollowsTheTheme(t *testing.T) {
	m := readV2(t, "components/topology/topology-map.tsx")
	for _, needle := range []string{"MAP_FALLBACK_DARK", "MAP_FALLBACK_LIGHT"} {
		if !strings.Contains(m, needle) {
			t.Errorf("the map has no %s - the fallback colours are the dark theme's, so a read failure paints the graph dark in light mode", needle)
		}
	}
	if !strings.Contains(m, "mapFallback()") {
		t.Error("the map does not pick the fallback that matches the theme")
	}
}

// TestV2TheDataViewCanHideAColumnUntilABreakpoint pins the column
// visibility option.
//
// The shared view could hide a column only BELOW the large breakpoint, so
// a column the legacy table hid below `lg` would have vanished at
// 1024-1280px instead - a silent loss of a column in the middle of the
// range of widths.
func TestV2TheDataViewCanHideAColumnUntilABreakpoint(t *testing.T) {
	view := stripComments(readV2(t, "components/ui/responsive-data-view.tsx"))
	if !strings.Contains(view, "hideUntil") {
		t.Error("the shared data view has no hideUntil option - a column the legacy table hid below `lg` would vanish at 1024-1280px instead")
	}
	// The breakpoint classes must be LITERAL. Tailwind only generates a class
	// it finds written out, so a runtime-built `${bp}:table-cell` produced a
	// bare `hidden`: the header vanished at every width.
	for _, bp := range []string{"sm", "md", "lg", "xl"} {
		if !strings.Contains(view, "'hidden "+bp+":table-cell'") {
			t.Errorf("the literal class 'hidden %s:table-cell' is missing — Tailwind will not generate it", bp)
		}
	}
	if strings.Contains(view, ":table-cell`") {
		t.Error("a :table-cell class is built in a template literal — Tailwind cannot see it")
	}
	// The header and the body share ONE helper, so a cell is never shown
	// under a hidden header.
	if n := strings.Count(view, "columnHiddenClass(header.column.columnDef.meta)") + strings.Count(view, "columnHiddenClass(cell.column.columnDef.meta)"); n != 2 {
		t.Errorf("the header and the body cells do not both use columnHiddenClass (%d of 2) — a column can be hidden in one and shown in the other", n)
	}
}
