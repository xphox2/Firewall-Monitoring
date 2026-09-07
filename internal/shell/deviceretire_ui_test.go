package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDeviceRetireUI pins the retire/restore device flow in the admin console.
// Deleting a device used to drop only the `devices` row and orphan every
// device-keyed telemetry, alert and config-history row ("DEV-<id>" in the
// alerts list, dead detail link). The replacement is a soft retire: the row is
// kept with retired_at set, polling stops, history stays attached to the same
// id, and the device can be restored — including from the Add Device form when
// a retired device already owns the typed name. Permanent removal is a
// separate admin-only purge, never the row-action trash icon.
//
// Signals pinned here:
//   - the Devices page has Active / Retired / All filter tabs
//   - row actions dispatch retire-device / restore-device (no delete-device)
//   - the retire confirm wording (the old "and all its data" text was false)
//   - the Add Device 409 → three-way chooser (Restore / Create new / Cancel)
//     wording, the `reuse_name: true` re-POST and the rename-on-restore prompt
//   - pickers label retired devices via AC.deviceOptionLabel
//   - the device-detail page's retired banner + purged-device message
func TestDeviceRetireUI(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s not found (tests must run from the package root); err: %v", path, err)
		}
		return string(data)
	}

	html := read("../../web/admin/admin.html")
	for _, sig := range []string{
		`data-action="filter-devices" data-filter="active"`,
		`data-action="filter-devices" data-filter="retired"`,
		`data-action="filter-devices" data-filter="all"`,
	} {
		if !strings.Contains(html, sig) {
			t.Errorf("admin.html missing the %q filter tab: the Devices page must offer Active / Retired / All.", sig)
		}
	}
	// The tabs must not share .filter-tab with the Probes page, whose
	// filterProbes() clears `.filter-tab.active` document-wide.
	if strings.Contains(html, `class="filter-tab chart-range-pill" data-action="filter-devices"`) ||
		strings.Contains(html, `class="filter-tab chart-range-pill active" data-action="filter-devices"`) {
		t.Errorf("admin.html device filter tabs reuse .filter-tab; use a page-scoped class so the Probes filter cannot clear them.")
	}

	js := read("../../cmd/api/static/js/admin-main.js")
	for _, sig := range []string{
		"action: 'retire-device'",
		`data-action="restore-device"`,
		"'retire-device': function(el)",
		"'restore-device': function(el)",
		"'filter-devices': function(el)",
		"function renderDevices()",
		"'Retire this device? Polling stops within a few minutes; all history is kept and it can be restored later.'",
		`, history preserved). Restore it and apply these settings, or create a new device with this name?`,
		"retired devices share this name; Restore applies to the most recently retired one.",
		"AC.choose(msg, {",
		"{ key: 'restore', label: 'Restore retired device' }",
		"{ key: 'create', label: 'Create new device' }",
		"reuse_name: true",
		"AC.promptText(",
		"already in use",
		"body.retired_device_id",
		"/restore'",
	} {
		if !strings.Contains(js, sig) {
			t.Errorf("admin-main.js missing the %q signal: retire/restore must replace delete on the Devices page.", sig)
		}
	}
	for _, gone := range []string{
		"delete-device",
		"function deleteDevice",
		"Delete this device and all its data?",
	} {
		if strings.Contains(js, gone) {
			t.Errorf("admin-main.js still contains %q: the UI must retire (keep history), never DELETE a device.", gone)
		}
	}
	// The restore-with-settings body must not carry `enabled` (the server
	// re-enables on restore and rejects it in the body).
	if !strings.Contains(js, "delete settings.enabled") {
		t.Errorf("admin-main.js restore-from-409 must strip `enabled` from the form payload before POSTing /restore.")
	}

	// Pickers that offer devices for NEW configuration must not list retired
	// devices as plain names: the shared label helper carries the retired date.
	for _, f := range []string{
		"../../cmd/api/static/js/admin-common.js",
		"../../cmd/api/static/js/admin-main.js",
		"../../cmd/api/static/js/admin-ipsec.js",
		"../../cmd/api/static/js/admin-event-profiles.js",
		"../../cmd/api/static/js/admin-event-rules.js",
		"../../cmd/api/static/js/admin-alerting.js",
	} {
		body := read(f)
		sig := "AC.deviceOptionLabel("
		if strings.HasSuffix(f, "admin-common.js") {
			sig = "deviceOptionLabel: deviceOptionLabel"
		}
		if !strings.Contains(body, sig) {
			t.Errorf("%s missing %q: device pickers must label retired devices with their retired date.", f, sig)
		}
	}
	common := read("../../cmd/api/static/js/admin-common.js")
	for _, sig := range []string{"choose: chooseModal", "promptText: promptTextModal"} {
		if !strings.Contains(common, sig) {
			t.Errorf("admin-common.js missing %q: the add-device chooser and rename-on-restore prompt need it.", sig)
		}
	}

	detailHTML := read("../../web/admin/device-detail.html")
	for _, sig := range []string{
		`id="retiredBanner"`,
		`id="retiredBannerText"`,
		`data-action="restore-device" data-min-role="operator"`,
	} {
		if !strings.Contains(detailHTML, sig) {
			t.Errorf("device-detail.html missing the %q signal: a retired device must show a banner with a Restore button.", sig)
		}
	}
	detailJS := read("../../cmd/api/static/js/admin-device-detail.js")
	for _, sig := range []string{
		"'This device was permanently deleted.'",
		"'Retired on ' + AC.formatDate(dev.retired_at) + '. Data preserved.'",
		"'restore-device': function()",
		"AC.promptText(",
		"already in use",
	} {
		if !strings.Contains(detailJS, sig) {
			t.Errorf("admin-device-detail.js missing the %q signal.", sig)
		}
	}
	if strings.Contains(detailJS, "if (!resp.ok) throw new Error('Failed to load device');") &&
		!strings.Contains(detailJS, "resp.status === 404") {
		t.Errorf("admin-device-detail.js must distinguish a 404 (purged device) from a generic load failure.")
	}
}
