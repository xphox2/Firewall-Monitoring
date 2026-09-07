package shell

import (
	"os"
	"strings"
	"testing"
)

// TestDevicePurgeUI pins the admin-only "Delete permanently" (purge) flow
// that sits beside Restore on a retired device (v0.11.243). Retire keeps every
// row; purge is the explicit remove-the-data path, so the UI must never
// regress into a bare delete:
//   - the Devices page row action is `purge-device` (trash icon, admin) and
//     an active job swaps Restore for a `purge-cancel` button + PURGING badge
//   - the dialog is the static #purge-device-modal on BOTH pages (ARIA per
//     TestModalAria_AUDIT069, labels per TestLabelFor_AUDIT056), with the
//     estimate, "type the device name" confirm, password and 2FA inputs
//   - the shared dialog logic lives in admin-common.js (openPurgeDevice /
//     submitPurgeDevice), and the name check happens BEFORE the POST
//   - job state is polled through AC.pollWhenVisible(loadPurgeJobs, 5000)
//   - `delete-device` / `function deleteDevice` stay absent everywhere
func TestDevicePurgeUI(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s not found (tests must run from the package root); err: %v", path, err)
		}
		return string(data)
	}

	// --- Devices page (SPA) ---
	main := read("../../cmd/api/static/js/admin-main.js")
	for _, sig := range []string{
		"action: 'purge-device'",
		"title: 'Delete permanently'",
		"minRole: 'admin'",
		`data-action="purge-cancel" data-min-role="admin"`,
		`class="badge critical" title="' + escapeHtml('Purge in progress`,
		"'purge-device': function(el)",
		"'purge-cancel': function(el)",
		"'close-purge-device-modal': function()",
		"AC.pollWhenVisible(loadPurgeJobs, 5000",
		"function startPurgePolling()",
		"function stopPurgePolling()",
		"if (page !== 'devices') stopPurgePolling();",
		"'/purge-jobs'",
		"AC.openPurgeDevice(id, d.name, {",
		"AC.cancelPurgeDevice(id)",
	} {
		if !strings.Contains(main, sig) {
			t.Errorf("admin-main.js missing the %q signal: retired rows must offer Delete permanently (purge) with a PURGING badge, Cancel and polling.", sig)
		}
	}
	// Restore must be hidden while a job is active: the active branch of the
	// retired-row actions renders only the Cancel button.
	if !strings.Contains(main, "if (AC.purgeJobActive(job)) {\n            return '<button class=\"btn sm secondary\" data-action=\"purge-cancel\"") {
		t.Errorf("admin-main.js retiredActionsHtml must return ONLY the Cancel button while a purge job is active (Restore hidden).")
	}

	// --- Shared dialog logic (admin-common.js) ---
	common := read("../../cmd/api/static/js/admin-common.js")
	for _, sig := range []string{
		"function openPurgeDevice(id, name, opts)",
		"function submitPurgeDevice()",
		"function cancelPurgeDevice(id)",
		"function purgeJobActive(job)",
		"openPurgeDevice: openPurgeDevice",
		"submitPurgeDevice: submitPurgeDevice",
		"cancelPurgeDevice: cancelPurgeDevice",
		"purgeJobActive: purgeJobActive",
		"purgeProgressText: purgeProgressText",
		"'/purge/estimate'",
		"'/purge/cancel'",
		"confirm_name: nameEl.value",
		"password: pwEl.value",
		"totp_code:",
		"showSuccess('Purge queued')",
		"the tunnel intent is removed for both ends",
	} {
		if !strings.Contains(common, sig) {
			t.Errorf("admin-common.js missing the %q signal: the purge dialog must be the shared, re-authed, name-confirmed flow.", sig)
		}
	}
	// Capped estimates render as "1,000,000+" — the "+" suffix must follow the
	// capped flag for both the per-table row and the total.
	if strings.Count(common, "(t.capped ? '+' : '')") < 1 || !strings.Contains(common, "(anyCapped ? '+' : '')") {
		t.Errorf("admin-common.js must render capped estimate counts with a trailing '+' (per table and total).")
	}
	// Confirm-before-POST: inside submitPurgeDevice the typed-name check must
	// precede the POST to /purge (never fire the request on a mismatch).
	submitIdx := strings.Index(common, "function submitPurgeDevice()")
	if submitIdx < 0 {
		t.Fatalf("admin-common.js: submitPurgeDevice not found")
	}
	body := common[submitIdx:]
	idxCheck := strings.Index(body, "if (nameEl.value !== purgeCtx.name)")
	idxPost := strings.Index(body, "'/purge', {")
	if idxCheck < 0 {
		t.Errorf("admin-common.js submitPurgeDevice must compare the typed name against the device name before POSTing.")
	}
	if idxPost < 0 {
		t.Errorf("admin-common.js submitPurgeDevice must POST to /devices/:id/purge.")
	}
	if idxCheck >= 0 && idxPost >= 0 && idxCheck > idxPost {
		t.Errorf("admin-common.js submitPurgeDevice: the name check must come BEFORE the POST (found check at %d, POST at %d).", idxCheck, idxPost)
	}
	// The Delete button starts disabled and is only enabled on an exact match.
	if !strings.Contains(common, "btn.disabled = !(purgeCtx.name && nameEl.value === purgeCtx.name);") {
		t.Errorf("admin-common.js must keep the Delete button disabled until the typed name equals the device name exactly.")
	}
	// A failed POST keeps the dialog open (wrong password / 2FA can be retried).
	if !strings.Contains(common, "purgeShowError(msg);\n            if (pwEl && e && /password|2FA|authenticator|code/i.test(msg)) pwEl.value = '';") {
		t.Errorf("admin-common.js submitPurgeDevice must show the server error inside the dialog and keep it open on failure.")
	}

	// --- Modal markup on both pages ---
	for _, path := range []string{"../../web/admin/admin.html", "../../web/admin/device-detail.html"} {
		html := read(path)
		for _, sig := range []string{
			`<div class="modal" id="purge-device-modal" role="dialog" aria-modal="true" aria-labelledby="purge-device-title">`,
			`<h2 id="purge-device-title">Delete permanently</h2>`,
			`<form id="purge-device-form" autocomplete="off">`,
			`id="purge-device-estimate"`,
			`id="purge-device-tunnels"`,
			`<label for="purge-device-name-confirm">Type the device name to confirm</label>`,
			`<input type="text" id="purge-device-name-confirm"`,
			`<label for="purge-device-password">Your password</label>`,
			`<input type="password" id="purge-device-password" autocomplete="current-password">`,
			`<label for="purge-device-totp">Authenticator code`,
			`<input type="text" id="purge-device-totp" inputmode="numeric" autocomplete="one-time-code"`,
			`id="purge-device-error"`,
			`<button type="submit" class="btn danger" id="purge-device-submit" disabled>Delete permanently</button>`,
			`data-action="close-purge-device-modal"`,
		} {
			if !strings.Contains(html, sig) {
				t.Errorf("%s missing the %q signal: the purge dialog must carry the estimate, name confirm, password and 2FA inputs.", path, sig)
			}
		}
	}

	// --- Device-detail page: banner button + progress + polling ---
	detailHTML := read("../../web/admin/device-detail.html")
	for _, sig := range []string{
		`id="retiredBannerPurge"`,
		`data-action="purge-device" data-min-role="admin"`,
		`data-action="purge-cancel" data-min-role="admin"`,
		`data-action="restore-device" data-min-role="operator"`,
	} {
		if !strings.Contains(detailHTML, sig) {
			t.Errorf("device-detail.html missing the %q signal: the retired banner must offer Delete permanently (admin) and show purge progress.", sig)
		}
	}
	detailJS := read("../../cmd/api/static/js/admin-device-detail.js")
	for _, sig := range []string{
		"'purge-device': function()",
		"'purge-cancel': function()",
		"'close-purge-device-modal': function()",
		"AC.pollWhenVisible(loadPurgeJob, 5000",
		"AC.openPurgeDevice(Number(deviceId), dev.name, {",
		"AC.cancelPurgeDevice(Number(deviceId))",
		"'Purging — ' + AC.purgeProgressText(purgeJob)",
		"restoreBtn.style.display = active ? 'none' : ''",
	} {
		if !strings.Contains(detailJS, sig) {
			t.Errorf("admin-device-detail.js missing the %q signal.", sig)
		}
	}

	// --- Never a bare delete ---
	for _, f := range []string{
		"../../cmd/api/static/js/admin-main.js",
		"../../cmd/api/static/js/admin-common.js",
		"../../cmd/api/static/js/admin-device-detail.js",
		"../../web/admin/admin.html",
		"../../web/admin/device-detail.html",
	} {
		body := read(f)
		for _, gone := range []string{"delete-device", "function deleteDevice"} {
			if strings.Contains(body, gone) {
				t.Errorf("%s contains %q: permanent removal is the admin-only purge (purge-device), never a delete-device row action.", f, gone)
			}
		}
	}
}
