package shell

import (
	"os"
	"strings"
	"testing"
)

// TestIPSecIdentityUI pins the device-UUID identity flow in the admin console.
// The IPSec wizard used to prefill the IKE identity from the sanitized device
// name, so a replacement device that reused a retired device's name (allowed
// since v0.11.241) would present the retired device's identity to a shared
// peer. The default is now `fwm-<device uuid>` (server-minted, immutable), the
// name path survives only as a fallback for a payload without a uuid, and the
// UUID is visible (device-detail meta strip with a copy button; read-only
// group in the device edit modal) so operators can match it in peer logs.
//
// Signals pinned here:
//   - admin-ipsec.js defaultIdentity derives 'fwm-' + dev.uuid for fqdn
//   - both wizard ends carry a static help element OUTSIDE the .ipsec-fielderr
//     slot (validateId rewrites that slot on every change) with the wording
//   - the identity placeholders read fwm-<uuid>, not site-a/site-b
//   - the device edit modal has a read-only <code id="device-uuid"> group
//   - the device-detail page shows the UUID with a clipboard copy action
func TestIPSecIdentityUI(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s not found (tests must run from the package root); err: %v", path, err)
		}
		return string(data)
	}

	ipsec := read("../../cmd/api/static/js/admin-ipsec.js")
	start := strings.Index(ipsec, "function defaultIdentity(pfx, dev)")
	if start < 0 {
		t.Fatalf("admin-ipsec.js missing defaultIdentity(pfx, dev).")
	}
	end := strings.Index(ipsec[start:], "function prefillIdentity(")
	if end < 0 {
		t.Fatalf("admin-ipsec.js: prefillIdentity must follow defaultIdentity.")
	}
	fn := ipsec[start : start+end]
	if !strings.Contains(fn, "'fwm-' + dev.uuid") {
		t.Errorf("admin-ipsec.js defaultIdentity must derive the fqdn identity from the device UUID ('fwm-' + dev.uuid), never from the name alone.")
	}
	if !strings.Contains(fn, "sanitizeFqdnId(dev && dev.name)") {
		t.Errorf("admin-ipsec.js defaultIdentity must keep the sanitized-name fallback for a device payload without a uuid.")
	}
	if strings.Index(fn, "'fwm-' + dev.uuid") > strings.Index(fn, "sanitizeFqdnId(dev && dev.name)") {
		t.Errorf("admin-ipsec.js defaultIdentity must prefer the UUID before falling back to the sanitized name.")
	}

	html := read("../../web/admin/admin.html")
	const helpText = "Defaults to this device's UUID (fwm-…) so a replacement device never reuses a retired device's identity."
	for _, pfx := range []string{"a", "b"} {
		helpID := `id="ipsec-` + pfx + `-id-help"`
		if !strings.Contains(html, helpID) {
			t.Errorf("admin.html missing %s: the wizard identity field needs a static help element.", helpID)
			continue
		}
		// The help element must be a sibling of the error slot, not inside it:
		// validateId() overwrites #ipsec-<pfx>-id-hint on every change.
		helpAt := strings.Index(html, helpID)
		tagStart := strings.LastIndex(html[:helpAt], "<")
		tagEnd := strings.Index(html[helpAt:], ">")
		if tagEnd < 0 {
			t.Fatalf("admin.html: unterminated tag at %s", helpID)
		}
		closeAt := helpAt + tagEnd
		closeTag := strings.Index(html[closeAt:], "</small>")
		if !strings.HasPrefix(html[tagStart:], "<small") || closeTag < 0 {
			t.Errorf("admin.html %s must be a <small> element.", helpID)
			continue
		}
		body := html[closeAt+1 : closeAt+closeTag]
		if !strings.Contains(body, helpText) {
			t.Errorf("admin.html %s text = %q, want %q.", helpID, strings.TrimSpace(body), helpText)
		}
		hintID := `id="ipsec-` + pfx + `-id-hint"`
		hintAt := strings.Index(html, hintID)
		if hintAt < 0 {
			t.Errorf("admin.html missing %s (the validateId error slot).", hintID)
		} else if hintAt < helpAt && !strings.Contains(html[hintAt:helpAt], "</div>") {
			t.Errorf("admin.html %s sits inside the %s error slot; validateId rewrites that slot, so the help text would never render.", helpID, hintID)
		}
		placeholder := `id="ipsec-` + pfx + `-id" placeholder="fwm-<uuid>"`
		if !strings.Contains(html, placeholder) {
			t.Errorf("admin.html missing %q: the identity placeholder must advertise the UUID default.", placeholder)
		}
		if strings.Contains(html, `id="ipsec-`+pfx+`-id" placeholder="site-`+pfx+`"`) {
			t.Errorf("admin.html still carries the old site-%s identity placeholder.", pfx)
		}
	}

	// Device edit modal: read-only UUID group (a span, not <label for>, because
	// <code> is not a form control — see TestLabelFor_AUDIT056).
	for _, sig := range []string{
		`id="device-uuid-group"`,
		`<code id="device-uuid"`,
	} {
		if !strings.Contains(html, sig) {
			t.Errorf("admin.html missing %q: the device edit modal must show the read-only UUID.", sig)
		}
	}
	if strings.Contains(html, `<label for="device-uuid"`) {
		t.Errorf("admin.html must not <label for> the read-only <code id=\"device-uuid\">; it is not a control.")
	}
	main := read("../../cmd/api/static/js/admin-main.js")
	for _, sig := range []string{
		"document.getElementById('device-uuid').textContent = d.uuid",
		"document.getElementById('device-uuid-group').style.display = ''",
		"document.getElementById('device-uuid-group').style.display = 'none'",
	} {
		if !strings.Contains(main, sig) {
			t.Errorf("admin-main.js missing %q: showDeviceModal must fill the UUID on edit and hide the group on add.", sig)
		}
	}

	// Device detail page: UUID in the meta strip with a copy action.
	detailHTML := read("../../web/admin/device-detail.html")
	for _, sig := range []string{
		`id="deviceUuidWrap"`,
		`<code id="deviceUuid"`,
		`data-action="copy-device-uuid"`,
	} {
		if !strings.Contains(detailHTML, sig) {
			t.Errorf("device-detail.html missing %q: the meta strip must show the UUID with a copy button.", sig)
		}
	}
	detailJS := read("../../cmd/api/static/js/admin-device-detail.js")
	for _, sig := range []string{
		"'copy-device-uuid': function()",
		"navigator.clipboard.writeText(uuid)",
		"AC.showSuccess('UUID copied')",
		"uuidWrap.classList.add('hidden')",
		"uuidWrap.classList.remove('hidden')",
	} {
		if !strings.Contains(detailJS, sig) {
			t.Errorf("admin-device-detail.js missing %q: the UUID must be copyable and hidden when absent.", sig)
		}
	}
}
