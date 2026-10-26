package guardrails

import (
	"regexp"
	"strings"
	"testing"
)

// The V2 console's device-management controls must match the server's.
//
// Two bugs of the same shape have already shipped here:
//
//   - the connection editor sent a `description` field that
//     `models.DeviceConnection` has no column for, so every update 500'd
//     (a GORM map update turns the key into a column name);
//   - the purge dialog sent no `confirm_name`, so every purge was rejected
//     with a 400 — the feature was present and unusable.
//
// Both are the same mistake: writing a form field without checking that the
// server accepts it. The tests below check the console's fields against the
// server's ALLOW-LIST, which is the list the server actually applies.
//
// The allow-list is PARSED from the Go source, not copied here: a copy would
// pass against a stale server and let the two drift apart unnoticed.

// deviceAllowedFields parses the server's update allow-list.
func deviceAllowedFields(t *testing.T) map[string]bool {
	t.Helper()
	src := readRepoFile(t, "internal/api/handlers/handlers_devices.go")
	block := regexp.MustCompile(`(?s)allowedFields := map\[string\]bool\{(.*?)\n\t\}`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("handlers_devices.go: the device update allow-list was not found — it is the source of truth for the console's fields")
	}
	fields := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z0-9_]+)"\s*:`).FindAllStringSubmatch(block[1], -1) {
		fields[m[1]] = true
	}
	if len(fields) == 0 {
		t.Fatal("the device update allow-list parsed empty — the parser is broken, not the server")
	}
	return fields
}

// TestV2DeviceEditorSendsOnlyAcceptedFields pins the console's device
// fields to the server's allow-list.
//
// A field outside the list is SILENTLY DROPPED by the server
// (httputil.FilterAllowedFields), so the operator types a value, presses
// save, and is told it worked — and nothing was stored.
func TestV2DeviceEditorSendsOnlyAcceptedFields(t *testing.T) {
	allowed := deviceAllowedFields(t)
	editor := readV2(t, "pages/DevicesWorkspace.tsx")

	// The DeviceRecord type is the console's view of a device. The fields
	// the editor can SET are the ones it writes back, so they are checked
	// against the allow-list.
	typeBlock := regexp.MustCompile(`(?s)export interface DeviceRecord \{(.*?)\n\}`).FindStringSubmatch(editor)
	if typeBlock == nil {
		t.Fatal("DevicesWorkspace.tsx: the DeviceRecord type was not found")
	}
	fields := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s{2}([a-z0-9_]+)\??:`).FindAllStringSubmatch(typeBlock[1], -1) {
		fields[m[1]] = true
	}
	if len(fields) == 0 {
		t.Fatal("the DeviceRecord type parsed empty — the parser is broken, not the type")
	}

	// The negative direction, which is the one that matters: a field that
	// has no column, or that the server's allow-list does not carry, must
	// never reappear in the console's view of a device. Each of these was
	// either named by the design review or was a live trap:
	//
	//   - wan_speed_mbps: the column EXISTS but is outside the update
	//     allow-list, so the server silently drops it — the value would be
	//     accepted by the UI and discarded by the server;
	//   - api_key / api_secret: no such columns at all;
	//   - snmpv3_security_level: never a field of models.Device.
	for _, phantom := range []string{
		"wan_speed_mbps",
		"api_key",
		"api_secret",
		"snmpv3_security_level",
	} {
		if fields[phantom] {
			t.Errorf("the console's DeviceRecord has %q — it is not a field the server can store (api_key and api_secret have no column; wan_speed_mbps is outside the update allow-list, so the server drops it silently; snmpv3_security_level was never a field)", phantom)
		}
	}

	// The fields the console DISPLAYS are not written back: the type carries
	// the whole device as the server returns it. Only the fields the EDITOR
	// writes are checked, and they are listed here explicitly.
	edited := []string{
		"name", "ip_address", "vendor", "site_id", "probe_id", "enabled",
		"snmp_version", "snmp_port", "snmp_community",
		"snmpv3_username", "snmpv3_auth_type", "snmpv3_auth_pass",
		"snmpv3_priv_type", "snmpv3_priv_pass",
		"ssh_username", "ssh_password", "ssh_port", "ssh_poll_enabled",
		"ssh_poll_interval",
		"api_token", "api_port", "api_insecure_tls",
		"location", "public_visible",
	}
	for _, field := range edited {
		if !allowed[field] {
			t.Errorf("the console edits %q, which is NOT in the server's update allow-list — the server silently drops it, so the operator's value is discarded without an error", field)
		}
		if !fields[field] {
			t.Errorf("the console edits %q, but the DeviceRecord type does not carry it — the value could not be sent", field)
		}
	}
}

// TestV2AdminOnlyDeviceFieldsAreGated pins that the console's admin-only
// controls are gated on the role.
//
// `public_visible` and `api_insecure_tls` are admin-only on the server
// (handlers_devices.go: "Only admins can change public visibility" / "Only
// admins can change API TLS verification"). A console that shows the control
// to a non-admin produces a 403 on save; a console that shows it without
// saying why looks like a broken control.
//
// `public_visible` is the more serious of the two: the column DEFAULTS TO
// TRUE, so the device is on the UNAUTHENTICATED public dashboard unless an
// operator turns it off.
func TestV2AdminOnlyDeviceFieldsAreGated(t *testing.T) {
	editor := readV2(t, "pages/DevicesWorkspace.tsx")

	// The console has to know the role at all.
	if !strings.Contains(editor, "queryKey: ['me']") {
		t.Error("DevicesWorkspace.tsx does not fetch the operator's own record — the admin-only controls cannot be gated without it")
	}
	if !strings.Contains(editor, "me?.role === 'admin'") {
		t.Error("DevicesWorkspace.tsx does not derive an admin role from the operator's record")
	}

	// Both admin-only controls must be disabled for a non-admin. The search is
	// anchored on the CONTROL's own expression — the field name also appears
	// in the DeviceRecord type, and matching there would find the
	// declaration instead of the control.
	for _, field := range []string{"public_visible", "api_insecure_tls"} {
		anchor := "editingDevice." + field
		idx := strings.Index(editor, anchor)
		if idx < 0 {
			t.Errorf("DevicesWorkspace.tsx has no %q control at all — it is admin-only, so it should be present and gated", field)
			continue
		}
		window := editor[idx:min(len(editor), idx+600)]
		if !strings.Contains(window, "disabled={!isAdmin}") {
			t.Errorf("the %q control is not disabled for a non-admin — the server rejects it with a 403, so the console has to say why", field)
		}
	}
}

// TestV2NonAdminSaveOmitsAdminOnlyFields pins that a non-admin's device
// edit does not carry the admin-only fields.
//
// The server gates on the PRESENCE of the key, not on a change
// (handlers_devices.go: `if _, has := updates["public_visible"]; has &&
// !admin { 403 }`). The loaded device record carries both fields — the
// redaction masks the SECRETS, not these — so a save body built by spreading
// the record always contained them.
//
// The effect was that EVERY device edit by a non-admin was rejected with a
// 403, because the request carried an admin-only field it had not changed.
// The control was "gated" by breaking the whole save.
func TestV2NonAdminSaveOmitsAdminOnlyFields(t *testing.T) {
	editor := readV2(t, "pages/DevicesWorkspace.tsx")

	body := regexp.MustCompile(`(?s)const buildSaveBody = \(\): Record<string, unknown> => \{(.*?)\n  \};`).FindStringSubmatch(editor)
	if body == nil {
		t.Fatal("DevicesWorkspace.tsx: buildSaveBody was not found — the save body is where the admin-only fields have to be dropped")
	}

	// The role check has to be there…
	if !strings.Contains(body[1], "isAdmin") {
		t.Error("buildSaveBody does not consider the operator's role — the admin-only fields are always sent, so a non-admin's edit is rejected with a 403")
	}
	// …and both fields have to be dropped for a non-admin.
	for _, field := range []string{"public_visible", "api_insecure_tls"} {
		if !regexp.MustCompile(`delete body\.` + field + `;`).MatchString(body[1]) {
			t.Errorf("buildSaveBody does not drop %q for a non-admin — the server gates on the PRESENCE of the key, so the field being in the body rejects the WHOLE update", field)
		}
	}
}

// The server needs `confirm_name`, `password` and (with 2FA) `totp_code`
// (handlers_devices_purge.go). The console's purge dialog sent only the
// password and the TOTP code, so EVERY purge was rejected with a 400 on the
// missing name — the feature was present and unusable.
func TestV2PurgeSendsTheConfirmationName(t *testing.T) {
	dialog := readV2(t, "components/devices/purge-device-dialog.tsx")
	// The needles are matched as OBJECT KEYS at the start of a line, not as
	// bare words: the dialog's own documentation names all three fields, so a
	// plain substring search would be satisfied by a comment and pass with
	// the field removed. Both `key: value` and the `key,` shorthand count.
	for _, needle := range []string{"confirm_name", "password", "totp_code"} {
		if !regexp.MustCompile(`(?m)^\s*` + needle + `\s*[:,]`).MatchString(dialog) {
			t.Errorf("purge-device-dialog.tsx does not send %q — the server requires it, and the console's purge was rejected with a 400 without it", needle)
		}
	}
	// The TOTP is only asked for when the account has 2FA.
	if !strings.Contains(dialog, "totpEnabled") {
		t.Error("purge-device-dialog.tsx does not pass totpEnabled — a 2FA account would never be asked for its code, and the server would reject the purge with a 403")
	}

	// The estimate has to be shown before the operator commits, and the
	// cancel path has to exist: a purge runs in the background.
	for _, needle := range []string{
		"/purge/estimate",
		"/purge/cancel",
		"/purge-jobs",
	} {
		if !strings.Contains(dialog, needle) && !strings.Contains(readV2(t, "pages/DevicesWorkspace.tsx"), needle) {
			t.Errorf("the purge lifecycle is missing %q — a purge runs in the background, so the operator needs to see it and be able to stop it", needle)
		}
	}
}

// TestV2AlertConfigUsesTheEventProfileEndpoint pins that the Event Profile
// is NOT sent in the alert-config body.
//
// The two are different things: the alert-config PUT BINDS onto the existing
// row, while the Event Profile is assigned through its own admin-only
// `/event-profile` endpoint, which is where the server refreshes the
// resolution cache from. Folding it into the alert-config body would fork
// the shipped contract and bypass that cache.
func TestV2AlertConfigUsesTheEventProfileEndpoint(t *testing.T) {
	builder := readV2(t, "lib/alert-config.ts")
	// The capture runs to the NEXT exported function (or the end of the file),
	// so a mutation added anywhere inside the body is inside the capture. A
	// non-greedy brace match would stop at the first inner `}` and let a
	// mutation near the end escape.
	bodyBlock := regexp.MustCompile(`(?s)export function buildAlertConfigBody\(.*?(?:\nexport function|\z)`).FindString(builder)
	if bodyBlock == "" {
		t.Fatal("lib/alert-config.ts: buildAlertConfigBody was not found")
	}
	if strings.Contains(bodyBlock, "event_profile_id") {
		t.Error("buildAlertConfigBody sends event_profile_id — it belongs on the dedicated /event-profile endpoint, which is where the server refreshes the resolution cache from")
	}
	if !strings.Contains(builder, "buildEventProfileBody") {
		t.Error("lib/alert-config.ts has no buildEventProfileBody — the Event Profile still needs somewhere to go")
	}

	drawer := readV2(t, "components/devices/alert-config-drawer.tsx")
	if !strings.Contains(drawer, "/event-profile") {
		t.Error("the alert-config drawer does not use the /event-profile endpoint")
	}
}

// TestV2PublicInterfaceWriteIsComplete pins that the per-interface public
// control writes the WHOLE map.
//
// `public_interfaces` is a display setting holding the map for EVERY device,
// so the write is a read-modify-write of the whole thing. Writing only this
// device's entry — or writing a map built before the setting finished
// loading — would erase every OTHER device's public-dashboard selection.
// That is the AUDIT-185 trap the legacy console already fell into once.
func TestV2PublicInterfaceWriteIsComplete(t *testing.T) {
	toggle := readV2(t, "components/devices/public-interface-toggle.tsx")
	if !strings.Contains(toggle, "/admin/api/settings") {
		t.Error("the public-interface toggle does not write the display setting")
	}
	if !strings.Contains(toggle, "public_interfaces") {
		t.Error("the public-interface toggle does not write the public_interfaces setting")
	}
	// The whole map goes back, not just this device's entry.
	if !strings.Contains(toggle, "const payload = { ...map,") {
		t.Error("the public-interface toggle does not write back the WHOLE map — a partial write would erase every other device's public-dashboard selection (AUDIT-185)")
	}
	// And the toggle stays disabled until the map has loaded, so a click
	// cannot serialise a half-loaded map.
	if !strings.Contains(toggle, "disabled={!map}") {
		t.Error("the public-interface toggle is not disabled until the map has loaded — a pre-load click would serialise an empty map and wipe every other device's selection")
	}
}
