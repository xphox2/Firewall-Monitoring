package shell

import (
	"regexp"
	"strings"
	"testing"
)

// AUDIT-185: admin-device-detail.js loaded the public_interfaces map without
// gating the checkboxes or waiting for the fetch. Two concrete defects:
//   1. loadPublicInterfaces() never RETURNED its fetch, so the init chain
//      (fetchCsrfToken → loadPublicInterfaces → loadDevice) did not wait and the
//      interface table rendered with publicInterfaces={} and never re-rendered.
//   2. togglePublicIface POSTs the ENTIRE publicInterfaces map, so a checkbox
//      click before the map loaded would serialize an empty map and wipe every
//      OTHER device's public-dashboard selection.
// The fix returns the fetch, tracks a publicIfacesLoaded flag that blocks the
// toggle and disables the checkbox until the map has loaded.

func TestPublicIface_LoadReturnsFetch_AUDIT185(t *testing.T) {
	js := readJS(t, "admin-device-detail.js")

	// loadPublicInterfaces must RETURN its fetch so the init chain waits.
	loadFn := extractFn(t, js, "function loadPublicInterfaces()")
	if !regexp.MustCompile(`return\s+fetch\(`).MatchString(loadFn) {
		t.Error("AUDIT-185 regression: loadPublicInterfaces() no longer returns its fetch — " +
			"the init chain will not wait and the interface table renders before publicInterfaces loads")
	}
	if !strings.Contains(loadFn, "publicIfacesLoaded = true") {
		t.Error("AUDIT-185 regression: loadPublicInterfaces() no longer sets publicIfacesLoaded")
	}
	// Follow-up hardening: the flag must be set true ONLY on the success path
	// (the .then), never in the .catch. A FAILED display-settings fetch that
	// re-enabled the Public checkboxes over an empty publicInterfaces map would
	// let a click POST that empty map and wipe every other device's selection —
	// the exact data-loss this finding guards. Pin exactly one set-true site.
	if n := strings.Count(loadFn, "publicIfacesLoaded = true"); n != 1 {
		t.Errorf("AUDIT-185 regression: publicIfacesLoaded is set true %d times in loadPublicInterfaces() "+
			"(want exactly 1 — the success .then only). A .catch that sets it re-enables the checkboxes "+
			"over an empty map on a failed fetch, wiping other devices' public-interface selections.", n)
	}
}

func TestPublicIface_ToggleGuardsOnLoadedFlag_AUDIT185(t *testing.T) {
	js := readJS(t, "admin-device-detail.js")

	if !strings.Contains(js, "var publicIfacesLoaded") {
		t.Fatal("AUDIT-185 regression: the publicIfacesLoaded flag was removed")
	}

	toggleFn := extractFn(t, js, "window.togglePublicIface = function")
	// The toggle must bail out before POSTing when the map has not loaded.
	if !regexp.MustCompile(`if\s*\(\s*!publicIfacesLoaded\s*\)\s*\{\s*return`).MatchString(toggleFn) {
		t.Error("AUDIT-185 regression: togglePublicIface no longer blocks on !publicIfacesLoaded — " +
			"a pre-load click can POST an empty map and wipe every other device's public interfaces")
	}

	// The checkbox must be disabled until the map loads.
	if !strings.Contains(js, "publicIfacesLoaded ? '' : 'disabled '") {
		t.Error("AUDIT-185 regression: the public-interface checkbox is no longer disabled until publicIfacesLoaded")
	}
}

// extractFn returns the source of a function starting at the given signature,
// balanced by braces. Good enough for these content-pinning guardrails.
func extractFn(t *testing.T, js, sig string) string {
	t.Helper()
	start := strings.Index(js, sig)
	if start < 0 {
		t.Fatalf("function %q not found", sig)
	}
	// Find the first '{' after the signature, then balance braces.
	open := strings.IndexByte(js[start:], '{')
	if open < 0 {
		t.Fatalf("no body for %q", sig)
	}
	i := start + open
	depth := 0
	for ; i < len(js); i++ {
		switch js[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return js[start : i+1]
			}
		}
	}
	t.Fatalf("unbalanced braces for %q", sig)
	return ""
}
