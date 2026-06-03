package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestNoDeadAdminSecretKey_AUDIT157 — the env var ADMIN_SECRET_KEY
// (and the corresponding ServerConfig.AdminSecretKey field) used to
// ship in config.env.example and be loaded into the config struct,
// but no code path ever read it. The pre-fix state was:
//   - 1 documented env var that did nothing
//   - 1 struct field that was set but never consumed
//   - 1 source of confusion for operators wondering what to set
//
// The fix is to remove both. This test pins the removal on two
// axes:
//
//  1. Static — grep config.go for the strings "ADMIN_SECRET_KEY"
//     and "AdminSecretKey". A future agent who copy-pastes an
//     example back into the file fails here immediately. A future
//     handler that references the (removed) field would also fail
//     to compile, which is its own kind of test.
//
//  2. Runtime — set ADMIN_SECRET_KEY to a sentinel value, load
//     the config, and confirm the sentinel doesn't surface
//     anywhere in the rendered Server block. This catches the
//     case where a future agent re-adds the field and the
//     runtime check passes (because they wired it up) but the
//     field is still dead from the operator's perspective.
func TestNoDeadAdminSecretKey_AUDIT157(t *testing.T) {
	// Static check: the env var name and field name must not
	// appear in the config source file. This is the stronger of
	// the two checks because it covers both the env-var-loading
	// line AND any reference to the (now-removed) struct field.
	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Skipf("config.go not found at ./config.go (tests must run from internal/config/); err: %v", err)
	}
	if strings.Contains(string(src), "ADMIN_SECRET_KEY") {
		t.Errorf("config.go still references the env var name 'ADMIN_SECRET_KEY' (AUDIT-157). Remove the line from config.Load() so the dead env var doesn't get resurrected by a future agent who copy-pastes an example.")
	}
	if strings.Contains(string(src), "AdminSecretKey") {
		t.Errorf("config.go still references the field 'AdminSecretKey' (AUDIT-157). Remove the struct field so the dead field doesn't get resurrected.")
	}

	// Runtime check: set the env var, load, and confirm the
	// value doesn't surface in the rendered Server block. A
	// unique sentinel is necessary because the config struct
	// is the thing under test — we need a value that
	// unambiguously proves "this string was captured" vs "this
	// string happened to be in the dump for another reason".
	sentinel := "AUDIT157-SENTINEL-MUST-NOT-APPEAR-ANYWHERE-XYZ"
	t.Setenv("ADMIN_SECRET_KEY", sentinel)
	c := Load()
	if c == nil {
		t.Fatal("Load() returned nil")
	}
	dump := fmt.Sprintf("%+v", struct{ Server ServerConfig }{Server: c.Server})
	if strings.Contains(dump, sentinel) {
		t.Errorf("ServerConfig somehow captured the ADMIN_SECRET_KEY value %q; the field is supposed to be dead (AUDIT-157)", sentinel)
	}
}
