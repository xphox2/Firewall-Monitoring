package classify

import "testing"

// TestGeoResolver_DisabledIsNilSafe verifies the disabled path: NewGeoResolver
// returns (nil, nil) and every method on the nil resolver is safe and empty.
func TestGeoResolver_DisabledIsNilSafe(t *testing.T) {
	g, err := NewGeoResolver(false, "")
	if err != nil {
		t.Fatalf("NewGeoResolver(disabled) err = %v, want nil", err)
	}
	if g != nil {
		t.Fatalf("NewGeoResolver(disabled) = %v, want nil", g)
	}
	if g.Enabled() {
		t.Error("nil resolver Enabled() = true, want false")
	}
	if got := g.Country("8.8.8.8"); got != "" {
		t.Errorf("nil resolver Country = %q, want empty", got)
	}
	if got := g.ASN("8.8.8.8"); got != 0 {
		t.Errorf("nil resolver ASN = %d, want 0", got)
	}
	if err := g.Close(); err != nil {
		t.Errorf("nil resolver Close = %v, want nil", err)
	}
}

// TestGeoResolver_EnabledMissingFiles verifies that enabling geo with a dir that
// has no .mmdb files returns an error (so the caller logs it) and a nil resolver
// (so enrichment is a no-op, not a crash).
func TestGeoResolver_EnabledMissingFiles(t *testing.T) {
	g, err := NewGeoResolver(true, t.TempDir())
	if err == nil {
		t.Error("NewGeoResolver(enabled, empty dir) err = nil, want an open error")
	}
	if g != nil {
		t.Errorf("NewGeoResolver(enabled, missing files) = %v, want nil", g)
	}
	// Lookups on the nil resolver remain safe.
	if got := g.Country("1.1.1.1"); got != "" {
		t.Errorf("Country on failed-open resolver = %q, want empty", got)
	}
}

// TestGeoResolver_EmptyDir verifies the enabled-but-no-dir guard.
func TestGeoResolver_EmptyDir(t *testing.T) {
	if _, err := NewGeoResolver(true, ""); err == nil {
		t.Error("NewGeoResolver(true, \"\") err = nil, want a config error")
	}
}

// TestGeoResolver_ReloadNilSafe verifies the audit-L4 reload path is nil-safe:
// Reload on a disabled (nil) resolver, and repeated Reloads on a resolver whose
// DB files are missing, must neither panic nor spuriously flip Enabled().
func TestGeoResolver_ReloadNilSafe(t *testing.T) {
	var g *GeoResolver // disabled
	g.Reload()         // must not panic

	// A resolver constructed with missing files is nil (see EnabledMissingFiles),
	// so this also exercises Reload on the nil path via the same code.
	r, _ := NewGeoResolver(true, t.TempDir())
	r.Reload()
	if r.Enabled() {
		t.Error("resolver with no .mmdb files reported Enabled after Reload")
	}
}
