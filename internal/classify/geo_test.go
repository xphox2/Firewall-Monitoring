package classify

import "testing"

// TestGeoResolver_DisabledIsNilSafe verifies the disabled path: NewGeoResolver
// returns (nil, nil) and every method on the nil resolver is safe and empty.
func TestGeoResolver_DisabledIsNilSafe(t *testing.T) {
	g, err := NewGeoResolver(false, "", "")
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
	if n, org := g.ASNInfo("8.8.8.8"); n != 0 || org != "" {
		t.Errorf("nil resolver ASNInfo = (%d,%q), want (0,\"\")", n, org)
	}
	if got := g.Source(); got != "disabled" {
		t.Errorf("nil resolver Source = %q, want \"disabled\"", got)
	}
	if err := g.Close(); err != nil {
		t.Errorf("nil resolver Close = %v, want nil", err)
	}
}

// TestGeoResolver_BundleEnabled verifies that with geo enabled and no live dir,
// the embedded DB-IP Lite bundle loads and resolves known IPs correctly — this
// is the "works out of the box" guarantee and the DB-IP schema-mapping check.
func TestGeoResolver_BundleEnabled(t *testing.T) {
	g, err := NewGeoResolver(true, "", t.TempDir())
	if err != nil {
		t.Fatalf("NewGeoResolver(bundle) err = %v, want nil", err)
	}
	if g == nil || !g.Enabled() {
		t.Fatal("bundle resolver not enabled")
	}
	defer g.Close()

	if got := g.Source(); got != "bundled (DB-IP Lite)" {
		t.Errorf("Source = %q, want bundled", got)
	}
	// DB-IP Lite must map onto the geoip2 typed reader (Country.IsoCode + ASN).
	cases := []struct {
		ip, wantCC string
		wantASN    uint32
	}{
		{"8.8.8.8", "US", 15169}, // Google
		{"1.1.1.1", "AU", 13335}, // Cloudflare
	}
	for _, tc := range cases {
		if cc := g.Country(tc.ip); cc != tc.wantCC {
			t.Errorf("Country(%s) = %q, want %q", tc.ip, cc, tc.wantCC)
		}
		if n := g.ASN(tc.ip); n != tc.wantASN {
			t.Errorf("ASN(%s) = %d, want %d", tc.ip, n, tc.wantASN)
		}
		if n, org := g.ASNInfo(tc.ip); n != tc.wantASN || org == "" {
			t.Errorf("ASNInfo(%s) = (%d,%q), want (%d, non-empty)", tc.ip, n, org, tc.wantASN)
		}
	}
	// Private ranges are unmapped.
	if cc := g.Country("10.0.0.1"); cc != "" {
		t.Errorf("Country(private) = %q, want empty", cc)
	}
}

// TestGeoResolver_ReloadNilSafe verifies the reload path is nil-safe and that a
// repeated Reload on the bundle resolver doesn't flip Enabled() off.
func TestGeoResolver_ReloadNilSafe(t *testing.T) {
	var g *GeoResolver // disabled
	g.Reload()         // must not panic

	r, err := NewGeoResolver(true, "", t.TempDir())
	if err != nil {
		t.Fatalf("NewGeoResolver err = %v", err)
	}
	defer r.Close()
	r.Reload()
	if !r.Enabled() {
		t.Error("bundle resolver reported not-Enabled after Reload")
	}
}
