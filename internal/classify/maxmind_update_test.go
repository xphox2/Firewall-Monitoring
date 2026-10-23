package classify

import (
	"context"
	"testing"
)

// TestMaxMindNewRequest_LicenseKeyInHeaderOnly pins D-23: the license key must
// ride only in the Authorization header (Basic auth), never in the query string.
func TestMaxMindNewRequest_LicenseKeyInHeaderOnly(t *testing.T) {
	u := &MaxMindUpdater{licenseKey: "secret-key", accountID: "acct-123"}
	req, err := u.newRequest(context.Background(), "GeoLite2-City", "tar.gz")
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}
	if got := req.URL.Query().Get("license_key"); got != "" {
		t.Errorf("license_key leaked in query string: %q", got)
	}
	if req.URL.Query().Get("edition_id") != "GeoLite2-City" {
		t.Errorf("edition_id = %q, want GeoLite2-City", req.URL.Query().Get("edition_id"))
	}
	user, pass, ok := req.BasicAuth()
	if !ok || user != "acct-123" || pass != "secret-key" {
		t.Errorf("BasicAuth = (%q, %q, %v), want (acct-123, secret-key, true)", user, pass, ok)
	}
}

// TestMaxMindNewRequest_LegacyLicenseKeyFallsBack pins the legacy account path:
// with no account ID, the license key doubles as the Basic-auth username.
func TestMaxMindNewRequest_LegacyLicenseKeyFallsBack(t *testing.T) {
	u := &MaxMindUpdater{licenseKey: "legacy-key"}
	req, err := u.newRequest(context.Background(), "GeoLite2-City", "tar.gz")
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}
	user, pass, ok := req.BasicAuth()
	if !ok || user != "legacy-key" || pass != "legacy-key" {
		t.Errorf("BasicAuth = (%q, %q, %v), want (legacy-key, legacy-key, true)", user, pass, ok)
	}
}
