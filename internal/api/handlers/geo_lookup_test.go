package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/classify"

	"github.com/gin-gonic/gin"
)

// TestLookupGeoBatch verifies the batch geo endpoint resolves a public IP to
// country/ASN/org + prefix and omits private/invalid addresses.
func TestLookupGeoBatch(t *testing.T) {
	h, _ := setupTestHandler(t)
	geo, err := classify.NewGeoResolver(true, "", t.TempDir())
	if err != nil || geo == nil || !geo.Enabled() {
		t.Skip("geo bundle unavailable")
	}
	defer geo.Close()
	h.geoResolver = geo

	router := gin.New()
	router.GET("/admin/api/geo/lookup", h.LookupGeoBatch)
	req := httptest.NewRequest("GET", "/admin/api/geo/lookup?ips=8.8.8.8,10.0.0.1,not-an-ip", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data map[string]struct {
			Country   string `json:"country"`
			ASN       uint32 `json:"asn"`
			ASNOrg    string `json:"asn_org"`
			ASNPrefix string `json:"asn_prefix"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}

	g := resp.Data["8.8.8.8"]
	if g.Country != "US" || g.ASN != 15169 || g.ASNPrefix == "" {
		t.Errorf("8.8.8.8 = %+v, want US / AS15169 / non-empty prefix", g)
	}
	if _, ok := resp.Data["10.0.0.1"]; ok {
		t.Error("private IP 10.0.0.1 should be omitted from the response")
	}
	if _, ok := resp.Data["not-an-ip"]; ok {
		t.Error("invalid IP should be omitted from the response")
	}
}
