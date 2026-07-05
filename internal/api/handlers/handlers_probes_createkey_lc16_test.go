package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestCreateProbe_ShowOnceKey_LC16 pins the operator probe-onboarding fix:
// CreateProbe (operator-reachable) returns the PLAINTEXT registration key
// exactly once — in the create response — because the only other reveal path
// (RegenerateProbeKey) is admin-only. At rest only the hash is stored, and
// every subsequent read (single GET and list) is redacted to the mask, never
// the hash.
func TestCreateProbe_ShowOnceKey_LC16(t *testing.T) {
	h, db := setupTestHandler(t)

	site := &models.Site{Name: "lc16-site"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}

	router := gin.New()
	router.POST("/admin/api/probes", h.CreateProbe)
	router.GET("/admin/api/probes/:id", h.GetProbe)
	router.GET("/admin/api/probes", h.GetProbes)

	body, _ := json.Marshal(map[string]interface{}{
		"name":    "lc16-probe",
		"site_id": site.ID,
	})
	req := httptest.NewRequest("POST", "/admin/api/probes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("CreateProbe: status=%d body=%s", w.Code, w.Body.String())
	}

	var created struct {
		Data models.Probe `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	key := created.Data.RegistrationKey

	// The one-time reveal: a real plaintext key — not empty, not the
	// redaction mask, not the at-rest hash.
	if key == "" {
		t.Fatal("create response must carry the plaintext registration key (show-once reveal)")
	}
	if key == httputil.RedactedMask {
		t.Fatalf("create response returned the redaction mask %q as the key", key)
	}
	if strings.HasPrefix(key, "sha256:") {
		t.Fatalf("create response leaked the at-rest hash: %q", key)
	}

	// At rest: the HASH of the returned plaintext (proves the returned key is
	// the one the collector can actually register with).
	var stored models.Probe
	if err := db.Gorm().First(&stored, created.Data.ID).Error; err != nil {
		t.Fatalf("reload probe: %v", err)
	}
	if stored.RegistrationKey != database.HashProbeKey(key) {
		t.Errorf("stored key = %q, want HashProbeKey(returned plaintext)", stored.RegistrationKey)
	}

	// Subsequent single GET: redacted to the mask — pre-LC-16 this endpoint
	// leaked the raw at-rest hash.
	req = httptest.NewRequest("GET", fmt.Sprintf("/admin/api/probes/%d", created.Data.ID), nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GetProbe: status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Data models.Probe `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if got.Data.RegistrationKey != httputil.RedactedMask {
		t.Errorf("GET /probes/:id registration_key = %q, want %q", got.Data.RegistrationKey, httputil.RedactedMask)
	}

	// List GET: also redacted.
	req = httptest.NewRequest("GET", "/admin/api/probes", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GetProbes: status=%d body=%s", w.Code, w.Body.String())
	}
	var list struct {
		Data []models.Probe `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	for _, p := range list.Data {
		if p.ID == created.Data.ID && p.RegistrationKey != httputil.RedactedMask {
			t.Errorf("GET /probes list registration_key = %q, want %q", p.RegistrationKey, httputil.RedactedMask)
		}
	}
}
