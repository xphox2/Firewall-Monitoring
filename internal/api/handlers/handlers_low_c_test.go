package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestSendIRCMessage_RejectsOverlongMessage_L15 pins L-15: a message that
// cannot fit one IRC line is a 400, decided before the manager is consulted.
func TestSendIRCMessage_RejectsOverlongMessage_L15(t *testing.T) {
	h := &Handler{}
	body := fmt.Sprintf(`{"server_id":1,"channel":"#ops","message":%q}`,
		strings.Repeat("x", maxIRCMessageBytes+1))
	c, rec := jsonReq(http.MethodPost, "/admin/api/irc/send", body)
	h.SendIRCMessage(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}

	// At the cap it passes validation (and stops at the absent manager).
	body = fmt.Sprintf(`{"server_id":1,"channel":"#ops","message":%q}`,
		strings.Repeat("x", maxIRCMessageBytes))
	c, rec = jsonReq(http.MethodPost, "/admin/api/irc/send", body)
	h.SendIRCMessage(c)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("at-cap status = %d, want 503 (no manager); body = %s", rec.Code, rec.Body.String())
	}
}

// TestGetPublicDisplaySettings_AllowListOnly_L12 pins L-12: the anonymous
// endpoint returns only the explicit allow-list — not every "public_%" row.
func TestGetPublicDisplaySettings_AllowListOnly_L12(t *testing.T) {
	h, db := setupTestHandler(t)
	for k, v := range map[string]string{
		"public_show_vpn":       "true",
		"public_internal_token": "should-not-leak",
		"public_show_cpu":       "true", // a retired key's stale row
	} {
		if err := db.Gorm().Create(&models.SystemSetting{Key: k, Value: v}).Error; err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}

	c, rec := jsonReq(http.MethodGet, "/api/public/display-settings", "")
	h.GetPublicDisplaySettings(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for k := range resp.Data {
		if _, ok := publicDisplaySettingDefaults[k]; !ok {
			t.Errorf("non-allow-listed key %q returned to anonymous caller", k)
		}
	}
	if resp.Data["public_show_vpn"] != "true" {
		t.Errorf("stored allow-listed value not returned: public_show_vpn = %q", resp.Data["public_show_vpn"])
	}
	if resp.Data["display_timezone"] == "" {
		t.Errorf("default for display_timezone missing")
	}
}

// TestCreateSite_IgnoresServerOwnedFields_L13 pins L-13: id, timestamps and
// the parent_site / probes associations are not mass-assignable on create.
func TestCreateSite_IgnoresServerOwnedFields_L13(t *testing.T) {
	h, db := setupTestHandler(t)

	c, rec := jsonReq(http.MethodPost, "/admin/api/sites",
		`{"name":"hq","id":999,"created_at":"2001-01-01T00:00:00Z",`+
			`"parent_site":{"name":"injected-parent"},`+
			`"probes":[{"name":"injected-probe","registration_key":"k"}]}`)
	h.CreateSite(c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}

	var created models.Site
	if err := db.Gorm().Where("name = ?", "hq").First(&created).Error; err != nil {
		t.Fatalf("read created site: %v", err)
	}
	if created.ID == 999 {
		t.Errorf("client-supplied id was honored")
	}
	if created.CreatedAt.Year() == 2001 {
		t.Errorf("client-supplied created_at was honored")
	}
	var n int64
	db.Gorm().Model(&models.Site{}).Where("name = ?", "injected-parent").Count(&n)
	if n != 0 {
		t.Errorf("nested parent_site was created via mass assignment")
	}
	db.Gorm().Model(&models.Probe{}).Where("name = ?", "injected-probe").Count(&n)
	if n != 0 {
		t.Errorf("nested probes were created via mass assignment")
	}
}

// TestUpdateSite_ParentSiteIDValidation_L14 pins L-14: a parent_site_id that
// is not null or a positive whole number is a 400, never passed to the UPDATE
// (a 500 on PostgreSQL, silently stored on SQLite).
func TestUpdateSite_ParentSiteIDValidation_L14(t *testing.T) {
	h, db := setupTestHandler(t)
	parent := &models.Site{Name: "parent"}
	child := &models.Site{Name: "child"}
	for _, s := range []*models.Site{parent, child} {
		if err := db.Gorm().Create(s).Error; err != nil {
			t.Fatalf("seed site: %v", err)
		}
	}

	router := gin.New()
	router.PUT("/sites/:id", h.UpdateSite)
	put := func(body string) int {
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/sites/%d", child.ID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	for _, bad := range []string{`"abc"`, `-3`, `1.5`, `true`, `1e12`, fmt.Sprint(child.ID)} {
		if code := put(`{"parent_site_id":` + bad + `}`); code != http.StatusBadRequest {
			t.Errorf("parent_site_id=%s: status = %d, want 400", bad, code)
		}
	}

	if code := put(fmt.Sprintf(`{"parent_site_id":%d}`, parent.ID)); code != http.StatusOK {
		t.Fatalf("valid parent: status = %d, want 200", code)
	}
	if code := put(`{"parent_site_id":0}`); code != http.StatusOK {
		t.Fatalf("parent 0 (clear): status = %d, want 200", code)
	}
	var got models.Site
	if err := db.Gorm().First(&got, child.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.ParentSiteID != nil {
		t.Errorf("parent_site_id 0 should clear to NULL, got %d", *got.ParentSiteID)
	}
}
