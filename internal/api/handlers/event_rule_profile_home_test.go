package handlers

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// A rule-update payload WITHOUT profile_id (every pre-PR-3 client) must
// PRESERVE the rule's current layer — folding the bind-zero into Default
// would silently re-home a non-default rule on every edit. Moving a rule is
// expressed with an explicit profile id.
func TestUpdateEventRule_OmittedProfileIDPreservesLayer(t *testing.T) {
	h, db := setupTestHandler(t)
	db.EnsureDefaultEventProfile()
	branch := models.EventRuleProfile{Name: "Branch"}
	if err := db.CreateEventRuleProfile(&branch); err != nil {
		t.Fatal(err)
	}
	r := models.EventRule{Name: "in-branch", Enabled: true, Source: "syslog", Action: "suppress",
		ProfileID: branch.ID, MatchJSON: `{"op":"exists","field":"message"}`}
	if err := db.CreateEventRule(&r); err != nil {
		t.Fatal(err)
	}

	do := func(body string) int {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest("PUT", "/admin/api/event-rules/1", bytes.NewBufferString(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		h.UpdateEventRule(c)
		return rec.Code
	}

	// Legacy payload: no profile_id field at all.
	if code := do(`{"name":"in-branch","enabled":true,"source":"syslog","action":"suppress","match_json":"{\"op\":\"exists\",\"field\":\"message\"}"}`); code != 200 {
		t.Fatalf("update: HTTP %d", code)
	}
	var got models.EventRule
	db.Gorm().First(&got, r.ID)
	if got.ProfileID != branch.ID {
		t.Fatalf("omitted profile_id re-homed the rule: got profile %d, want %d (Branch)", got.ProfileID, branch.ID)
	}

	// Explicit move to Default works.
	def, _ := db.GetDefaultEventRuleProfile()
	if code := do(`{"name":"in-branch","enabled":true,"source":"syslog","action":"suppress","match_json":"{\"op\":\"exists\",\"field\":\"message\"}","profile_id":` + fmt.Sprintf("%d", def.ID) + `}`); code != 200 {
		t.Fatalf("explicit move: HTTP %d", code)
	}
	got = models.EventRule{}
	db.Gorm().First(&got, r.ID)
	if got.ProfileID != def.ID {
		t.Fatalf("explicit profile_id must move the rule: got %d, want %d", got.ProfileID, def.ID)
	}

	// Unknown profile → 400.
	if code := do(`{"name":"in-branch","source":"syslog","action":"suppress","match_json":"{\"op\":\"exists\",\"field\":\"message\"}","profile_id":9999}`); code != 400 {
		t.Fatalf("unknown profile must 400, got %d", code)
	}
}

// M-fix regression: the suggester's governing-profile resolution must use the
// DEVICE'S actual site (alert.SiteID is only stamped on device-less rollups),
// or a class suppress for a device under a site profile would land in Default
// where the site layer out-ranks it.
func TestSuggestEventRule_GoverningProfileUsesDeviceSite(t *testing.T) {
	h, db := setupTestHandler(t)
	db.EnsureDefaultEventProfile()
	siteProf := models.EventRuleProfile{Name: "SiteProf"}
	if err := db.CreateEventRuleProfile(&siteProf); err != nil {
		t.Fatal(err)
	}
	site := models.Site{Name: "branch-site"}
	if err := db.Gorm().Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.SetSiteEventProfile(site.ID, &siteProf.ID); err != nil {
		t.Fatal(err)
	}
	dev := models.Device{Name: "fw-b", IPAddress: "10.2.2.2", Vendor: "fortigate", SiteID: &site.ID}
	if err := db.Gorm().Create(&dev).Error; err != nil {
		t.Fatal(err)
	}
	// Device-attributed alert: SiteID deliberately nil (only rollups carry it).
	alert := models.Alert{DeviceID: dev.ID, AlertType: models.AlertTypeDeviceOffline,
		Severity: "critical", Message: "offline", MetricName: "device_offline"}
	if err := db.Gorm().Create(&alert).Error; err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest("GET", "/admin/api/alerts/1/suggested-rule", nil)
	c.Params = gin.Params{{Key: "id", Value: fmt.Sprintf("%d", alert.ID)}}
	h.SuggestEventRuleForAlert(c)
	if rec.Code != 200 {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte(`"profile_name":"SiteProf"`)) {
		t.Fatalf("suggestion must target the device's SITE profile (chain head), got: %s", body)
	}
}
