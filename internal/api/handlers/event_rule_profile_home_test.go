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
