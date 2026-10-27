package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// alertConfigReq builds a request for the device alert-config endpoint.
//
// The handler reads the device id from the ROUTE, so the test has to set the
// route parameter: a gin test context is not routed.
func alertConfigReq(t *testing.T, deviceID string, body map[string]interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal the body: %v", err)
	}
	c, rec := jsonReq(http.MethodPut, "/admin/api/devices/"+deviceID, string(raw))
	c.Params = gin.Params{{Key: "id", Value: deviceID}}
	return c, rec
}

// TestUpsertDeviceAlertConfig_ProfileIsAtomic pins that the alert config
// and the event profile are written TOGETHER.
//
// They used to be two requests: the console committed the config, then
// assigned the profile. A failure between them left HALF an override
// applied, with a save that reported failure. The console now sends one
// request and the server writes both in one transaction.
//
// The two properties that matter:
//   - assigning a profile is ADMIN-ONLY (the event-profile routes are in
//     adminOnlyRoutes), so a non-admin asking for one is refused, not
//     silently ignored;
//   - a body that does not ask for a profile leaves the assignment alone.
func TestUpsertDeviceAlertConfig_ProfileIsAtomic(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	h := &Handler{db: db}
	// A profile for the assignment to point at.
	profile := &models.EventRuleProfile{Name: "strict"}
	if err := db.Gorm().Create(profile).Error; err != nil {
		t.Fatalf("create the profile: %v", err)
	}

	t.Run("an admin assigns the profile in the same request", func(t *testing.T) {
		c, rec := alertConfigReq(t, "1", map[string]interface{}{
			"cpu_threshold":    80,
			"event_profile_id": profile.ID,
		})
		c.Set("role", auth.RoleAdmin)
		h.UpsertDeviceAlertConfig(c)

		if rec.Code != http.StatusOK {
			t.Fatalf("the save was refused: %d %s", rec.Code, rec.Body.String())
		}
		cfg, err := db.GetDeviceAlertConfig(1)
		if err != nil {
			t.Fatalf("read the config back: %v", err)
		}
		if cfg.CPUThreshold != 80 {
			t.Errorf("the threshold was not written: %v", cfg.CPUThreshold)
		}
		if cfg.EventProfileID == nil || *cfg.EventProfileID != profile.ID {
			t.Errorf("the event profile was not assigned: %v", cfg.EventProfileID)
		}
	})

	t.Run("a non-admin is refused, not silently ignored", func(t *testing.T) {
		c, rec := alertConfigReq(t, "2", map[string]interface{}{
			"cpu_threshold":    70,
			"event_profile_id": profile.ID,
		})
		c.Set("role", auth.RoleOperator)
		h.UpsertDeviceAlertConfig(c)

		if rec.Code != http.StatusForbidden {
			t.Errorf("a non-admin's profile assignment answered %d, want 403 — assigning a profile is admin-only", rec.Code)
		}
		cfg, err := db.GetDeviceAlertConfig(2)
		if err == nil && cfg.CPUThreshold == 70 {
			t.Error("the config was written even though the request was refused — the whole save must be refused")
		}
	})

	t.Run("a body with no profile leaves the assignment alone", func(t *testing.T) {
		c, rec := alertConfigReq(t, "1", map[string]interface{}{"cpu_threshold": 60})
		c.Set("role", auth.RoleOperator)
		h.UpsertDeviceAlertConfig(c)

		if rec.Code != http.StatusOK {
			t.Fatalf("the save was refused: %d %s", rec.Code, rec.Body.String())
		}
		cfg, err := db.GetDeviceAlertConfig(1)
		if err != nil {
			t.Fatalf("read the config back: %v", err)
		}
		if cfg.EventProfileID == nil || *cfg.EventProfileID != profile.ID {
			t.Errorf("the event profile was changed by a save that did not ask for it: %v", cfg.EventProfileID)
		}
	})

	t.Run("an unknown profile is refused", func(t *testing.T) {
		c, rec := alertConfigReq(t, "3", map[string]interface{}{"event_profile_id": 999999})
		c.Set("role", auth.RoleAdmin)
		h.UpsertDeviceAlertConfig(c)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("an unknown profile answered %d, want 400", rec.Code)
		}
	})
}
