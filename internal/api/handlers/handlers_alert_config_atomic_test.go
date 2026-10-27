package handlers

import (
	"encoding/json"
	"fmt"
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

	t.Run("a non-admin cannot CLEAR the profile either", func(t *testing.T) {
		// The alert-config route is operator-level, and the struct's own
		// JSON tag binds `event_profile_id: null` into the config, so the
		// plain save would write NULL. Without the gate, an operator
		// could clear an override that only an admin may touch.
		c, rec := alertConfigReq(t, "4", map[string]interface{}{
			"event_profile_id": nil,
		})
		c.Set("role", auth.RoleOperator)
		h.UpsertDeviceAlertConfig(c)

		if rec.Code != http.StatusForbidden {
			t.Errorf("a non-admin's profile CLEAR answered %d, want 403 — clearing an assignment is admin-only", rec.Code)
		}
	})

	t.Run("an admin clears the profile with an explicit null", func(t *testing.T) {
		c, rec := alertConfigReq(t, "1", map[string]interface{}{
			"event_profile_id": nil,
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
		if cfg.EventProfileID != nil {
			t.Errorf("the event profile was not cleared: %v", *cfg.EventProfileID)
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

	t.Run("a fractional id is refused, not truncated", func(t *testing.T) {
		// uint(3.9) is 3: without the check, a malformed id would assign a
		// profile nobody named.
		c, rec := alertConfigReq(t, "3", map[string]interface{}{"event_profile_id": float64(profile.ID) + 0.9})
		c.Set("role", auth.RoleAdmin)
		h.UpsertDeviceAlertConfig(c)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("a fractional profile id answered %d, want 400", rec.Code)
		}
	})
}

// TestUpsertAlertConfig_BindCannotMoveTheProfile pins that the struct bind
// never assigns or clears an event profile.
//
// encoding/json matches keys CASE-INSENSITIVELY, so a body that spells the
// key differently binds onto EventProfileID while the admin gate - which
// looks for the exact key - sees nothing. An operator assigned an admin-only
// profile that way (200, profile written) until the handler restored the
// stored value after the bind.
func TestUpsertAlertConfig_BindCannotMoveTheProfile(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	h := &Handler{db: db}
	strict := &models.EventRuleProfile{Name: "strict"}
	quiet := &models.EventRuleProfile{Name: "quiet"}
	for _, p := range []*models.EventRuleProfile{strict, quiet} {
		if err := db.Gorm().Create(p).Error; err != nil {
			t.Fatalf("create profile %s: %v", p.Name, err)
		}
	}
	// An admin-assigned profile on both scopes, for the clear attempts.
	if err := db.UpsertDeviceAlertConfigWithProfile(&models.DeviceAlertConfig{DeviceID: 1, AlertsEnabled: true}, &strict.ID); err != nil {
		t.Fatalf("seed the device override: %v", err)
	}
	if err := db.UpsertSiteAlertConfigWithProfile(&models.SiteAlertConfig{SiteID: 1}, &strict.ID); err != nil {
		t.Fatalf("seed the site override: %v", err)
	}

	for _, key := range []string{"Event_Profile_ID", "EVENT_PROFILE_ID", "Event_profile_id"} {
		for _, value := range []interface{}{quiet.ID, nil} {
			t.Run(fmt.Sprintf("device %s=%v", key, value), func(t *testing.T) {
				c, rec := alertConfigReq(t, "1", map[string]interface{}{"cpu_threshold": 70, key: value})
				c.Set("role", auth.RoleOperator)
				h.UpsertDeviceAlertConfig(c)
				if rec.Code != http.StatusOK {
					t.Fatalf("the operator's threshold save was refused: %d %s", rec.Code, rec.Body.String())
				}
				cfg, err := db.GetDeviceAlertConfig(1)
				if err != nil {
					t.Fatalf("read the device config back: %v", err)
				}
				if cfg.EventProfileID == nil || *cfg.EventProfileID != strict.ID {
					t.Errorf("an operator moved the device's event profile with %q: now %v, want %d", key, derefUint(cfg.EventProfileID), strict.ID)
				}
			})
			t.Run(fmt.Sprintf("site %s=%v", key, value), func(t *testing.T) {
				raw, err := json.Marshal(map[string]interface{}{"cpu_threshold": 70, key: value})
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				c, rec := jsonReq(http.MethodPut, "/admin/api/sites/1/alert-config", string(raw))
				c.Params = gin.Params{{Key: "id", Value: "1"}}
				c.Set("role", auth.RoleOperator)
				h.UpsertSiteAlertConfig(c)
				if rec.Code != http.StatusOK {
					t.Fatalf("the operator's threshold save was refused: %d %s", rec.Code, rec.Body.String())
				}
				cfg, err := db.GetSiteAlertConfig(1)
				if err != nil {
					t.Fatalf("read the site config back: %v", err)
				}
				if cfg.EventProfileID == nil || *cfg.EventProfileID != strict.ID {
					t.Errorf("an operator moved the site's event profile with %q: now %v, want %d", key, derefUint(cfg.EventProfileID), strict.ID)
				}
			})
		}
	}
}

func derefUint(p *uint) interface{} {
	if p == nil {
		return nil
	}
	return *p
}
