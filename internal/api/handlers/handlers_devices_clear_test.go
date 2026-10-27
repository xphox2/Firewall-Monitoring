package handlers

import (
	"net/http"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
)

// TestPrepareDeviceUpdates_ClearsSecretsOnlyWhenAsked pins the explicit
// clear.
//
// The secret handling is deliberately conservative: a masked or empty value
// means "leave unchanged", because a client that loads a device and saves it
// back resends the mask, and writing the mask over the real secret
// silently breaks SNMP polling.
//
// That conservatism left an operator with NO way to remove a credential — an
// API token they no longer want, an SSH password that should not be stored.
// So clearing is explicit: a `clear_secrets` array naming the fields to
// empty.
//
// The two properties that matter:
//   - the round-trip safety is UNTOUCHED — an empty or masked value still
//     means "leave unchanged";
//   - the array can only name a real credential, so it can never be used to
//     write an arbitrary column.
func TestPrepareDeviceUpdates_ClearsSecretsOnlyWhenAsked(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw", IPAddress: "192.0.2.1"}

	t.Run("an empty secret still means leave unchanged", func(t *testing.T) {
		c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
		c.Set("role", auth.RoleAdmin)
		out, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{
			"api_token": "",
		})
		if !ok {
			t.Fatalf("the update was rejected: %d", c.Writer.Status())
		}
		if _, has := out["api_token"]; has {
			t.Error("an empty secret was written — it must mean 'leave unchanged', or a round-trip save destroys the credential")
		}
	})

	t.Run("a masked secret still means leave unchanged", func(t *testing.T) {
		c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
		c.Set("role", auth.RoleAdmin)
		out, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{
			"api_token": httputil.RedactedMask,
		})
		if !ok {
			t.Fatalf("the update was rejected: %d", c.Writer.Status())
		}
		if _, has := out["api_token"]; has {
			t.Error("the mask was written over the secret — a round-trip save would destroy the credential")
		}
	})

	t.Run("clear_secrets empties the named field", func(t *testing.T) {
		c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
		c.Set("role", auth.RoleAdmin)
		out, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{
			"clear_secrets": []interface{}{"api_token"},
		})
		if !ok {
			t.Fatalf("the update was rejected: %d", c.Writer.Status())
		}
		if got, has := out["api_token"]; !has || got != "" {
			t.Errorf("api_token was not cleared: %v", out["api_token"])
		}
	})

	t.Run("clear_secrets is not a column", func(t *testing.T) {
		c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
		c.Set("role", auth.RoleAdmin)
		updates := map[string]interface{}{
			"clear_secrets": []interface{}{"api_token"},
		}
		out, ok := prepareDeviceUpdates(c, db, dev, updates)
		if !ok {
			t.Fatalf("the update was rejected: %d", c.Writer.Status())
		}
		if _, has := out["clear_secrets"]; has {
			t.Error("clear_secrets reached the update map — it is not a column, and gorm would try to write it")
		}
		if _, has := updates["clear_secrets"]; has {
			t.Error("clear_secrets was not removed from the raw updates — it would reach the database write")
		}
	})

	t.Run("clear_secrets may only name a credential", func(t *testing.T) {
		for _, name := range []string{"name", "ip_address", "public_visible", "bogus"} {
			c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
			c.Set("role", auth.RoleAdmin)
			_, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{
				"clear_secrets": []interface{}{name},
			})
			if ok {
				t.Errorf("clear_secrets accepted %q — it must only name a device credential, or it is a way to write an arbitrary column", name)
			}
			if c.Writer.Status() != http.StatusBadRequest {
				t.Errorf("clearing %q answered %d, want 400", name, c.Writer.Status())
			}
		}
	})

	t.Run("clear_secrets is admin-only", func(t *testing.T) {
		// The device update route is operator-level, and the console
		// hides the Clear control from an operator — so without a check
		// here, the control is the only thing between an operator and a
		// cleared credential.
		c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
		c.Set("role", auth.RoleOperator)
		_, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{
			"clear_secrets": []interface{}{"api_token"},
		})
		if ok {
			t.Error("an operator cleared a credential — removing one is admin-only")
		}
		if c.Writer.Status() != http.StatusForbidden {
			t.Errorf("answered %d, want 403", c.Writer.Status())
		}
	})

	t.Run("clear_secrets must be an array", func(t *testing.T) {
		c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
		c.Set("role", auth.RoleAdmin)
		_, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{
			"clear_secrets": "api_token",
		})
		if ok {
			t.Error("a non-array clear_secrets was accepted")
		}
		if c.Writer.Status() != http.StatusBadRequest {
			t.Errorf("answered %d, want 400", c.Writer.Status())
		}
	})
}
