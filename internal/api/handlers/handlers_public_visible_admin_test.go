package handlers

import (
	"net/http"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestPrepareDeviceUpdates_PublicVisibleAdminOnly pins H-10: public_visible is
// the sole control exposing a device to the unauthenticated public dashboard, so
// changing it is admin-only. An operator must be refused; an admin may proceed.
func TestPrepareDeviceUpdates_PublicVisibleAdminOnly(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw", IPAddress: "192.0.2.1"}

	// Operator → 403.
	c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
	c.Set("role", auth.RoleOperator)
	if _, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{"public_visible": true}); ok {
		t.Fatal("operator must not be able to change public_visible")
	}
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("operator status = %d, want 403", c.Writer.Status())
	}

	// Admin → allowed.
	c2, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
	c2.Set("role", auth.RoleAdmin)
	updates, ok := prepareDeviceUpdates(c2, db, dev, map[string]interface{}{"public_visible": true, "name": "x"})
	if !ok {
		t.Fatalf("admin must be able to change public_visible (status %d)", c2.Writer.Status())
	}
	if _, has := updates["public_visible"]; !has {
		t.Fatal("admin's public_visible update was dropped")
	}
}

// TestPrepareDeviceUpdates_APIInsecureTLSAdminOnly pins D-25: api_insecure_tls
// (disables TLS verification for the vendor REST API) is admin-only.
func TestPrepareDeviceUpdates_APIInsecureTLSAdminOnly(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw", IPAddress: "192.0.2.1"}

	c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
	c.Set("role", auth.RoleOperator)
	if _, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{"api_insecure_tls": true}); ok {
		t.Fatal("operator must not be able to change api_insecure_tls")
	}
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("operator status = %d, want 403", c.Writer.Status())
	}

	c2, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
	c2.Set("role", auth.RoleAdmin)
	updates, ok := prepareDeviceUpdates(c2, db, dev, map[string]interface{}{"api_insecure_tls": true})
	if !ok {
		t.Fatalf("admin must be able to change api_insecure_tls (status %d)", c2.Writer.Status())
	}
	if _, has := updates["api_insecure_tls"]; !has {
		t.Fatal("admin's api_insecure_tls update was dropped")
	}
}
