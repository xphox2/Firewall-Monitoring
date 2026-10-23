package handlers

import (
	"net/http"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestCreateAlertPolicy_IgnoresServerOwnedFields pins H-18: a client must not be
// able to mass-assign the id, is_default flag, or rules association on create.
func TestCreateAlertPolicy_IgnoresServerOwnedFields(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	h := &Handler{db: db}

	c, rec := jsonReq(http.MethodPost, "/admin/api/alert-policies",
		`{"name":"p","is_default":true,"id":999,"rules":[{"alert_type":"LINK_DOWN","enabled":true}]}`)
	h.CreateAlertPolicy(c)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var created models.AlertPolicy
	if err := db.Gorm().First(&created).Error; err != nil {
		t.Fatalf("read created policy: %v", err)
	}
	if created.ID == 999 {
		t.Errorf("client-supplied id %d was honored", created.ID)
	}
	if created.IsDefault {
		t.Error("client-supplied is_default=true was honored")
	}
	var n int64
	if err := db.Gorm().Model(&models.AlertRule{}).Where("policy_id = ?", created.ID).Count(&n).Error; err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if n != 0 {
		t.Errorf("client-supplied rules were honored: %d rules created", n)
	}
}
