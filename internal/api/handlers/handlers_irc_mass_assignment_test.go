package handlers

import (
	"net/http"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestCreateIRCServer_IgnoresServerOwnedFields pins H-11: a client must not be
// able to mass-assign server-owned fields (id, timestamps, runtime status,
// last_error) on create.
func TestCreateIRCServer_IgnoresServerOwnedFields(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	if err := db.Gorm().AutoMigrate(&models.IRCServer{}, &models.IRCChannel{}); err != nil {
		t.Fatalf("migrate irc tables: %v", err)
	}
	h := &Handler{db: db}

	c, rec := jsonReq(http.MethodPost, "/admin/api/irc/servers",
		`{"name":"srv","server_host":"198.51.100.1","nick":"bot",`+
			`"id":999,"status":"connected","last_error":"injected","created_at":"2020-01-01T00:00:00Z"}`)
	h.CreateIRCServer(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var created models.IRCServer
	if err := db.Gorm().First(&created).Error; err != nil {
		t.Fatalf("read created server: %v", err)
	}
	if created.ID == 999 {
		t.Errorf("client-supplied id %d was honored", created.ID)
	}
	if created.Status == "connected" {
		t.Errorf("client-supplied status %q was honored", created.Status)
	}
	if created.LastError != "" {
		t.Errorf("client-supplied last_error %q was honored", created.LastError)
	}
}

// TestCreateIRCChannel_IgnoresServerOwnedFields pins the same H-11 fix for
// channel creation.
func TestCreateIRCChannel_IgnoresServerOwnedFields(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	if err := db.Gorm().AutoMigrate(&models.IRCServer{}, &models.IRCChannel{}); err != nil {
		t.Fatalf("migrate irc tables: %v", err)
	}
	h := &Handler{db: db}

	c, rec := jsonReq(http.MethodPost, "/admin/api/irc/channels",
		`{"server_id":1,"channel_name":"#ops","id":777,"status":"joined"}`)
	h.CreateIRCChannel(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var created models.IRCChannel
	if err := db.Gorm().First(&created).Error; err != nil {
		t.Fatalf("read created channel: %v", err)
	}
	if created.ID == 777 {
		t.Errorf("client-supplied id %d was honored", created.ID)
	}
	if created.Status == "joined" {
		t.Errorf("client-supplied status %q was honored", created.Status)
	}
}

// TestCreateIRCServer_RejectsBlockedHost pins D-24: a server host that resolves
// to a loopback/private/link-local address is rejected on create (SSRF), like
// the "test connection" endpoint.
func TestCreateIRCServer_RejectsBlockedHost(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	if err := db.Gorm().AutoMigrate(&models.IRCServer{}, &models.IRCChannel{}); err != nil {
		t.Fatalf("migrate irc tables: %v", err)
	}
	h := &Handler{db: db}

	c, rec := jsonReq(http.MethodPost, "/admin/api/irc/servers",
		`{"name":"srv","server_host":"127.0.0.1","nick":"bot"}`)
	h.CreateIRCServer(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
