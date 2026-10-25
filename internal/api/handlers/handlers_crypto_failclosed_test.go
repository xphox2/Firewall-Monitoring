package handlers

import (
	"net/http"
	"strings"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// D-12: every handler write path that encrypts a secret must abort with a 500
// when encryption fails — never persist the plaintext. A keyless Database with
// the test harness's passthrough turned off (RequireEncryptionKeyForTesting)
// behaves like a production Database whose key is missing. Synthetic data only
// (RFC 5737, fw-example-NN).

// mustEncryptField encrypts a fixture value, failing the test on error.
func mustEncryptField(t testing.TB, db interface {
	EncryptField(string) (string, error)
}, v string) string {
	t.Helper()
	ct, err := db.EncryptField(v)
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}
	return ct
}

// noRowContains fails if any row of table has a column holding needle.
func noRowContains(t *testing.T, db *database.Database, table, col, needle string) {
	t.Helper()
	var n int64
	if err := db.Gorm().Table(table).Where(col+" LIKE ?", "%"+needle+"%").Count(&n).Error; err != nil {
		t.Fatalf("scan %s.%s: %v", table, col, err)
	}
	if n != 0 {
		t.Fatalf("%s.%s holds the plaintext secret in %d row(s)", table, col, n)
	}
}

func TestUpdateDevice_EncryptFailureIs500AndStoresNothing(t *testing.T) {
	h, db := setupTestHandler(t)
	db.RequireEncryptionKeyForTesting()
	dev := &models.Device{Name: "fw-example-10", IPAddress: "192.0.2.20", SNMPVersion: "2c", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"snmp_community", "ssh_password", "api_token"} {
		w := doPartialUpdateRequest(t, h.UpdateDevice, "/api/devices/:id", dev.ID,
			map[string]interface{}{"name": "fw-example-10-renamed", field: "plain-" + field})
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("%s: status=%d body=%s, want 500", field, w.Code, w.Body.String())
		}
		noRowContains(t, db, "devices", field, "plain-"+field)
	}
	var after models.Device
	db.Gorm().First(&after, dev.ID)
	if after.Name != "fw-example-10" {
		t.Fatalf("the aborted update still wrote other fields (name=%q)", after.Name)
	}
}

func TestCreateDevice_EncryptFailureIs500(t *testing.T) {
	h, db := setupTestHandler(t)
	db.RequireEncryptionKeyForTesting()
	c, rec := jsonReq(http.MethodPost, "/api/devices",
		`{"name":"fw-example-11","ip_address":"192.0.2.21","snmp_version":"2c","snmp_community":"plain-community"}`)
	h.CreateDevice(c)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	var n int64
	db.Gorm().Model(&models.Device{}).Count(&n)
	if n != 0 {
		t.Fatalf("device stored despite the encryption failure")
	}
}

func TestUpdateSettings_EncryptFailureIs500(t *testing.T) {
	h, db := setupTestHandler(t)
	db.RequireEncryptionKeyForTesting()
	w := doSettingsRequest(t, h.UpdateSettings, "PUT", []models.SystemSetting{
		{Key: "smtp_password", Value: "plain-smtp-password"},
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	noRowContains(t, db, "system_settings", "value", "plain-smtp-password")
}

func ircHandler(t *testing.T) (*Handler, *database.Database) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	if err := db.Gorm().AutoMigrate(&models.IRCServer{}, &models.IRCChannel{}); err != nil {
		t.Fatalf("migrate irc tables: %v", err)
	}
	return &Handler{db: db}, db
}

func TestIRC_EncryptFailureIs500(t *testing.T) {
	h, db := ircHandler(t)
	srv := models.IRCServer{Name: "srv", ServerHost: "198.51.100.1", Nick: "bot"}
	if err := db.Gorm().Create(&srv).Error; err != nil {
		t.Fatal(err)
	}
	ch := models.IRCChannel{ServerID: srv.ID, ChannelName: "#ops"}
	if err := db.Gorm().Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	db.RequireEncryptionKeyForTesting()

	c, rec := jsonReq(http.MethodPost, "/admin/api/irc/servers",
		`{"name":"srv2","server_host":"198.51.100.2","nick":"bot","server_password":"plain-irc-pass"}`)
	h.CreateIRCServer(c)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create server: status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}

	c, rec = jsonReq(http.MethodPost, "/admin/api/irc/channels",
		`{"server_id":1,"channel_name":"#sec","channel_key":"plain-chan-key"}`)
	h.CreateIRCChannel(c)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create channel: status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}

	w := doPartialUpdateRequest(t, h.UpdateIRCServer, "/admin/api/irc/servers/:id", srv.ID,
		map[string]interface{}{"sasl_password": "plain-sasl"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("update server: status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	w = doPartialUpdateRequest(t, h.UpdateIRCChannel, "/admin/api/irc/channels/:id", ch.ID,
		map[string]interface{}{"chanserv_password": "plain-chanserv"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("update channel: status=%d body=%s, want 500", w.Code, w.Body.String())
	}

	noRowContains(t, db, "irc_servers", "server_password", "plain-irc-pass")
	noRowContains(t, db, "irc_servers", "sasl_password", "plain-sasl")
	noRowContains(t, db, "irc_channels", "channel_key", "plain-chan-key")
	noRowContains(t, db, "irc_channels", "chanserv_password", "plain-chanserv")
}

func TestSetup2FA_EncryptFailureIs500(t *testing.T) {
	h, db, u := profileTestHandler(t, "op", auth.RoleOperator, "pw-operator")
	db.RequireEncryptionKeyForTesting()
	c, body := profileReq(http.MethodPost, "/admin/api/2fa/setup", `{"password":"pw-operator"}`, "op", auth.RoleOperator, u.ID)
	h.Setup2FA(c)
	if c.Writer.Status() != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%s)", c.Writer.Status(), body.String())
	}
	var after models.Admin
	if err := db.Gorm().First(&after, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.TOTPSecret != "" {
		t.Fatalf("TOTP secret stored despite the encryption failure: %q", after.TOTPSecret)
	}
}

// TestUpdateDevice_NewSecretIsEnc2 — D-11 through the handler: a saved
// credential lands as {enc2}, and re-sending an existing {enc2} value is not
// double-encrypted.
func TestUpdateDevice_NewSecretIsEnc2(t *testing.T) {
	h, db := setupTestHandler(t)
	db.SetEncryptionKeyForTesting("handler-enc2-key")
	dev := &models.Device{Name: "fw-example-12", IPAddress: "192.0.2.22", SNMPVersion: "2c", Enabled: true}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	w := doPartialUpdateRequest(t, h.UpdateDevice, "/api/devices/:id", dev.ID,
		map[string]interface{}{"ssh_password": "fresh-ssh-password"})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var raw models.Device
	db.Gorm().First(&raw, dev.ID)
	if !strings.HasPrefix(raw.SSHPassword, "{enc2}") || db.DecryptField(raw.SSHPassword) != "fresh-ssh-password" {
		t.Fatalf("ssh_password stored as %q, want {enc2} ciphertext of the new value", raw.SSHPassword)
	}

	stored := raw.SSHPassword
	w = doPartialUpdateRequest(t, h.UpdateDevice, "/api/devices/:id", dev.ID,
		map[string]interface{}{"ssh_password": stored})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	db.Gorm().First(&raw, dev.ID)
	if raw.SSHPassword != stored {
		t.Fatalf("an {enc2} value was re-encrypted: %q -> %q", stored, raw.SSHPassword)
	}
}
