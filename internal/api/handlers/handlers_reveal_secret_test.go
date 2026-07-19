package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// revealCtx builds an authenticated admin gin.Context for the reveal endpoint,
// with the device id in the path params and the caller identity on the context
// (as the AdminAuth middleware would set it).
func revealCtx(deviceID uint, username string, userID uint, body string) (*gin.Context, *httptest.ResponseRecorder) {
	c, rec := jsonReq(http.MethodPost, "/admin/api/devices/x/reveal-secret", body)
	c.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(uint64(deviceID), 10)}}
	c.Set("username", username)
	c.Set("user_id", userID)
	return c, rec
}

func TestRevealDeviceSecret_Success(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SSHPassword: "actual-ssh-pw"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}

	c, rec := revealCtx(dev.ID, "admin1", u.ID, `{"password":"s3cret-pw","field":"ssh_password"}`)
	h.RevealDeviceSecret(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Data struct {
			Field  string `json:"field"`
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Secret != "actual-ssh-pw" || resp.Data.Field != "ssh_password" {
		t.Fatalf("got field=%q secret=%q, want ssh_password/actual-ssh-pw", resp.Data.Field, resp.Data.Secret)
	}

	// The reveal is audit-logged with an explicit record naming the field.
	var n int64
	db.Gorm().Model(&models.AuditLog{}).Where("action = ?", "reveal_secret").Count(&n)
	if n != 1 {
		t.Errorf("audit rows for reveal_secret = %d, want 1", n)
	}
}

func TestRevealDeviceSecret_WrongPassword(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SSHPassword: "actual-ssh-pw"}
	db.Gorm().Create(dev)

	c, rec := revealCtx(dev.ID, "admin1", u.ID, `{"password":"WRONG","field":"ssh_password"}`)
	h.RevealDeviceSecret(c)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a wrong password", rec.Code)
	}
	// A failed reveal writes no explicit reveal_secret record (the audit
	// middleware records the attempt+status independently in production).
	var n int64
	db.Gorm().Model(&models.AuditLog{}).Where("action = ?", "reveal_secret").Count(&n)
	if n != 0 {
		t.Errorf("audit rows after failed reveal = %d, want 0", n)
	}
}

func TestRevealDeviceSecret_UnknownField(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SSHPassword: "actual-ssh-pw"}
	db.Gorm().Create(dev)

	c, rec := revealCtx(dev.ID, "admin1", u.ID, `{"password":"s3cret-pw","field":"jwt_secret"}`)
	h.RevealDeviceSecret(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-whitelisted field", rec.Code)
	}
}

func TestRevealDeviceSecret_EmptyStored(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1"} // no ssh password stored
	db.Gorm().Create(dev)

	c, rec := revealCtx(dev.ID, "admin1", u.ID, `{"password":"s3cret-pw","field":"ssh_password"}`)
	h.RevealDeviceSecret(c)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when nothing is stored", rec.Code)
	}
}

func TestRevealDeviceSecret_EmptyPassword(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SSHPassword: "actual-ssh-pw"}
	db.Gorm().Create(dev)

	c, rec := revealCtx(dev.ID, "admin1", u.ID, `{"password":"","field":"ssh_password"}`)
	h.RevealDeviceSecret(c)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an empty password", rec.Code)
	}
}

// TestRevealDeviceSecret_TOTPStepUp: a 2FA-enrolled admin must also supply a
// valid authenticator code — a correct password alone is rejected.
func TestRevealDeviceSecret_TOTPStepUp(t *testing.T) {
	h, db, u := profileTestHandler(t, "admin1", auth.RoleAdmin, "s3cret-pw")
	const secret = "JBSWY3DPEHPK3PXP" // valid base32 test secret
	if err := db.Gorm().Model(&models.Admin{}).Where("id = ?", u.ID).
		Updates(map[string]interface{}{"totp_enabled": true, "totp_secret": secret}).Error; err != nil {
		t.Fatalf("enroll TOTP: %v", err)
	}
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SSHPassword: "actual-ssh-pw"}
	db.Gorm().Create(dev)

	// Correct password, no code → 403.
	c, rec := revealCtx(dev.ID, "admin1", u.ID, `{"password":"s3cret-pw","field":"ssh_password"}`)
	h.RevealDeviceSecret(c)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when 2FA enrolled and no code supplied", rec.Code)
	}

	// Correct password + valid code → 200.
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	c2, rec2 := revealCtx(dev.ID, "admin1", u.ID, `{"password":"s3cret-pw","totp_code":"`+code+`","field":"ssh_password"}`)
	h.RevealDeviceSecret(c2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with a valid 2FA code", rec2.Code)
	}
}

// TestRedactDevice_MasksSSHPassword pins that the SSH password is masked on GET
// like the SNMP secrets — it must only be recoverable via the reveal endpoint.
func TestRedactDevice_MasksSSHPassword(t *testing.T) {
	d := &models.Device{SSHPassword: "actual-ssh-pw", SNMPCommunity: "public"}
	httputil.RedactDevice(d)
	if d.SSHPassword != httputil.RedactedMask {
		t.Errorf("ssh_password = %q after redact, want %q", d.SSHPassword, httputil.RedactedMask)
	}
	if d.SNMPCommunity != httputil.RedactedMask {
		t.Errorf("snmp_community = %q after redact, want mask", d.SNMPCommunity)
	}
}

// TestRedactDevice_MasksAPIToken pins that the vendor REST API token (PR-C1) is
// masked on every read path like the other device credentials.
func TestRedactDevice_MasksAPIToken(t *testing.T) {
	d := &models.Device{APIToken: "secret-bearer-token", APIPort: 8443}
	httputil.RedactDevice(d)
	if d.APIToken != httputil.RedactedMask {
		t.Errorf("api_token = %q after redact, want %q", d.APIToken, httputil.RedactedMask)
	}
	if d.APIPort != 8443 {
		t.Errorf("api_port = %d after redact, want 8443 (non-secret, unchanged)", d.APIPort)
	}
}
