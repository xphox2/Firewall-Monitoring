package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestProbeAuth_HashedKey_AUDIT017 verifies end-to-end that a probe whose key is
// stored HASHED authenticates with the plaintext token, rejects a wrong token,
// and — importantly — rejects the stored HASH presented as a token (sending the
// at-rest value must not grant access, since validateProbe hashes the input).
func TestProbeAuth_HashedKey_AUDIT017(t *testing.T) {
	h, db := setupTestHandler(t)
	const plain = "the-real-probe-token-xyz"
	probe := &models.Probe{
		Name:            "p",
		RegistrationKey: database.HashProbeKey(plain), // stored hashed
		ApprovalStatus:  "approved",
		Status:          "online",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}

	post := func(token string) int {
		router := gin.New()
		router.POST("/api/probes/:id/syslog", h.ReceiveSyslogMessages)
		body, _ := json.Marshal([]models.SyslogMessage{{Message: "x", SourceIP: "10.0.0.1"}})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/syslog", probe.ID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	if code := post(plain); code != http.StatusOK {
		t.Errorf("correct plaintext token: status=%d, want 200", code)
	}
	if code := post("wrong-token"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: status=%d, want 401", code)
	}
	if code := post(database.HashProbeKey(plain)); code != http.StatusUnauthorized {
		t.Errorf("presenting the stored HASH as the token authenticated (status=%d) — it must be rejected (401)", code)
	}
}
