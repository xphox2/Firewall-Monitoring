package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestHandler(t *testing.T) (*Handler, *database.Database) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	cfg := &config.Config{}
	h := NewHandler(cfg, nil, db)
	return h, db
}

func setupProbeAndDevice(t *testing.T, db *database.Database) (probe *models.Probe, device *models.Device) {
	t.Helper()
	// Probe.SiteID is a non-nullable uint with a FK to sites (fk_sites_probes).
	// Postgres ENFORCES that FK, so a probe created without a site (site_id=0)
	// fails with SQLSTATE 23503; SQLite (the local default) does not enforce
	// FKs, which is why this passed locally but reddened the integration lane.
	// Seed a real site first and reference it.
	site := &models.Site{Name: "test-site"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}
	// AUDIT-017: keys are stored HASHED at rest, but probes authenticate with
	// the plaintext token. Seed the hash, then expose the plaintext on the
	// returned struct so callers send the real token (validateProbe hashes it
	// and matches the stored hash).
	const probeKey = "test-key-abc123"
	probe = &models.Probe{
		Name:            "test-probe",
		SiteID:          site.ID,
		RegistrationKey: database.HashProbeKey(probeKey),
		ApprovalStatus:  "approved",
		Status:          "online",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("create probe: %v", err)
	}
	probe.RegistrationKey = probeKey
	device = &models.Device{
		Name:      "test-fw",
		IPAddress: "192.168.1.1",
		ProbeID:   &probe.ID,
	}
	if err := db.Gorm().Create(device).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	return
}

func probeAuthHeader(probeID uint, key string) string {
	return "Bearer " + key
}

// doTestRequest performs a test HTTP request against the given handler func.
// Routes the request to /:id/... with probeID set as the :id param.
func doTestRequest(t *testing.T, h func(*gin.Context), method, path string, probeID uint, authKey string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.Handle(method, "/probes/:id"+path, h)

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}

	req := httptest.NewRequest(method, fmt.Sprintf("/probes/%d%s", probeID, path), bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if authKey != "" {
		req.Header.Set("Authorization", probeAuthHeader(probeID, authKey))
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}
