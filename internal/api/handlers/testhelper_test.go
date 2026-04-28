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
	probe = &models.Probe{
		Name:            "test-probe",
		RegistrationKey: "test-key-abc123",
		ApprovalStatus:  "approved",
		Status:          "online",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("create probe: %v", err)
	}
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
