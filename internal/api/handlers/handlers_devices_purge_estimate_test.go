package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestEstimateDevicePurge_ReportsTheCapAndTheBlockers pins the two
// things the estimate was NOT telling the operator. (The cap's aggregate flag
// is proven in the database package, where the cap can be lowered:
// purge_test.go, est.Capped.)
//
// The total: a per-table count is capped, so when any table is capped the
// TOTAL is a lower bound. Without the flag the dialog rendered "of
// 100,000" for a table that holds 134 million rows.
//
// The blockers: the purge refuses an IPSec tunnel that is deploying or
// rolling back, and it refuses a device that already has a queued job. The
// estimate is what the operator reads BEFORE they commit, so a blocker
// discovered at the estimate is a blocker they can act on — instead of a
// 409 after they have already typed the device's name.
func TestEstimateDevicePurge_ReportsTheCapAndTheBlockers(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	h := &Handler{db: db}

	// A retired device: the estimate refuses a live one.
	device := &models.Device{Name: "fw-old", IPAddress: "192.0.2.1", RetiredAt: nowPtr()}
	if err := db.Gorm().Create(device).Error; err != nil {
		t.Fatalf("create the device: %v", err)
	}

	t.Run("the estimate is refused for a live device", func(t *testing.T) {
		live := &models.Device{Name: "fw-live", IPAddress: "192.0.2.2"}
		if err := db.Gorm().Create(live).Error; err != nil {
			t.Fatalf("create the device: %v", err)
		}
		// The live device is the SECOND one created, so it is not id 1.
		c, rec := jsonReq(http.MethodGet, "/admin/api/devices/2/purge/estimate", "")
		c.Params = paramsFor("id", "2")
		c.Set("role", auth.RoleAdmin)
		h.EstimateDevicePurge(c)
		if rec.Code != http.StatusConflict {
			t.Errorf("the estimate for a live device answered %d, want 409", rec.Code)
		}
	})

	t.Run("a queued job is a blocker", func(t *testing.T) {
		job := &models.DevicePurgeJob{
			DeviceID:    device.ID,
			DeviceUUID:  device.UUID,
			DeviceName:  device.Name,
			RequestedBy: "admin",
			Status:      "pending",
		}
		if err := db.Gorm().Create(job).Error; err != nil {
			t.Fatalf("create the job: %v", err)
		}
		c, rec := jsonReq(http.MethodGet, "/admin/api/devices/1/purge/estimate", "")
		c.Params = paramsFor("id", "1")
		c.Set("role", auth.RoleAdmin)
		h.EstimateDevicePurge(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("the estimate was refused: %d %s", rec.Code, rec.Body.String())
		}
		body := decodeEstimate(t, rec.Body.String())
		if len(body.Blockers) == 0 {
			t.Error("the estimate did not mention the queued job — the operator would only find out when the purge answered 409")
		}
	})

	t.Run("a tunnel that is deploying or rolling back is a blocker", func(t *testing.T) {
		// A separate retired device, so the queued job above is not what is
		// being reported.
		dev := &models.Device{Name: "fw-ipsec", IPAddress: "192.0.2.3", RetiredAt: nowPtr()}
		peer := &models.Device{Name: "fw-peer", IPAddress: "192.0.2.4"}
		for _, d := range []*models.Device{dev, peer} {
			if err := db.Gorm().Create(d).Error; err != nil {
				t.Fatalf("create the device: %v", err)
			}
		}
		for _, tun := range []*models.IPSecTunnel{
			{Name: "settled", ADeviceID: dev.ID, BDeviceID: peer.ID, Status: "up"},
			{Name: "mid-deploy", ADeviceID: peer.ID, BDeviceID: dev.ID, Status: ipsecStatusDeploying},
		} {
			if err := db.Gorm().Create(tun).Error; err != nil {
				t.Fatalf("create the tunnel: %v", err)
			}
		}
		id := strconv.FormatUint(uint64(dev.ID), 10)
		c, rec := jsonReq(http.MethodGet, "/admin/api/devices/"+id+"/purge/estimate", "")
		c.Params = paramsFor("id", id)
		c.Set("role", auth.RoleAdmin)
		h.EstimateDevicePurge(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("the estimate was refused: %d %s", rec.Code, rec.Body.String())
		}
		body := decodeEstimate(t, rec.Body.String())
		if len(body.Blockers) != 1 || !strings.Contains(body.Blockers[0], "mid-deploy") {
			t.Errorf("blockers = %q, want exactly the deploying tunnel (the settled one is not a blocker)", body.Blockers)
		}
	})
}

// nowPtr is the timestamp for a retired device.
func nowPtr() *time.Time {
	now := time.Now()
	return &now
}

// paramsFor builds the route parameters for the handler.
func paramsFor(key, value string) gin.Params {
	return gin.Params{{Key: key, Value: value}}
}

// decodeEstimate reads the estimate out of a response body.
func decodeEstimate(t *testing.T, body string) database.DevicePurgeEstimate {
	t.Helper()
	var envelope struct {
		Success bool                         `json:"success"`
		Data    database.DevicePurgeEstimate `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode the estimate: %v", err)
	}
	return envelope.Data
}
