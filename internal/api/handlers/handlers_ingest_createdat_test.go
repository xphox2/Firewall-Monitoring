package handlers

import (
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestReceive_IgnoresClientCreatedAt: created_at is the server's ingest stamp
// of the three archived tables (the raw archive cuts syslog chunks by it and
// files every row under its ingest month), so a body-supplied value — past or
// future — must never be stored. The collector never sends the field.
func TestReceive_IgnoresClientCreatedAt(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)
	spoofs := []string{"2025-01-01T00:00:00Z", "2099-01-01T00:00:00Z"}
	cases := []struct {
		name  string
		path  string
		fn    gin.HandlerFunc
		model interface{}
		row   func(spoof string) map[string]interface{}
	}{
		{"syslog", "/syslog", h.ReceiveSyslogMessages, &models.SyslogMessage{}, func(s string) map[string]interface{} {
			return map[string]interface{}{"device_id": device.ID, "timestamp": time.Now().UTC(), "severity": 5,
				"hostname": "fw-example-01", "message": "srcip=192.0.2.10 dstip=198.51.100.7", "created_at": s}
		}},
		{"flow samples", "/flow-samples", h.ReceiveFlowSamples, &models.FlowSample{}, func(s string) map[string]interface{} {
			return map[string]interface{}{"device_id": device.ID, "timestamp": time.Now().UTC(),
				"src_addr": "192.0.2.10", "dst_addr": "198.51.100.7", "created_at": s}
		}},
		{"flow counters", "/flow-counters", h.ReceiveFlowCounterSamples, &models.FlowInterfaceCounter{}, func(s string) map[string]interface{} {
			return map[string]interface{}{"device_id": device.ID, "timestamp": time.Now().UTC(), "if_index": 3, "created_at": s}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := time.Now().Add(-time.Minute)
			var batch []map[string]interface{}
			for _, s := range spoofs {
				batch = append(batch, c.row(s))
			}
			w := doTestRequest(t, c.fn, "POST", c.path, probe.ID, probe.RegistrationKey, batch)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}
			var created []time.Time
			if err := db.Gorm().Model(c.model).Order("id").Pluck("created_at", &created).Error; err != nil {
				t.Fatal(err)
			}
			if len(created) != len(spoofs) {
				t.Fatalf("%d rows stored, want %d", len(created), len(spoofs))
			}
			for i, ts := range created {
				if ts.Before(before) || ts.After(time.Now().Add(time.Minute)) {
					t.Errorf("row %d: created_at %s — the client's %s was stored, not the server's stamp", i, ts.UTC().Format(time.RFC3339), spoofs[i])
				}
			}
		})
	}
}
