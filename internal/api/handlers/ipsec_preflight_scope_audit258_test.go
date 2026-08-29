package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestPreflight_TunnelScoped_AUDIT258 proves preflight results are read by the
// per-end command ID recorded on the tunnel (tunnel-scoped), not by device+type.
// Two tunnels share one hub device (end A); pre-fix, both polls returned the
// device's LATEST preflight command — so tunnel 1's poll surfaced tunnel 2's
// collision report (and vice versa).
func TestPreflight_TunnelScoped_AUDIT258(t *testing.T) {
	h, db := setupTestHandler(t)
	if sqlDB, err := db.Gorm().DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	probe, _ := setupProbeAndDevice(t, db)
	shared := makeFortiDevice(t, db, probe.ID, "203.0.113.50") // end A of BOTH tunnels
	b1 := makeFortiDevice(t, db, probe.ID, "203.0.113.51")
	b2 := makeFortiDevice(t, db, probe.ID, "203.0.113.52")

	t1 := createTunnelRow(t, db, "fortigate", "fortigate", shared.ID, b1.ID, 1)
	t2 := createTunnelRow(t, db, "fortigate", "fortigate", shared.ID, b2.ID, 1)

	preflight := func(id uint) {
		c, rec := jsonReq(http.MethodPost, "/x", "")
		c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
		h.PreflightIPSecTunnel(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("preflight tunnel %d = %d: %s", id, rec.Code, rec.Body.String())
		}
	}
	preflight(t1)
	preflight(t2)

	// Stamp an identifiable succeeded result on each tunnel's END-A (shared device)
	// preflight command, read from the tunnel's persisted preflight state.
	setEndAResult := func(tunnelID uint, marker string) {
		row, err := db.GetIPSecTunnel(tunnelID)
		if err != nil {
			t.Fatalf("get tunnel %d: %v", tunnelID, err)
		}
		st, err := parsePreflightState(row)
		if err != nil || st == nil {
			t.Fatalf("tunnel %d has no persisted preflight state (err=%v) — AUDIT-258 fix not recording command IDs", tunnelID, err)
		}
		var cmdID string
		for _, e := range st.Ends {
			if e.End == 0 {
				cmdID = e.CommandID
			}
		}
		if cmdID == "" {
			t.Fatalf("tunnel %d recorded no end-A command id", tunnelID)
		}
		if err := db.Gorm().Model(&models.ProbeCommand{}).Where("command_id = ?", cmdID).
			Updates(map[string]interface{}{"result": `{"marker":"` + marker + `"}`, "status": "succeeded"}).Error; err != nil {
			t.Fatalf("stamp result: %v", err)
		}
	}
	setEndAResult(t1, "tunnel-one")
	setEndAResult(t2, "tunnel-two")

	poll := func(id uint) string {
		c, rec := jsonReq(http.MethodGet, "/x", "")
		c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
		h.GetIPSecPreflightResult(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("poll tunnel %d = %d: %s", id, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	b1body := poll(t1)
	if !strings.Contains(b1body, "tunnel-one") {
		t.Errorf("tunnel 1 poll is missing its OWN report: %s", b1body)
	}
	if strings.Contains(b1body, "tunnel-two") {
		t.Errorf("tunnel 1 poll cross-contaminated with tunnel 2's report: %s", b1body)
	}

	b2body := poll(t2)
	if !strings.Contains(b2body, "tunnel-two") {
		t.Errorf("tunnel 2 poll is missing its OWN report: %s", b2body)
	}
	if strings.Contains(b2body, "tunnel-one") {
		t.Errorf("tunnel 2 poll cross-contaminated with tunnel 1's report: %s", b2body)
	}

	// Review hardening (AUDIT-258 finding 1): reassigning a tunnel's end-A device
	// after a preflight must NOT attribute the old device's stale report (or
	// advisories derived against the new intent) to the new device. UpdateIPSecTunnel
	// does not clear preflight_json, so the poll must reject a recorded end whose
	// device no longer matches. Swap tunnel 1's end A to a fresh device and re-poll.
	swapped := makeFortiDevice(t, db, probe.ID, "203.0.113.60")
	row, err := db.GetIPSecTunnel(t1)
	if err != nil {
		t.Fatalf("get tunnel 1: %v", err)
	}
	row.ADeviceID = swapped.ID
	if err := db.UpdateIPSecTunnel(row); err != nil {
		t.Fatalf("swap end-A device: %v", err)
	}
	swappedBody := poll(t1)
	if strings.Contains(swappedBody, "tunnel-one") {
		t.Errorf("tunnel 1 poll still surfaced the stale report of its FORMER end-A device after a device swap: %s", swappedBody)
	}
}
