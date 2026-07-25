package database

import (
	"testing"

	"firewall-mon/internal/models"
)

// GetProvisionedTunnelPairs is what lets the connection-map detector stop
// guessing who a tunnel connects. Peer attribution is otherwise derived from the
// tunnel's remote IP, which is structurally wrong for a dialup peer behind NAT —
// the responder observes the NAT gateway's address, so the tunnel gets
// attributed to whichever monitored device owns that public IP.

func mkTunnel(t *testing.T, d *Database, name, status string, a, b uint) {
	t.Helper()
	m := &models.IPSecTunnel{Name: name, Status: status, ADeviceID: a, BDeviceID: b}
	if err := d.CreateIPSecTunnel(m); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
}

// The state filter is the whole safety story: a tunnel whose config is NOT on
// the devices must not attribute anything, and one whose config may still be
// live must.
func TestGetProvisionedTunnelPairs_StateFilter(t *testing.T) {
	d := NewDatabaseForTesting(t)

	// Config definitively NOT on the devices.
	mkTunnel(t, d, "fwm-t1", "draft", 1, 2)
	mkTunnel(t, d, "fwm-t2", "rolled_back", 3, 4)
	// Config present or very likely present.
	live := []string{"up", "down", "degraded", "deploying", "rolling_back", "rollback_failed", "error"}
	for i, s := range live {
		mkTunnel(t, d, "fwm-live-"+s, s, uint(10+i), uint(50+i))
	}

	got, err := d.GetProvisionedTunnelPairs()
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if _, ok := got["fwm-t1"]; ok {
		t.Error("a draft tunnel has no config on any device and must not attribute a pair")
	}
	if _, ok := got["fwm-t2"]; ok {
		t.Error("a rolled_back tunnel has been removed from the devices and must not attribute a pair")
	}
	for _, s := range live {
		if _, ok := got["fwm-live-"+s]; !ok {
			t.Errorf("status %q may still have live config — it must attribute its recorded pair", s)
		}
	}
	// rollback_failed deserves an explicit callout: config is probably still on
	// the box, which is exactly when correct attribution matters most.
	if p, ok := got["fwm-live-rollback_failed"]; !ok || p.A == 0 {
		t.Error("rollback_failed must be included — its config is the most likely of all to still be live")
	}
}

// The map is keyed lowercase so the detector can match device-reported names
// without worrying about case.
func TestGetProvisionedTunnelPairs_KeyedLowercaseWithBothEndpoints(t *testing.T) {
	d := NewDatabaseForTesting(t)
	mkTunnel(t, d, "FWM-T9", "up", 7, 8)

	got, err := d.GetProvisionedTunnelPairs()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	p, ok := got["fwm-t9"]
	if !ok {
		t.Fatalf("want a lowercase key, got %v", got)
	}
	if p.A != 7 || p.B != 8 {
		t.Errorf("pair = %d/%d, want 7/8", p.A, p.B)
	}
	// The original casing is preserved for logging/diagnostics.
	if p.Name != "FWM-T9" {
		t.Errorf("Name = %q, want the stored casing", p.Name)
	}
}

// A tunnel missing an endpoint cannot attribute anything, and letting it through
// would produce a pair against device 0 — a row referencing a device that does
// not exist.
func TestGetProvisionedTunnelPairs_SkipsIncompleteEndpoints(t *testing.T) {
	d := NewDatabaseForTesting(t)
	mkTunnel(t, d, "fwm-noA", "up", 0, 5)
	mkTunnel(t, d, "fwm-noB", "up", 5, 0)

	got, err := d.GetProvisionedTunnelPairs()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a tunnel with an unresolved endpoint must be skipped; got %v", got)
	}
}
