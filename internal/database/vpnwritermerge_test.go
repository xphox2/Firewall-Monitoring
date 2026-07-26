package database

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// vpn_status has two writers with disjoint fields — the ~60s SNMP path reports
// status/counters/selectors, the ~15min SSH config path reports
// interface_name/mode with a placeholder status and no counters. Newest-row-wins
// discarded whichever had not fired most recently. These pin the merge.

func seedStateRow(t *testing.T, d *Database, dev uint, name, status string, ts time.Time) {
	t.Helper()
	if err := d.SaveVPNStatuses([]models.VPNStatus{{
		DeviceID: dev, TunnelName: name, TunnelType: "ipsec", Status: status,
		BytesIn: 1000, BytesOut: 2000, LocalSubnet: "192.168.5.0/24",
		Timestamp: ts,
	}}); err != nil {
		t.Fatalf("seed state row: %v", err)
	}
}

func seedConfigRow(t *testing.T, d *Database, dev uint, name string, ts time.Time) {
	t.Helper()
	if err := d.SaveVPNStatuses([]models.VPNStatus{{
		DeviceID: dev, TunnelName: name, TunnelType: "ipsec", Status: "unknown",
		InterfaceName: `"WAN"`, Mode: "aggressive", Timestamp: ts,
	}}); err != nil {
		t.Fatalf("seed config row: %v", err)
	}
}

func onlyTunnel(t *testing.T, rows []models.VPNStatus, name string) models.VPNStatus {
	t.Helper()
	var found []models.VPNStatus
	for _, r := range rows {
		if r.TunnelName == name {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly 1 row for %q, got %d — the two writers were not merged", name, len(found))
	}
	return found[0]
}

// The headline case, and the one no single row in the table can satisfy: the
// config row is NEWER, so before the merge it won the selection outright and the
// badge read "unknown" with zero counters.
func TestVPNWriterMerge_StateSurvivesANewerConfigRow(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	seedStateRow(t, d, 1, "DMZ", "down", now.Add(-90*time.Second))
	seedConfigRow(t, d, 1, "DMZ", now.Add(-30*time.Second)) // newer

	rows, err := d.GetLatestVPNStatuses(1)
	if err != nil {
		t.Fatalf("GetLatestVPNStatuses: %v", err)
	}
	got := onlyTunnel(t, rows, "DMZ")

	if got.Status != "down" {
		t.Errorf("status = %q, want \"down\" — a config row has no liveness to report "+
			"and must never displace a state observation", got.Status)
	}
	if got.BytesIn == 0 {
		t.Error("counters lost; the base must be the state row, not a blend")
	}
	if got.InterfaceName != "WAN" || got.Mode != "aggressive" {
		t.Errorf("interface/mode = %q/%q, want \"WAN\"/\"aggressive\" — the config row's "+
			"metadata is the whole reason it is kept", got.InterfaceName, got.Mode)
	}
}

// The merged row must carry the STATE row's timestamp. Borrowing the config
// row's fresher one would let a tunnel whose SNMP feed had died keep looking
// live on the strength of a poll that knows nothing about liveness.
func TestVPNWriterMerge_KeepsTheStateRowsTimestamp(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	stateAt := now.Add(-40 * time.Minute) // past VPNEvidenceFresh, inside grace
	seedStateRow(t, d, 1, "DMZ", "up", stateAt)
	seedConfigRow(t, d, 1, "DMZ", now.Add(-1*time.Minute))

	rows, err := d.GetLatestVPNStatuses(1)
	if err != nil {
		t.Fatalf("GetLatestVPNStatuses: %v", err)
	}
	got := onlyTunnel(t, rows, "DMZ")

	if now.Sub(got.Timestamp) <= VPNEvidenceFresh {
		t.Fatalf("merged row is %v old, which reads as FRESH — it inherited the config "+
			"row's timestamp, so a dead SNMP feed would look live", now.Sub(got.Timestamp))
	}
}

// A device whose only writer is the SSH config path (SNMP-restricted) must keep
// working exactly as before.
func TestVPNWriterMerge_ConfigOnlyTunnelIsUnchanged(t *testing.T) {
	d := NewDatabaseForTesting(t)
	seedConfigRow(t, d, 1, "SSH-ONLY", time.Now().Add(-2*time.Minute))

	rows, err := d.GetLatestVPNStatuses(1)
	if err != nil {
		t.Fatalf("GetLatestVPNStatuses: %v", err)
	}
	got := onlyTunnel(t, rows, "SSH-ONLY")
	if got.Status != "unknown" {
		t.Errorf("status = %q, want \"unknown\" — with no state row the config row IS the "+
			"base, and inventing a status for it would make it alert-eligible", got.Status)
	}
	if got.InterfaceName != "WAN" {
		t.Errorf("interface = %q, want \"WAN\"", got.InterfaceName)
	}
}

// THE TRAP. The SQL prune (grace + 24h slack) is far wider than the authoritative
// grace horizon applied in Go. A state row aged between the two is RETURNED by
// the query — so a fallback keyed on "absent from the state subquery" would not
// fire — and is then dropped by the grace filter, leaving nothing at all.
//
// Failure mode if this regresses: a device whose SNMP feed died yesterday but
// whose SSH poll is alive loses every tunnel from the UI. That is strictly worse
// than the bug this merge fixes.
func TestVPNWriterMerge_AgedStateRowFallsBackInsteadOfVanishing(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	// Between VPNEvidenceGrace (3h) and the SQL prune (grace + 24h slack).
	seedStateRow(t, d, 1, "DMZ", "up", now.Add(-VPNEvidenceGrace-2*time.Hour))
	seedConfigRow(t, d, 1, "DMZ", now.Add(-2*time.Minute))

	rows, err := d.GetLatestVPNStatuses(1)
	if err != nil {
		t.Fatalf("GetLatestVPNStatuses: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the tunnel VANISHED — the aged state row suppressed the fallback and was " +
			"then grace-filtered away. Merge must run AFTER withinVPNGrace")
	}
	got := onlyTunnel(t, rows, "DMZ")
	if got.Status != "unknown" {
		t.Errorf("status = %q, want \"unknown\" — the only surviving row is the config row, "+
			"and an out-of-grace state claim must not be resurrected", got.Status)
	}
}

// The fleet-wide reader feeds both the map and the alert engine; it must merge
// identically or the two disagree about the same tunnel.
func TestVPNWriterMerge_AppliesToTheFleetWideReaderToo(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	seedStateRow(t, d, 1, "DMZ", "down", now.Add(-90*time.Second))
	seedConfigRow(t, d, 1, "DMZ", now.Add(-30*time.Second))

	rows, err := d.GetAllLatestVPNStatuses()
	if err != nil {
		t.Fatalf("GetAllLatestVPNStatuses: %v", err)
	}
	got := onlyTunnel(t, rows, "DMZ")
	if got.Status != "down" || got.InterfaceName != "WAN" {
		t.Errorf("fleet reader gave status=%q iface=%q, want \"down\"/\"WAN\" — it must not "+
			"diverge from the per-device reader that renders the same page", got.Status, got.InterfaceName)
	}
}

// Two writers must not become two tunnels. The subquery now returns the newest
// row of EACH class, so counting rows directly doubles every dual-writer tunnel.
func TestVPNWriterMerge_CountsADualWriterTunnelOnce(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	seedStateRow(t, d, 1, "DMZ", "up", now.Add(-90*time.Second))
	seedConfigRow(t, d, 1, "DMZ", now.Add(-30*time.Second))

	up, total, err := d.GetVPNTunnelCounts(1)
	if err != nil {
		t.Fatalf("GetVPNTunnelCounts: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1 — the two writers of ONE tunnel were counted separately", total)
	}
	if up != 1 {
		t.Errorf("up = %d, want 1 — the badge must agree with the page, which now reads \"up\"", up)
	}
}

// FortiOS quotes config values, and the SSH parser captures the token verbatim,
// so every device in the fleet stores `"wan1"` rather than wan1. Making Interface
// visible ~94% more often makes that wart visible too.
func TestVPNWriterMerge_StripsFortiOSConfigQuotes(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	seedStateRow(t, d, 1, "DMZ", "down", now.Add(-90*time.Second))
	seedConfigRow(t, d, 1, "DMZ", now.Add(-30*time.Second))

	rows, err := d.GetLatestVPNStatuses(1)
	if err != nil {
		t.Fatalf("GetLatestVPNStatuses: %v", err)
	}
	got := onlyTunnel(t, rows, "DMZ")
	if got.InterfaceName != "WAN" {
		t.Errorf("interface = %q, want \"WAN\" — FortiOS quoting is syntax, not part of "+
			"the interface name, and it reaches the UI verbatim today", got.InterfaceName)
	}
}

// GetVPNTunnelCounts selects only (tunnel_name, status, timestamp), so DeviceID
// is zero on every row it merges. The merge key is (device, name) — with the
// device half constant, the NAME half has to carry the whole discrimination or
// every tunnel on the device collapses into one.
//
// The single-tunnel count test cannot see this: one tunnel collapses to one
// tunnel either way.
func TestVPNWriterMerge_CountsDoNotCollapseDistinctTunnels(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	for _, name := range []string{"DMZ", "HUB", "NUDAY_LAN"} {
		seedStateRow(t, d, 1, name, "up", now.Add(-90*time.Second))
		seedConfigRow(t, d, 1, name, now.Add(-30*time.Second))
	}

	up, total, err := d.GetVPNTunnelCounts(1)
	if err != nil {
		t.Fatalf("GetVPNTunnelCounts: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3 — three distinct tunnels, each with two writers; "+
			"neither collapsed together nor counted twice", total)
	}
	if up != 3 {
		t.Errorf("up = %d, want 3", up)
	}
}

// The merge is keyed per DEVICE as well as per name. Two devices commonly run
// tunnels with the same name (DMZ, HUB and NUDAY_LAN all appear on more than one
// firewall in a hub-and-spoke), and the fleet-wide reader sees them together.
func TestVPNWriterMerge_SameTunnelNameOnTwoDevicesStaysSeparate(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	seedStateRow(t, d, 1, "DMZ", "up", now.Add(-90*time.Second))
	seedConfigRow(t, d, 1, "DMZ", now.Add(-30*time.Second))
	seedStateRow(t, d, 2, "DMZ", "down", now.Add(-90*time.Second))
	seedConfigRow(t, d, 2, "DMZ", now.Add(-30*time.Second))

	rows, err := d.GetAllLatestVPNStatuses()
	if err != nil {
		t.Fatalf("GetAllLatestVPNStatuses: %v", err)
	}
	byDevice := map[uint]string{}
	for _, r := range rows {
		if r.TunnelName != "DMZ" {
			continue
		}
		if prev, dup := byDevice[r.DeviceID]; dup {
			t.Fatalf("device %d has two DMZ rows (%q and %q) — not merged", r.DeviceID, prev, r.Status)
		}
		byDevice[r.DeviceID] = r.Status
	}
	if len(byDevice) != 2 {
		t.Fatalf("want DMZ on 2 devices, got %d — one device's tunnel absorbed the other's", len(byDevice))
	}
	if byDevice[1] != "up" || byDevice[2] != "down" {
		t.Errorf("statuses = dev1:%q dev2:%q, want up/down — the two devices' rows were "+
			"merged into one another", byDevice[1], byDevice[2])
	}
}
