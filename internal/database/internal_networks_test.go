package database

import (
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func TestParseInternalNetworks(t *testing.T) {
	got, bad := ParseInternalNetworks("66.179.9.144/28\n66.9.166.120, 2001:db8::/32  66.179.9.150/28\n::ffff:198.51.100.0/120\n0.0.0.0/0\n::/0\nnope\n10.0.0.0/33\nfe80::1%eth0")
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if want := "66.179.9.144/28 66.9.166.120/32 2001:db8::/32 198.51.100.0/24"; strings.Join(s, " ") != want {
		t.Errorf("parsed %q, want %q (canonical, masked, de-duplicated, mapped prefix unmapped)", strings.Join(s, " "), want)
	}
	if len(bad) != 5 {
		t.Errorf("rejected %v, want the two catch-alls, the word, the /33 and the zoned address", bad)
	}
	for _, b := range bad[:2] {
		if !strings.Contains(b, "covers every address") {
			t.Errorf("catch-all rejection %q does not say why", b)
		}
	}
	if CanonicalInternalNetworks(got) != "66.179.9.144/28\n66.9.166.120/32\n2001:db8::/32\n198.51.100.0/24" {
		t.Errorf("canonical form = %q", CanonicalInternalNetworks(got))
	}
}

// TestLoadInternalNetworks pins what counts as the operator's own: the latest
// interface snapshot of ACTIVE devices (each address, plus its subnet unless it
// is a /30–/32 provider link), device management addresses, and the manual
// list — never private ranges (always internal anyway), stale snapshots or
// retired devices.
func TestLoadInternalNetworks(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now()
	fw := models.Device{Name: "nuday-fw", IPAddress: "66.179.9.155"}
	gone := models.Device{Name: "old-fw", IPAddress: "203.0.113.50"}
	named := models.Device{Name: "by-name", IPAddress: "fw.example.net"}
	for _, dev := range []*models.Device{&fw, &gone, &named} {
		if err := d.Gorm().Create(dev).Error; err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}
	retired := now
	if err := d.Gorm().Model(&models.Device{}).Where("id = ?", gone.ID).Update("retired_at", &retired).Error; err != nil {
		t.Fatalf("retire: %v", err)
	}
	addrs := []models.InterfaceAddress{
		{DeviceID: fw.ID, IPAddress: "66.179.9.156", NetMask: "255.255.255.240", Timestamp: now},                         // /28 LAN
		{DeviceID: fw.ID, IPAddress: "76.66.145.146", NetMask: "255.255.255.252", Timestamp: now},                        // /30 WAN link
		{DeviceID: fw.ID, IPAddress: "192.168.5.1", NetMask: "255.255.255.0", Timestamp: now},                            // private
		{DeviceID: fw.ID, IPAddress: "198.51.100.9", NetMask: "255.255.255.0", Timestamp: now.Add(-18 * 24 * time.Hour)}, // stale
		{DeviceID: gone.ID, IPAddress: "203.0.113.51", NetMask: "255.255.255.0", Timestamp: now},                         // retired device
		{DeviceID: fw.ID, IPAddress: "198.18.0.1", NetMask: "0.0.0.0", Timestamp: now},                                   // bogus mask: never a /0
	}
	if err := d.Gorm().Create(&addrs).Error; err != nil {
		t.Fatalf("seed addresses: %v", err)
	}
	if err := d.Gorm().Create(&models.SystemSetting{Key: FlowInternalNetworksKey, Value: "66.9.166.120\n2001:db8::/32\n192.168.0.0/13\n10.1.0.0/16"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	nets, err := d.LoadInternalNetworks()
	if err != nil {
		t.Fatalf("LoadInternalNetworks: %v", err)
	}
	got := map[string]string{}
	for _, n := range nets {
		got[n.CIDR] = n.Source + "/" + n.Device
	}
	want := map[string]string{
		"66.9.166.120/32": "manual/",
		"2001:db8::/32":   "manual/",
		// Starts inside 192.168/16 but reaches 192.175.255.255: kept.
		"192.168.0.0/13": "manual/",
		// The bogus-mask interface's own address is listed; its "subnet" is not.
		"198.18.0.1/32":    "interface/nuday-fw",
		"66.179.9.156/32":  "interface/nuday-fw",
		"66.179.9.144/28":  "subnet/nuday-fw",
		"76.66.145.146/32": "interface/nuday-fw",
		"66.179.9.155/32":  "management/nuday-fw",
	}
	for cidr, src := range want {
		if got[cidr] != src {
			t.Errorf("%s: got %q, want %q", cidr, got[cidr], src)
		}
	}
	for cidr := range got {
		if _, ok := want[cidr]; !ok {
			t.Errorf("unexpected entry %s (%s): stale snapshots, retired devices, /30 links and private ranges must not appear", cidr, got[cidr])
		}
	}

	// Auto off: only the manual list.
	if err := d.Gorm().Create(&models.SystemSetting{Key: FlowInternalAutoKey, Value: "false"}).Error; err != nil {
		t.Fatalf("seed auto: %v", err)
	}
	nets, err = d.LoadInternalNetworks()
	// 10.1.0.0/16 lies wholly inside 10/8 and is always internal: not listed.
	if err != nil || len(nets) != 3 {
		t.Errorf("with auto off: %v %v, want only the three manual entries not already private", nets, err)
	}
}
