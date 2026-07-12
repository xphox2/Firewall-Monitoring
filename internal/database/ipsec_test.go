package database

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"
)

func sampleIntent() *ipsec.TunnelIntent {
	m, _ := ipsec.PresetByName(ipsec.ProfileModern)
	return &ipsec.TunnelIntent{
		Name: "fwm-t1", Enabled: true, IKEVersion: m.IKEVersion, Mode: ipsec.ModeRouteBased,
		IKE: m.IKE, ESP: m.ESP, IKELifetimeSecs: m.IKELifetimeSecs, PSK: "s3cretPSKvalue012345",
		VTISubnet: "169.254.1.4/30",
		Ends: [2]ipsec.EndpointSpec{
			{DeviceID: 10, Vendor: "fortigate", PeerIP: "203.0.113.1", ProtectedSubnets: []string{"10.0.0.0/24"}},
			{DeviceID: 20, Vendor: "opnsense", PeerIP: "198.51.100.1", ProtectedSubnets: []string{"192.168.50.0/24"}},
		},
	}
}

func TestIPSecTunnel_CRUDRoundTrip(t *testing.T) {
	d := NewDatabaseForTesting(t)
	// Configure an encryption key so the PSK is actually encrypted at rest
	// (without a key, EncryptField is an identity no-op).
	d.encKeys = keyChain{current: deriveKey("ipsec-test-encryption-key-32bytes!!")}

	in := sampleIntent()
	m, err := IPSecIntentToModel(in)
	if err != nil {
		t.Fatalf("to model: %v", err)
	}
	// The PSK must NOT be embedded in the serialized intent blob.
	if strings.Contains(m.IntentJSON, in.PSK) {
		t.Fatal("PSK leaked into IntentJSON")
	}
	if m.ADeviceID != 10 || m.BVendor != "opnsense" {
		t.Fatalf("promoted columns wrong: %+v", m)
	}

	if err := d.CreateIPSecTunnel(m); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Stored PSK is encrypted at rest.
	var raw models.IPSecTunnel
	d.Gorm().First(&raw, m.ID)
	if raw.PSK == in.PSK || !strings.HasPrefix(raw.PSK, "{enc}") {
		t.Fatalf("PSK not encrypted at rest: %q", raw.PSK)
	}

	// Get decrypts the PSK and the intent round-trips.
	got, err := d.GetIPSecTunnel(m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PSK != in.PSK {
		t.Errorf("PSK round-trip: got %q want %q", got.PSK, in.PSK)
	}
	intent, err := IPSecModelToIntent(got)
	if err != nil {
		t.Fatalf("to intent: %v", err)
	}
	if intent.PSK != in.PSK || intent.IKE.Enc != in.IKE.Enc || intent.Ends[1].Vendor != "opnsense" {
		t.Errorf("intent round-trip mismatch: %+v", intent)
	}

	// List never exposes the PSK (not even ciphertext).
	list, err := d.ListIPSecTunnels()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v n=%d", err, len(list))
	}
	if list[0].PSK != "" {
		t.Errorf("list leaked PSK: %q", list[0].PSK)
	}

	// Update with the mask leaves the stored PSK unchanged.
	m.PSK = redactedMask
	m.Status = "up"
	if err := d.UpdateIPSecTunnel(m); err != nil {
		t.Fatalf("update: %v", err)
	}
	after, _ := d.GetIPSecTunnel(m.ID)
	if after.PSK != in.PSK {
		t.Errorf("masked update clobbered PSK: got %q", after.PSK)
	}
	if after.Status != "up" {
		t.Errorf("status not updated: %q", after.Status)
	}

	if err := d.DeleteIPSecTunnel(m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := d.GetIPSecTunnel(m.ID); err == nil {
		t.Error("expected error getting a deleted tunnel")
	}
}
