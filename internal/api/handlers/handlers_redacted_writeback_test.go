package handlers

import (
	"net/http"
	"testing"

	"firewall-mon/internal/models"
)

// TestUpdateDevice_RedactedCommunityNotWrittenBack is the regression for the
// production outage where a probe-monitored FortiGate stopped answering SNMP.
//
// Root cause: GET /api/devices/:id masks SNMP secrets as "********"
// (httputil.RedactedMask). The admin UI loads a device with that mask in the
// community field; saving the device back resent {"snmp_community":"********"}.
// The UpdateDevice handler encrypted-and-stored whatever came in, so the mask
// OVERWROTE the real community. The collector then fetched "********" and polled
// the firewall with it — every request silently timed out (the FortiGate drops
// an unknown community), and the device flipped offline while its sibling, which
// had never been edited, kept working.
//
// The fix: the write path treats an incoming value equal to RedactedMask (or
// empty) as "unchanged" and never persists it. This test edits an unrelated
// field while resending the mask, and asserts the stored secret survives.
func TestUpdateDevice_RedactedCommunityNotWrittenBack(t *testing.T) {
	h, db := setupTestHandler(t)

	const realCommunity = "s3cr3t-snmp-comm"
	dev := &models.Device{
		Name:          "fw-edge",
		IPAddress:     "192.168.5.1",
		SNMPVersion:   "2c",
		SNMPCommunity: db.EncryptField(realCommunity),
		Enabled:       true,
	}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	storedBefore := dev.SNMPCommunity

	// Simulate the admin UI round-trip: change only the name, but resend the
	// masked community exactly as the GET handler returned it.
	w := doPartialUpdateRequest(t, h.UpdateDevice, "/api/devices/:id", dev.ID,
		map[string]interface{}{
			"name":           "fw-edge-renamed",
			"snmp_community": "********",
		})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	// Reload the RAW row (no decryption).
	var after models.Device
	if err := db.Gorm().First(&after, dev.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}

	// The genuine edit must apply.
	if after.Name != "fw-edge-renamed" {
		t.Errorf("name = %q, want fw-edge-renamed (the real edit must still apply)", after.Name)
	}
	// The masked community must NOT have been persisted over the real secret.
	if after.SNMPCommunity != storedBefore {
		t.Errorf("SNMP community overwritten by the '********' mask:\n got      %q\n want unchanged %q", after.SNMPCommunity, storedBefore)
	}
	if got := db.DecryptField(after.SNMPCommunity); got != realCommunity {
		t.Errorf("decrypted community = %q, want %q (the real secret must survive a redacted save)", got, realCommunity)
	}
}

// TestUpdateDevice_RealCommunityStillUpdates is the companion guard: a genuine
// new community (not the mask) must still be encrypted and stored, so the guard
// doesn't accidentally make the field read-only.
func TestUpdateDevice_RealCommunityStillUpdates(t *testing.T) {
	h, db := setupTestHandler(t)

	dev := &models.Device{
		Name:          "fw-edge",
		IPAddress:     "192.168.5.2",
		SNMPVersion:   "2c",
		SNMPCommunity: db.EncryptField("old-comm"),
		Enabled:       true,
	}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}

	w := doPartialUpdateRequest(t, h.UpdateDevice, "/api/devices/:id", dev.ID,
		map[string]interface{}{"snmp_community": "brand-new-comm"})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	var after models.Device
	if err := db.Gorm().First(&after, dev.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := db.DecryptField(after.SNMPCommunity); got != "brand-new-comm" {
		t.Errorf("a real community update was dropped: decrypted = %q, want brand-new-comm", got)
	}
}
