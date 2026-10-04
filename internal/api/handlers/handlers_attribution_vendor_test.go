package handlers

import (
	"net/http"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// Two PAN-OS-shaped configs that differ by one security rule, so the second
// delivery is a real change (insert-change) for a paloalto device.
const paloaltoRawA = `<config version="10.1.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<rulebase><security><rules>
<entry name="allow-lan"><action>allow</action><from><member>trust</member></from><to><member>untrust</member></to></entry>
</rules></security></rulebase></entry></vsys></entry></devices></config>`

const paloaltoRawB = `<config version="10.1.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<rulebase><security><rules>
<entry name="allow-lan"><action>allow</action><from><member>trust</member></from><to><member>untrust</member></to></entry>
<entry name="allow-guest"><action>allow</action><from><member>guest</member></from><to><member>untrust</member></to></entry>
</rules></security></rulebase></entry></vsys></entry></devices></config>`

// TestAttributeConfigChange_SkipsVendorsWithoutSyslogAudit: a config change
// on a Palo Alto device is NOT attributed from a stored syslog line that the
// FortiOS audit parser would happily read (`user=alice cfgpath=...`). Only a
// vendor implementing configdiff.SyslogAuditParser (FortiGate) is correlated;
// before 0.11.291 every vendor went through ParseFortiAuditEvent and this
// change came back attributed=true, changed_by=alice.
func TestAttributeConfigChange_SkipsVendorsWithoutSyslogAudit(t *testing.T) {
	h, probe, device := setupVendorProbeDevice(t, "paloalto")

	w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": paloaltoRawA,
		"checksum":    "raw-a",
		"length":      len(paloaltoRawA),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("baseline status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	// A line in the lookback window that is NOT a PAN-OS config audit event
	// but parses as one under the FortiOS key=value rules.
	line := &models.SyslogMessage{
		DeviceID:  device.ID,
		Timestamp: time.Now(),
		SourceIP:  "192.0.2.7",
		Message:   `user=alice cfgpath=firewall.policy action=edit`,
	}
	if err := h.db.Gorm().Create(line).Error; err != nil {
		t.Fatalf("create syslog: %v", err)
	}

	w = doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, probe.RegistrationKey, map[string]interface{}{
		"device_id":   device.ID,
		"config_text": paloaltoRawB,
		"checksum":    "raw-b",
		"length":      len(paloaltoRawB),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("change status = %d (body=%s), want 200", w.Code, w.Body.String())
	}

	var rev models.DeviceConfigRevision
	if err := h.db.Gorm().Where("device_id = ?", device.ID).Order("id DESC").First(&rev).Error; err != nil {
		t.Fatalf("load latest rev: %v", err)
	}
	if !rev.AttributionChecked {
		t.Fatal("AttributionChecked = false: the delivery was not treated as a real change (fixture no longer differs after normalization?)")
	}
	if rev.Attributed || rev.ChangedBy != "" || rev.ChangeMethod != "" {
		t.Errorf("paloalto change was attributed from FortiOS-shaped syslog: attributed=%v changed_by=%q method=%q, want unattributed", rev.Attributed, rev.ChangedBy, rev.ChangeMethod)
	}
}

// TestAttributeConfigChange_FortiGateStillAttributes guards the positive path
// through the new vendor-dispatched signature: a FortiGate device's stored
// audit event is found, the user / method come from the line and the source
// falls back to the row's SourceIP when the line carries none. The same line
// under a vendor without the capability yields nothing.
func TestAttributeConfigChange_FortiGateStillAttributes(t *testing.T) {
	h, db := setupTestHandler(t)
	dev := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.1", Vendor: "fortigate"}
	if err := db.Gorm().Create(dev).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, m := range []*models.SyslogMessage{
		// Newest first in the lookback: a traffic line that must be skipped.
		{DeviceID: dev.ID, Timestamp: now.Add(-time.Minute), SourceIP: "192.0.2.1",
			Message: `logid="0000000013" type="traffic" subtype="forward" action="deny" user="bob"`},
		{DeviceID: dev.ID, Timestamp: now.Add(-2 * time.Minute), SourceIP: "192.0.2.9",
			Message: `logid="0100044546" type="event" subtype="system" user="alice" ui="jsconsole" action="Edit" cfgpath="system.admin"`},
	} {
		if err := db.Gorm().Create(m).Error; err != nil {
			t.Fatal(err)
		}
	}

	att, found := h.attributeConfigChange("fortigate", dev.ID, now)
	if !found {
		t.Fatal("attributeConfigChange(fortigate) found nothing for a stored config-change audit event")
	}
	if att.User != "alice" {
		t.Errorf("User = %q, want alice (the traffic line's user=bob must not win)", att.User)
	}
	if att.Source != "192.0.2.9" {
		t.Errorf("Source = %q, want the row's SourceIP 192.0.2.9 (the line carries no srcip / ui address)", att.Source)
	}
	if att.Method == "" {
		t.Error("Method is empty, want the ui= method")
	}
	if att, found := h.attributeConfigChange("paloalto", dev.ID, now); found {
		t.Errorf("attributeConfigChange(paloalto) = %+v, found — a vendor without SyslogAuditParser must not correlate", att)
	}
}

// TestReceiveTrapEvents_NormalizesTrapType: a collector that classified the
// trap with the raw profile spelling (`ha-state-change`, collectors < 1.3.49)
// has it stored in the canonical alert-type form so the row matches the
// HA_STATE_CHANGE alert type and seed rule like a server-classified trap.
func TestReceiveTrapEvents_NormalizesTrapType(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	body := []map[string]interface{}{
		{"device_id": device.ID, "source_ip": device.IPAddress, "trap_oid": ".1.3.6.1.4.1.25461.2.1.3.2.0.801",
			"trap_type": "ha-state-change", "severity": "warning", "message": "ha-state-change: passive"},
		{"device_id": device.ID, "source_ip": device.IPAddress, "trap_oid": ".1.3.6.1.6.3.1.1.5.3",
			"trap_type": "LINK_DOWN", "severity": "warning", "message": "LINK_DOWN interface=port1"},
	}
	w := doTestRequest(t, h.ReceiveTrapEvents, "POST", "/traps", probe.ID, probe.RegistrationKey, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var traps []models.TrapEvent
	if err := db.Gorm().Where("device_id = ?", device.ID).Order("id ASC").Find(&traps).Error; err != nil {
		t.Fatal(err)
	}
	if len(traps) != 2 {
		t.Fatalf("stored %d traps, want 2", len(traps))
	}
	if got, want := traps[0].TrapType, string(models.AlertTypeHAStateChange); got != want {
		t.Errorf("stored trap_type = %q, want %q", got, want)
	}
	if traps[1].TrapType != "LINK_DOWN" {
		t.Errorf("already-canonical trap_type changed to %q", traps[1].TrapType)
	}
}
