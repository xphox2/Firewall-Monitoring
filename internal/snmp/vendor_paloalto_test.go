package snmp

import (
	"testing"

	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// paSensorPDUs builds the five ENTITY-SENSOR-MIB varbinds for one sensor index.
func paSensorPDUs(idx, sensorType, status int) []gosnmp.SnmpPDU {
	suffix := "." + itoa(idx)
	return []gosnmp.SnmpPDU{
		{Name: paOIDSensorType + suffix, Type: gosnmp.Integer, Value: sensorType},
		{Name: paOIDSensorScale + suffix, Type: gosnmp.Integer, Value: 9}, // scale 9 = factor 1
		{Name: paOIDSensorPrecision + suffix, Type: gosnmp.Integer, Value: 0},
		{Name: paOIDSensorValue + suffix, Type: gosnmp.Integer, Value: 45},
		{Name: paOIDSensorStatus + suffix, Type: gosnmp.Integer, Value: status},
	}
}

// TestPaloAlto_ParseHardwareSensors_StatusAlarm is the AUDIT-302 regression:
// EntPhySensorOperStatus 3 (nonoperational) was dropped alongside 2
// (unavailable) BEFORE the alarm branch could run, so every emitted PA sensor
// was hardcoded "normal" and a failed sensor read as healthy/absent. The fix
// drops only status 2; status 3 must reach the "alarm" branch.
func TestPaloAlto_ParseHardwareSensors_StatusAlarm(t *testing.T) {
	p := &PaloAltoProfile{}

	var pdus []gosnmp.SnmpPDU
	pdus = append(pdus, paSensorPDUs(1, 8, 3)...) // temperature, nonoperational -> alarm
	pdus = append(pdus, paSensorPDUs(2, 8, 1)...) // temperature, ok           -> normal
	pdus = append(pdus, paSensorPDUs(3, 8, 2)...) // temperature, unavailable  -> dropped

	byStatus := map[int]models.HardwareSensor{}
	for _, s := range p.ParseHardwareSensors(pdus) {
		// Sensor names embed the index ("Temperature Sensor N").
		switch s.Name {
		case "Temperature Sensor 1":
			byStatus[1] = s
		case "Temperature Sensor 2":
			byStatus[2] = s
		case "Temperature Sensor 3":
			byStatus[3] = s
		}
	}

	alarm, ok := byStatus[1]
	if !ok {
		t.Fatal("nonoperational (status 3) sensor was dropped; it must be emitted with Status alarm (AUDIT-302)")
	}
	if alarm.Status != "alarm" {
		t.Errorf("status-3 sensor Status = %q, want alarm", alarm.Status)
	}

	normal, ok := byStatus[2]
	if !ok {
		t.Fatal("ok (status 1) sensor missing")
	}
	if normal.Status != "normal" {
		t.Errorf("status-1 sensor Status = %q, want normal", normal.Status)
	}

	if _, ok := byStatus[3]; ok {
		t.Error("unavailable (status 2) sensor must be dropped, but it was emitted")
	}
}
