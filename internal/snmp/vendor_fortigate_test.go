package snmp

import (
	"testing"

	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// TestFortiGate_ParseHardwareSensors_DisplayStringValue is a regression for the
// bug where every FortiGate temperature/voltage reading showed 0.0 on the
// device page: fgHwSensorEntValue is a DisplayString (gosnmp delivers it as
// []byte) like "52.500000", but the parser used gosnmp.ToBigInt, which returns
// 0 for a []byte AND for any non-integer numeric string. The value must be
// parsed as a float.
func TestFortiGate_ParseHardwareSensors_DisplayStringValue(t *testing.T) {
	f := &FortiGateProfile{}
	pdus := []gosnmp.SnmpPDU{
		{Name: fgOIDHWSensorName + ".1", Type: gosnmp.OctetString, Value: []byte("CPU LM75 Temp")},
		{Name: fgOIDHWSensorValue + ".1", Type: gosnmp.OctetString, Value: []byte("52.500000")},
		{Name: fgOIDHWSensorAlarm + ".1", Type: gosnmp.Integer, Value: 0},
		{Name: fgOIDHWSensorName + ".2", Type: gosnmp.OctetString, Value: []byte("PS1 Fan 1")},
		{Name: fgOIDHWSensorValue + ".2", Type: gosnmp.OctetString, Value: []byte("11200")},
		{Name: fgOIDHWSensorAlarm + ".2", Type: gosnmp.Integer, Value: 1},
	}

	byName := map[string]models.HardwareSensor{}
	for _, s := range f.ParseHardwareSensors(pdus) {
		byName[s.Name] = s
	}
	if len(byName) != 2 {
		t.Fatalf("expected 2 sensors, got %d", len(byName))
	}

	temp := byName["CPU LM75 Temp"]
	if temp.Value != 52.5 {
		t.Errorf("temperature value = %v, want 52.5 (DisplayString must be parsed as float, not zeroed)", temp.Value)
	}
	if temp.Status != "normal" {
		t.Errorf("temperature status = %q, want normal", temp.Status)
	}
	// inferSensorUnit must populate Type/Unit from the sensor name (parity with
	// the collector) — the table itself carries no unit column.
	if temp.Type != "temperature" || temp.Unit != "°C" {
		t.Errorf("temperature type/unit = %q/%q, want temperature/°C", temp.Type, temp.Unit)
	}

	fan := byName["PS1 Fan 1"]
	if fan.Value != 11200 {
		t.Errorf("fan value = %v, want 11200", fan.Value)
	}
	if fan.Status != "alarm" {
		t.Errorf("fan status = %q, want alarm", fan.Status)
	}
	if fan.Type != "fan" || fan.Unit != "RPM" {
		t.Errorf("fan type/unit = %q/%q, want fan/RPM", fan.Type, fan.Unit)
	}
}
