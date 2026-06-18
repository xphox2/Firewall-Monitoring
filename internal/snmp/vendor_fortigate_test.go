package snmp

import (
	"testing"

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

	byName := map[string]float64{}
	status := map[string]string{}
	for _, s := range f.ParseHardwareSensors(pdus) {
		byName[s.Name] = s.Value
		status[s.Name] = s.Status
	}
	if len(byName) != 2 {
		t.Fatalf("expected 2 sensors, got %d", len(byName))
	}

	if v := byName["CPU LM75 Temp"]; v != 52.5 {
		t.Errorf("temperature value = %v, want 52.5 (DisplayString must be parsed as float, not zeroed)", v)
	}
	if status["CPU LM75 Temp"] != "normal" {
		t.Errorf("temperature status = %q, want normal", status["CPU LM75 Temp"])
	}
	if v := byName["PS1 Fan 1"]; v != 11200 {
		t.Errorf("fan value = %v, want 11200", v)
	}
	if status["PS1 Fan 1"] != "alarm" {
		t.Errorf("fan status = %q, want alarm", status["PS1 Fan 1"])
	}
}
