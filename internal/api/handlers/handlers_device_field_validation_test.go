package handlers

import (
	"net/http"
	"testing"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// TestPrepareDeviceUpdates_ValidatesPortsAndEnums pins M-5: ssh_port / api_port
// must be 1-65535, snmp_version an allow-listed enum, and ssh_poll_interval
// non-negative — a malformed value must be rejected, not persisted.
func TestPrepareDeviceUpdates_ValidatesPortsAndEnums(t *testing.T) {
	db := database.NewDatabaseForTesting(t)
	dev := &models.Device{Name: "fw", IPAddress: "192.0.2.1"}

	cases := []struct {
		name   string
		field  string
		value  interface{}
		wantOK bool
	}{
		{"ssh_port zero", "ssh_port", float64(0), false},
		{"ssh_port too high", "ssh_port", float64(70000), false},
		{"ssh_port valid", "ssh_port", float64(22), true},
		{"api_port negative", "api_port", float64(-1), false},
		{"api_port valid", "api_port", float64(443), true},
		{"snmp_version bad", "snmp_version", "2", false},
		{"snmp_version valid", "snmp_version", "2c", true},
		{"snmp_version v3 valid", "snmp_version", "3", true},
		{"ssh_poll_interval negative", "ssh_poll_interval", float64(-5), false},
		{"ssh_poll_interval valid", "ssh_poll_interval", float64(900), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := jsonReq(http.MethodPut, "/admin/api/devices/1", `{}`)
			c.Set("role", auth.RoleAdmin)
			_, ok := prepareDeviceUpdates(c, db, dev, map[string]interface{}{tc.field: tc.value})
			if ok != tc.wantOK {
				t.Errorf("ok=%v, want %v (status=%d)", ok, tc.wantOK, c.Writer.Status())
			}
		})
	}
}
