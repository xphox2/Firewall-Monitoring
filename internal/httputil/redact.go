package httputil

import "firewall-mon/internal/models"

// RedactDevice masks SNMP secrets on a single device.
func RedactDevice(d *models.Device) {
	if d.SNMPCommunity != "" {
		d.SNMPCommunity = "********"
	}
	d.SNMPV3AuthPass = ""
	d.SNMPV3PrivPass = ""
}

// RedactDevices masks SNMP secrets on a slice of devices.
func RedactDevices(devices []models.Device) {
	for i := range devices {
		RedactDevice(&devices[i])
	}
}

// RedactProbe masks sensitive paths on a single probe.
func RedactProbe(p *models.Probe) {
	p.TLSCertPath = "********"
	p.TLSKeyPath = "********"
	p.ServerTLSCert = "********"
}

// RedactProbes masks sensitive paths on a slice of probes.
func RedactProbes(probes []models.Probe) {
	for i := range probes {
		RedactProbe(&probes[i])
	}
}
