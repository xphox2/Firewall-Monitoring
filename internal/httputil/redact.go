package httputil

import "firewall-mon/internal/models"

// RedactedMask is the placeholder the API substitutes for secret values in GET
// responses. Write handlers MUST treat an incoming field equal to this mask as
// "unchanged" and never persist it — otherwise a client that GETs a redacted
// record and saves it back destroys the real secret. That is exactly the bug
// that overwrote a device's SNMP community with "********" and silently broke
// SNMP polling for that device.
const RedactedMask = "********"

// RedactDevice masks credential secrets on a single device. The SSH password is
// admin-level credential material and MUST be masked here like the SNMP secrets
// — before this it was returned in plaintext on every device GET. The plaintext
// is available only through the dedicated, re-authenticated, audit-logged
// reveal endpoint (RevealDeviceSecret). The write path already treats an
// incoming value equal to RedactedMask as "unchanged", so masking here is safe
// for round-trip saves.
func RedactDevice(d *models.Device) {
	if d.SNMPCommunity != "" {
		d.SNMPCommunity = RedactedMask
	}
	if d.SNMPV3AuthPass != "" {
		d.SNMPV3AuthPass = RedactedMask
	}
	if d.SNMPV3PrivPass != "" {
		d.SNMPV3PrivPass = RedactedMask
	}
	if d.SSHPassword != "" {
		d.SSHPassword = RedactedMask
	}
}

// RedactDevices masks SNMP secrets on a slice of devices.
func RedactDevices(devices []models.Device) {
	for i := range devices {
		RedactDevice(&devices[i])
	}
}

// RedactProbe masks sensitive paths on a single probe.
func RedactProbe(p *models.Probe) {
	p.TLSCertPath = RedactedMask
	p.TLSKeyPath = RedactedMask
	p.ServerTLSCert = RedactedMask
	if p.RegistrationKey != "" {
		p.RegistrationKey = RedactedMask
	}
}

// RedactProbes masks sensitive paths on a slice of probes.
func RedactProbes(probes []models.Probe) {
	for i := range probes {
		RedactProbe(&probes[i])
	}
}

// RedactIRCChannel masks channel secrets (key, ChanServ/oper passwords) on a
// single channel. Values are stored encrypted at rest; GET responses must show
// the mask, never the plaintext (or the ciphertext).
func RedactIRCChannel(ch *models.IRCChannel) {
	if ch.ChannelKey != "" {
		ch.ChannelKey = RedactedMask
	}
	if ch.ChanServPass != "" {
		ch.ChanServPass = RedactedMask
	}
	if ch.ChanOperPass != "" {
		ch.ChanOperPass = RedactedMask
	}
}

// RedactIRCServer masks server secrets (server/NickServ/SASL passwords) and the
// secrets of any preloaded channels.
func RedactIRCServer(s *models.IRCServer) {
	if s.ServerPassword != "" {
		s.ServerPassword = RedactedMask
	}
	if s.NickServPassword != "" {
		s.NickServPassword = RedactedMask
	}
	if s.SASLPassword != "" {
		s.SASLPassword = RedactedMask
	}
	for i := range s.Channels {
		RedactIRCChannel(&s.Channels[i])
	}
}

// RedactIRCServers masks secrets on a slice of servers (and their channels).
func RedactIRCServers(servers []models.IRCServer) {
	for i := range servers {
		RedactIRCServer(&servers[i])
	}
}
