package normalize

import "firewall-mon/internal/models"

func init() {
	Register(filterlogMapper{vendor: "opnsense"})
	Register(filterlogMapper{vendor: "pfsense"})
}

// filterlogMapper covers OPNsense and pfSense: the pf `filterlog` CSV for
// every packet-filter verdict (AUDIT-280) plus the free-text daemons both
// run (sshd, openvpn, charon). Per-packet logs carry no bytes, user, app or
// NAT — the capability profile says so rather than the mapper guessing.
type filterlogMapper struct{ vendor string }

func (m filterlogMapper) Vendor() string   { return m.vendor }
func (filterlogMapper) Families() []Family { return []Family{FamilyFilterlog, FamilyText} }

func (filterlogMapper) Map(tok Tokens, _ *models.SyslogMessage, ev *Event) Outcome {
	if tok.Family == FamilyText {
		return mapText(tok.TX, ev)
	}
	return mapFilterlog(tok.FL, ev)
}
