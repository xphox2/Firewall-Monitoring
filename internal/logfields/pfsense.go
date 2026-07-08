package logfields

// pfsenseExtractor is a registered STUB (see opnsense.go for rationale). pfSense
// also emits `filterlog` CSV syslog, so its Extract will be near-identical to
// OPNsense's when implemented. Behaves like generic until then.
//
// TODO(pfsense): parse `filterlog` CSV payloads (same schema family as OPNsense).
type pfsenseExtractor struct{}

func init() { Register(pfsenseExtractor{}) }

func (pfsenseExtractor) Vendor() string { return "pfsense" }

func (pfsenseExtractor) Extract(raw string, dst map[string]string) {
	// STUB: no structured extraction yet.
}
