package logfields

// pfsenseExtractor parses the pf `filterlog` CSV, identical to OPNsense's schema
// family (AUDIT-280) — both share extractFilterlog (see opnsense.go).
type pfsenseExtractor struct{}

func init() { Register(pfsenseExtractor{}) }

func (pfsenseExtractor) Vendor() string { return "pfsense" }

func (pfsenseExtractor) Extract(raw string, dst map[string]string) {
	extractFilterlog(raw, dst)
}
