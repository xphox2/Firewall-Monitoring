package logfields

// opnsenseExtractor is a registered STUB. OPNsense devices arrive shortly; when
// they do, implement Extract to parse the OPNsense filterlog CSV / structured
// syslog into matchable fields (rule/action/interface/proto/src/dst/…). Until
// then it behaves like the generic extractor (base fields only), so registering
// it now costs nothing and makes vendor="opnsense" a known, non-fallback vendor.
//
// TODO(opnsense): parse `filterlog` CSV payloads:
//
//	<PRI>... filterlog[pid]: rule,subrule,anchor,tracker,iface,reason,action,dir,ipver,...
type opnsenseExtractor struct{}

func init() { Register(opnsenseExtractor{}) }

func (opnsenseExtractor) Vendor() string { return "opnsense" }

func (opnsenseExtractor) Extract(raw string, dst map[string]string) {
	// STUB: no structured extraction yet.
}
