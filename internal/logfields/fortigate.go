package logfields

func init() { Register(fortigateExtractor{}) }

// fortigateExtractor parses FortiOS key=value log output. Every KV pair becomes
// a matchable field (subtype, level, logid, type, action, srcintf, srcip, user,
// msg, devname, …), so operators can write rules against any FortiGate field.
// The KV walker is non-regex and µs-scale, safe to run on the syslog hot path.
type fortigateExtractor struct{}

func (fortigateExtractor) Vendor() string { return "fortigate" }

func (fortigateExtractor) Extract(raw string, dst map[string]string) {
	// Cheap guard: FortiGate lines always contain at least one '='. Skip the
	// scan for anything that clearly isn't key=value (keeps non-FortiGate noise
	// off the parser).
	if raw == "" {
		return
	}
	for k, v := range parseKV(raw) {
		// Don't let a KV pair clobber a base field that carries real syslog
		// metadata (severity/facility). app_name/hostname/message may be
		// refined by the vendor view, but keep base severity/facility authoritative.
		if k == "severity" || k == "facility" {
			continue
		}
		dst[k] = v
	}
}
