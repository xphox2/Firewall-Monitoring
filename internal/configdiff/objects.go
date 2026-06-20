package configdiff

// ConfigObject is a single vendor-neutral configuration object extracted from a
// device config — a firewall policy, an address object, an interface, an admin,
// or a singleton settings block. It is the unit of the semantic (per-object)
// diff that augments the raw line diff for vendors that implement ObjectParser.
//
// Kind is the dotted section path (e.g. "firewall.policy", "system.interface",
// "system.global"). Name is the table-entry key (e.g. "12", "wan1"); it is empty
// for singleton sections that carry direct `set` lines instead of `edit` blocks.
// Path uniquely identifies the object for diffing: Kind for singletons, or
// Kind+"/"+Name for table entries.
type ConfigObject struct {
	Kind  string            `json:"kind"`
	Name  string            `json:"name"`
	Path  string            `json:"path"`
	Attrs map[string]string `json:"attrs"`
}

// ObjectParser is an optional capability a vendor Normalizer may implement to
// expose a structured object model of a config for semantic diffing. Vendors
// without it fall back to the line diff. Parsers should operate on already-
// normalized text (see DiffObjects) so volatile content (ENC blobs, IV drift,
// timestamps) never surfaces as a phantom attribute change.
type ObjectParser interface {
	ParseObjects(raw []byte) ([]ConfigObject, error)
}

// ParseObjects returns the object model for a config if the vendor's normalizer
// implements ObjectParser. ok is false when the vendor has no parser, in which
// case the caller should fall back to the line diff.
func ParseObjects(vendor string, raw []byte) (objs []ConfigObject, ok bool) {
	p, isParser := Lookup(vendor).(ObjectParser)
	if !isParser {
		return nil, false
	}
	out, err := p.ParseObjects(raw)
	if err != nil {
		return nil, false
	}
	return out, true
}

// HasObjectParser reports whether the vendor exposes a structured object model.
func HasObjectParser(vendor string) bool {
	_, ok := Lookup(vendor).(ObjectParser)
	return ok
}
