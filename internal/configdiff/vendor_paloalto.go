package configdiff

// Palo Alto config drift on backup has not been audited for this codebase yet.
// Until we have evidence of a similar IV-churn problem on PAN-OS exports, the
// normalizer is identity — same as today's behavior for paloalto devices.
// When we add real normalization, replace this file's body and add tests.

func init() {
	Register(paloaltoNormalizer{})
}

type paloaltoNormalizer struct{}

func (paloaltoNormalizer) Vendor() string                       { return "paloalto" }
func (paloaltoNormalizer) Normalize(raw []byte) ([]byte, string) { return raw, QualityUnknown }
func (paloaltoNormalizer) VolatilePatterns() []VolatilePattern   { return nil }
