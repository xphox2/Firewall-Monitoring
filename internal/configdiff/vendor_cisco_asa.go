package configdiff

// Cisco ASA config drift on backup has not been audited for this codebase yet.
// Identity normalizer until we have evidence we need more.

func init() {
	Register(ciscoASANormalizer{})
}

type ciscoASANormalizer struct{}

func (ciscoASANormalizer) Vendor() string                       { return "cisco_asa" }
func (ciscoASANormalizer) Normalize(raw []byte) ([]byte, string) { return raw, QualityUnknown }
func (ciscoASANormalizer) VolatilePatterns() []VolatilePattern   { return nil }
