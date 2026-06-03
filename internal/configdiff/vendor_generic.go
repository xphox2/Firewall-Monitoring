package configdiff

// Generic / unknown vendor — explicit identity registration.
// Same effect as Lookup falling back to identityNormalizer, but having an
// explicit "generic" entry lets us distinguish "operator chose generic" from
// "we didn't know the vendor" in any future telemetry.

func init() {
	Register(genericNormalizer{})
}

type genericNormalizer struct{}

func (genericNormalizer) Vendor() string                        { return "generic" }
func (genericNormalizer) Normalize(raw []byte) ([]byte, string) { return raw, QualityUnknown }
func (genericNormalizer) VolatilePatterns() []VolatilePattern   { return nil }
