package logfields

// genericExtractor is the fallback for unknown/未-profiled vendors. It adds no
// structured fields — only the base fields (severity, facility, app_name,
// hostname, message) that Fields already populated are available for matching.
// This is intentionally the zero-behavior default so an unprofiled vendor is
// safe (rules simply can't match vendor-specific fields until a profile ships).
type genericExtractor struct{}

func (genericExtractor) Vendor() string { return "generic" }

func (genericExtractor) Extract(raw string, dst map[string]string) {}
