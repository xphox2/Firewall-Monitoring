package middleware

import (
	"log"
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

// ParseTrustedProxies turns the TRUSTED_PROXIES value (comma-separated IPs
// and/or CIDRs) into the list handed to gin. Blank items are ignored; an
// entry that is neither a valid IP nor a valid CIDR is logged and SKIPPED —
// never fatal, so a typo can't keep the API from starting. An empty result
// means "trust no proxy".
func ParseTrustedProxies(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(item)
		if entry == "" {
			continue
		}
		if net.ParseIP(entry) != nil {
			out = append(out, entry)
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err == nil {
			out = append(out, entry)
			continue
		}
		log.Printf("WARNING: TRUSTED_PROXIES entry %q is not a valid IP or CIDR — ignored", entry)
	}
	return out
}

// ConfigureTrustedProxies applies TRUSTED_PROXIES to the engine (D-D3).
//
//   - Empty / no valid entries: SetTrustedProxies(nil) — exactly the historical
//     behaviour: forwarding headers are ignored and ClientIP() is the TCP peer.
//   - Otherwise: trust only the listed proxies and read ONLY X-Forwarded-For
//     (not X-Real-IP). gin walks X-Forwarded-For right-to-left and returns the
//     first address that is not a trusted proxy, and it consults the header at
//     all only when the TCP peer itself is trusted — so a client-supplied
//     X-Forwarded-For from an untrusted peer is ignored.
//
// If gin rejects the list anyway, fall back to trusting nothing (fail closed).
func ConfigureTrustedProxies(engine *gin.Engine, raw string) {
	proxies := ParseTrustedProxies(raw)
	if len(proxies) == 0 {
		_ = engine.SetTrustedProxies(nil) // nil never errors
		return
	}
	if err := engine.SetTrustedProxies(proxies); err != nil {
		log.Printf("WARNING: TRUSTED_PROXIES could not be applied (%v) — trusting no proxy", err)
		_ = engine.SetTrustedProxies(nil)
		return
	}
	engine.RemoteIPHeaders = []string{"X-Forwarded-For"}
	log.Printf("Trusting X-Forwarded-For from proxies: %s", strings.Join(proxies, ", "))
}
