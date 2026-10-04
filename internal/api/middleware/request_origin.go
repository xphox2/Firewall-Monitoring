package middleware

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

// TrustedProxySet is the TRUSTED_PROXIES list as address ranges, used to
// decide whether the TCP peer of a request is a reverse proxy whose
// X-Forwarded-Proto may be believed. It is built from the same parsed list
// gin receives in ConfigureTrustedProxies, so the two never disagree about
// who the proxies are. A nil set trusts nobody.
type TrustedProxySet struct {
	nets []*net.IPNet
}

// NewTrustedProxySet turns the entries ConfigureTrustedProxies returned (each
// already a valid IP or CIDR) into a set. Entries that fail to parse are
// skipped; nothing here is fatal.
func NewTrustedProxySet(entries []string) *TrustedProxySet {
	s := &TrustedProxySet{}
	for _, entry := range entries {
		if _, n, err := net.ParseCIDR(entry); err == nil {
			s.nets = append(s.nets, n)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			continue
		}
		bits := 128
		if ip4 := ip.To4(); ip4 != nil {
			ip, bits = ip4, 32
		}
		s.nets = append(s.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return s
}

// Contains reports whether ip is one of the trusted proxies.
func (s *TrustedProxySet) Contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// requestHTTPSKey is the gin-context key RequestOrigin stores its verdict under.
const requestHTTPSKey = "fwmon.request_over_https"

// RequestOrigin decides once per request whether it reached the operator's
// deployment over HTTPS and records the verdict for RequestOverHTTPS. It is
// true when the API terminated TLS itself, or when the TCP peer is one of the
// trusted proxies AND that proxy says X-Forwarded-Proto: https. The peer is
// c.RemoteIP() — the socket address, never a forwarded header — so a client
// that is not the proxy cannot claim HTTPS by sending the header itself, and
// with TRUSTED_PROXIES empty the header is never consulted at all.
//
// The verdict drives the Secure flag on the session cookies (when
// COOKIE_SECURE is not set explicitly) and the HSTS header, which is why it
// must be registered before SecureHeaders and the route handlers.
func RequestOrigin(proxies *TrustedProxySet) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(requestHTTPSKey, arrivedOverHTTPS(c, proxies))
		c.Next()
	}
}

func arrivedOverHTTPS(c *gin.Context, proxies *TrustedProxySet) bool {
	if c.Request.TLS != nil {
		return true
	}
	if !proxies.Contains(net.ParseIP(c.RemoteIP())) {
		return false
	}
	// Exact match only: a chained value such as "https, http" is ambiguous
	// about the hop the browser used, so it is treated as not-HTTPS (the
	// conservative answer — a cookie without Secure still works, HSTS is
	// simply not sent). The bundled nginx config sets the header from its own
	// $scheme, so the value is always a single token there.
	return strings.EqualFold(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")), "https")
}

// RequestOverHTTPS returns RequestOrigin's verdict for this request. When the
// middleware is not installed (unit tests that mount a single handler) it
// falls back to the pre-existing rule, in-process TLS only, so nothing is ever
// treated as HTTPS on the strength of a header alone.
func RequestOverHTTPS(c *gin.Context) bool {
	if v, ok := c.Get(requestHTTPSKey); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return c.Request != nil && c.Request.TLS != nil
}
