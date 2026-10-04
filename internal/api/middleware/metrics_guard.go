package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// MetricsGuard gates the Prometheus endpoint. Until v0.11.288 /metrics was
// served to anyone who could reach port 8080, which is published to the
// internet on most installs because remote collectors post to it. It carries
// no secrets, but route templates, request rates and Go runtime figures are
// still reconnaissance, so:
//
//   - METRICS_TOKEN set: every request must carry `Authorization: Bearer
//     <token>`; anything else is 401 with a WWW-Authenticate challenge. The
//     operator has chosen to expose the endpoint to a scraper, so a clear
//     auth failure (visible in Prometheus' target status) beats a silent 404.
//     The comparison is constant-time over SHA-256 digests, so neither the
//     value nor its length leaks through timing.
//   - METRICS_TOKEN unset (the default): only a loopback TCP peer (127/8,
//     ::1) is served — `wget http://127.0.0.1:8080/metrics` inside the
//     container keeps working — and everyone else gets a 404, the same answer
//     as for a path that does not exist, so the endpoint is not advertised.
//
// The peer is c.RemoteIP(), the socket address. ClientIP() is deliberately
// not used: it honours X-Forwarded-For from a trusted proxy, and a proxy must
// never be able to turn a remote scrape into a "local" one.
func MetricsGuard(token string) gin.HandlerFunc {
	token = strings.TrimSpace(token) // a whitespace-only value would lock everyone out
	want := sha256.Sum256([]byte(token))
	return func(c *gin.Context) {
		if token != "" {
			got, ok := bearerToken(c.GetHeader("Authorization"))
			sum := sha256.Sum256([]byte(got))
			if !ok || subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
				c.Header("WWW-Authenticate", `Bearer realm="metrics"`)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Next()
			return
		}
		if ip := net.ParseIP(c.RemoteIP()); ip == nil || !ip.IsLoopback() {
			// Same body as gin's unknown-route 404, so the gated endpoint is
			// indistinguishable from a route that does not exist.
			c.String(http.StatusNotFound, "404 page not found")
			c.Abort()
			return
		}
		c.Next()
	}
}

// bearerToken extracts the credential from an Authorization header. The
// scheme is case-insensitive (RFC 9110 §11.1), the credential is not.
func bearerToken(header string) (string, bool) {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	return strings.TrimSpace(header[len(scheme):]), true
}
