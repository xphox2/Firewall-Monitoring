package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// metricsRouter mounts MetricsGuard in front of a stub /metrics, with the
// trusted-proxy set the production router would have for TRUSTED_PROXIES =
// proxies (so ClientIP honours X-Forwarded-For from that peer, exactly as in
// production — the guard must still ignore it).
func metricsRouter(t *testing.T, token string, proxies ...string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if len(proxies) > 0 {
		if err := r.SetTrustedProxies(proxies); err != nil {
			t.Fatalf("SetTrustedProxies: %v", err)
		}
		r.RemoteIPHeaders = []string{"X-Forwarded-For"}
	} else {
		_ = r.SetTrustedProxies(nil)
	}
	r.GET("/metrics", MetricsGuard(token), func(c *gin.Context) {
		c.String(http.StatusOK, "fwmon_up 1\n")
	})
	return r
}

func scrape(r *gin.Engine, remoteAddr string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestMetricsGuard_NoToken_LoopbackOnly: with METRICS_TOKEN unset the endpoint
// answers a loopback TCP peer (the in-container `wget http://127.0.0.1:8080/
// metrics` path) and nobody else — and the refusal is a 404, not a 401/403,
// so an internet-facing port 8080 does not advertise the endpoint.
func TestMetricsGuard_NoToken_LoopbackOnly(t *testing.T) {
	r := metricsRouter(t, "")
	for _, peer := range []string{"127.0.0.1:40000", "127.0.0.5:40000", "[::1]:40000"} {
		if rec := scrape(r, peer, nil); rec.Code != http.StatusOK || rec.Body.String() != "fwmon_up 1\n" {
			t.Errorf("loopback peer %s: status=%d body=%q, want 200 + metrics", peer, rec.Code, rec.Body.String())
		}
	}
	for _, peer := range []string{"203.0.113.9:40000", "192.0.2.1:1234", "[2001:db8::1]:40000", "10.0.0.2:40000"} {
		rec := scrape(r, peer, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("non-loopback peer %s: status=%d, want 404", peer, rec.Code)
		}
		if rec.Body.String() == "fwmon_up 1\n" {
			t.Errorf("non-loopback peer %s was served the metrics body", peer)
		}
	}
}

// TestMetricsGuard_NoToken_SpoofedForwardedHeadersIgnored: the guard keys on
// the socket peer, never on a forwarded header. A remote peer claiming to be
// loopback via X-Forwarded-For / X-Real-IP stays a 404 — even when that peer
// IS a trusted proxy whose X-Forwarded-For ClientIP() would otherwise honour.
func TestMetricsGuard_NoToken_SpoofedForwardedHeadersIgnored(t *testing.T) {
	spoof := map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}

	if rec := scrape(metricsRouter(t, ""), "203.0.113.9:40000", spoof); rec.Code != http.StatusNotFound {
		t.Errorf("untrusted peer with spoofed loopback headers: status=%d, want 404", rec.Code)
	}
	if rec := scrape(metricsRouter(t, "", "203.0.113.9"), "203.0.113.9:40000", spoof); rec.Code != http.StatusNotFound {
		t.Errorf("trusted proxy forwarding a 'loopback' client: status=%d, want 404 (RemoteIP, not ClientIP, decides)", rec.Code)
	}
}

// TestMetricsGuard_Token_RequiredAndChecked: with METRICS_TOKEN set the bearer
// token is required from every peer (loopback included), the wrong value is
// refused, and the refusal is a 401 with a challenge so a misconfigured
// scraper shows an auth failure rather than a vanished target.
func TestMetricsGuard_Token_RequiredAndChecked(t *testing.T) {
	const token = "scrape-me-please-0123456789"
	r := metricsRouter(t, token)

	ok := scrape(r, "203.0.113.9:40000", map[string]string{"Authorization": "Bearer " + token})
	if ok.Code != http.StatusOK || ok.Body.String() != "fwmon_up 1\n" {
		t.Fatalf("correct token from a remote peer: status=%d body=%q, want 200 + metrics", ok.Code, ok.Body.String())
	}
	// The auth scheme is case-insensitive (RFC 9110), the credential is not.
	if rec := scrape(r, "127.0.0.1:40000", map[string]string{"Authorization": "bearer " + token}); rec.Code != http.StatusOK {
		t.Errorf("lower-case scheme with the correct token: status=%d, want 200", rec.Code)
	}
	// A whitespace-only METRICS_TOKEN is "unset", not a token nobody can present.
	if rec := scrape(metricsRouter(t, "  "), "127.0.0.1:40000", nil); rec.Code != http.StatusOK {
		t.Errorf("blank token, loopback peer: status=%d, want 200 (loopback rule)", rec.Code)
	}

	cases := []struct {
		name string
		peer string
		hdr  map[string]string
	}{
		{"no header, remote", "203.0.113.9:40000", nil},
		{"no header, loopback", "127.0.0.1:40000", nil},
		{"wrong token", "203.0.113.9:40000", map[string]string{"Authorization": "Bearer " + token + "x"}},
		{"token prefix", "203.0.113.9:40000", map[string]string{"Authorization": "Bearer " + token[:len(token)-1]}},
		{"wrong scheme", "203.0.113.9:40000", map[string]string{"Authorization": "Basic " + token}},
		{"bare token", "203.0.113.9:40000", map[string]string{"Authorization": token}},
		{"empty bearer", "203.0.113.9:40000", map[string]string{"Authorization": "Bearer "}},
	}
	for _, tc := range cases {
		rec := scrape(r, tc.peer, tc.hdr)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status=%d, want 401", tc.name, rec.Code)
		}
		if rec.Body.String() == "fwmon_up 1\n" {
			t.Errorf("%s: metrics body served without a valid token", tc.name)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="metrics"` {
			t.Errorf("%s: WWW-Authenticate=%q, want the Bearer challenge", tc.name, got)
		}
	}
}
