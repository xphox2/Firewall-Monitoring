package middleware

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// originRouter is the production middleware order: RequestOrigin (built from
// the given TRUSTED_PROXIES entries) then SecureHeaders, in front of a probe
// route that reports RequestOverHTTPS.
func originRouter(proxies ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestOrigin(NewTrustedProxySet(proxies)))
	r.Use(SecureHeaders())
	r.GET("/probe", func(c *gin.Context) {
		if RequestOverHTTPS(c) {
			c.String(http.StatusOK, "https")
			return
		}
		c.String(http.StatusOK, "http")
	})
	return r
}

func probe(r *gin.Engine, remoteAddr string, overTLS bool, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.RemoteAddr = remoteAddr
	if overTLS {
		req.TLS = &tls.ConnectionState{}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

const hstsProxied = "max-age=31536000"

// TestRequestOrigin_HTTPSVerdictAndHSTS pins the "arrived over HTTPS" rule and
// the HSTS header it drives: present for in-process TLS and for a trusted
// proxy's X-Forwarded-Proto: https; absent on plain HTTP; and a spoofed
// header from a peer that is not the trusted proxy changes nothing.
func TestRequestOrigin_HTTPSVerdictAndHSTS(t *testing.T) {
	xfpHTTPS := map[string]string{"X-Forwarded-Proto": "https"}
	cases := []struct {
		name     string
		proxies  []string
		peer     string
		tls      bool
		hdr      map[string]string
		wantHTTP bool // verdict: true = HTTPS
		wantHSTS string
	}{
		{"direct plain HTTP", nil, "203.0.113.9:40000", false, nil, false, ""},
		{"direct plain HTTP, self-claimed https", nil, "203.0.113.9:40000", false, xfpHTTPS, false, ""},
		{"in-process TLS", nil, "203.0.113.9:40000", true, nil, true, "max-age=31536000; includeSubDomains"},
		{"trusted proxy, https", []string{"192.0.2.10"}, "192.0.2.10:40000", false, xfpHTTPS, true, hstsProxied},
		{"trusted proxy, HTTPS (case)", []string{"192.0.2.10"}, "192.0.2.10:40000", false, map[string]string{"X-Forwarded-Proto": " HTTPS "}, true, hstsProxied},
		{"trusted proxy by CIDR, https", []string{"192.0.2.0/24"}, "192.0.2.77:40000", false, xfpHTTPS, true, hstsProxied},
		{"trusted proxy, http", []string{"192.0.2.10"}, "192.0.2.10:40000", false, map[string]string{"X-Forwarded-Proto": "http"}, false, ""},
		{"trusted proxy, no header", []string{"192.0.2.10"}, "192.0.2.10:40000", false, nil, false, ""},
		{"trusted proxy, chained value", []string{"192.0.2.10"}, "192.0.2.10:40000", false, map[string]string{"X-Forwarded-Proto": "https, http"}, false, ""},
		{"untrusted peer spoofing https", []string{"192.0.2.10"}, "203.0.113.9:40000", false, xfpHTTPS, false, ""},
		{"untrusted peer spoofing https + XFF", []string{"192.0.2.10"}, "203.0.113.9:40000", false, map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-For": "192.0.2.10"}, false, ""},
		{"trusted IPv6 proxy, https", []string{"2001:db8::10"}, "[2001:db8::10]:40000", false, xfpHTTPS, true, hstsProxied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := probe(originRouter(tc.proxies...), tc.peer, tc.tls, tc.hdr)
			want := "http"
			if tc.wantHTTP {
				want = "https"
			}
			if got := rec.Body.String(); got != want {
				t.Errorf("RequestOverHTTPS verdict = %q, want %q", got, want)
			}
			if got := rec.Header().Get("Strict-Transport-Security"); got != tc.wantHSTS {
				t.Errorf("Strict-Transport-Security = %q, want %q", got, tc.wantHSTS)
			}
		})
	}
}

// TestRequestOverHTTPS_WithoutMiddleware: a handler mounted without
// RequestOrigin (every unit test that calls a handler directly) falls back to
// in-process TLS only — a header alone never counts.
func TestRequestOverHTTPS_WithoutMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.RemoteAddr = "127.0.0.1:40000"
	c.Request.Header.Set("X-Forwarded-Proto", "https")
	if RequestOverHTTPS(c) {
		t.Error("header alone counted as HTTPS without the middleware")
	}
	c.Request.TLS = &tls.ConnectionState{}
	if !RequestOverHTTPS(c) {
		t.Error("in-process TLS not recognised without the middleware")
	}
}

// TestSecureHeaders_NoHSTSOnPlainHTTP is the AUDIT-024 counterpart for HSTS:
// a plain-HTTP deployment must never pin browsers to https.
func TestSecureHeaders_NoHSTSOnPlainHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecureHeaders())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS sent on plain HTTP: %q", got)
	}
}

func TestTrustedProxySet_Contains(t *testing.T) {
	set := NewTrustedProxySet([]string{"192.0.2.10", "198.51.100.0/24", "2001:db8::10", "not-an-ip"})
	for ip, want := range map[string]bool{
		"192.0.2.10":        true,
		"192.0.2.11":        false,
		"198.51.100.1":      true,
		"198.51.100.0":      true,
		"198.51.101.1":      false,
		"2001:db8::10":      true,
		"2001:db8::11":      false,
		"::ffff:192.0.2.10": true,
	} {
		if got := set.Contains(net.ParseIP(ip)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", ip, got, want)
		}
	}
	if set.Contains(nil) {
		t.Error("Contains(nil) must be false")
	}
	var nilSet *TrustedProxySet
	if nilSet.Contains(net.ParseIP("192.0.2.10")) {
		t.Error("a nil set must trust nobody")
	}
	if NewTrustedProxySet(nil).Contains(net.ParseIP("127.0.0.1")) {
		t.Error("an empty set must trust nobody, loopback included")
	}
}
