package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/config"

	"github.com/gin-gonic/gin"
)

// TestTestIRCServer_RejectsSSRFTargets_AUDIT013 locks in AUDIT-013: the
// admin-only "Test IRC Server" endpoint dialed an arbitrary `server_host`
// from the request body with NO SSRF allow-list, even though sibling test
// endpoints (TestProbeConnection, TestEmail) gate on `isValidExternalIP`
// since v0.10.140. An admin (or anyone with a stolen session cookie) could
// turn this handler into an internal port-scanner against the monitor's LAN.
//
// The check rejects loopback, RFC 1918, link-local, and unresolvable hosts.
// We assert on the 400 status code: SSRF rejection returns 400, whereas a
// real connection failure (against a public IP that doesn't speak IRC)
// returns 200 with success=false in the body.
func TestTestIRCServer_RejectsSSRFTargets_AUDIT013(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, nil, nil)

	cases := []struct {
		name string
		host string
		want int
	}{
		{"ipv4 loopback", "127.0.0.1", http.StatusBadRequest},
		{"ipv4 loopback alt", "127.0.0.53", http.StatusBadRequest},
		{"ipv6 loopback", "::1", http.StatusBadRequest},
		{"unspecified ipv4", "0.0.0.0", http.StatusBadRequest},
		{"unspecified ipv6", "::", http.StatusBadRequest},
		{"link-local ipv4", "169.254.169.254", http.StatusBadRequest},
		{"link-local ipv6", "fe80::1", http.StatusBadRequest},
		{"rfc1918 10/8", "10.0.0.1", http.StatusBadRequest},
		{"rfc1918 172.16/12", "172.16.0.1", http.StatusBadRequest},
		{"rfc1918 192.168/16", "192.168.1.1", http.StatusBadRequest},
		{"rfc4193 fc00::/7", "fc00::1", http.StatusBadRequest},
		{"localhost name", "localhost", http.StatusBadRequest},
		{"unresolvable host", "this-host-does-not-exist.invalid", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := map[string]interface{}{
				"server_host": c.host,
				"server_port": 6667,
				"nick":        "test",
			}
			w := callTestIRCServer(t, h, body)
			if w.Code != c.want {
				t.Errorf("host %q: status %d, want %d; body: %s", c.host, w.Code, c.want, w.Body.String())
			}
			if !strings.Contains(strings.ToLower(w.Body.String()), "disallowed") &&
				!strings.Contains(strings.ToLower(w.Body.String()), "invalid") {
				t.Errorf("host %q: response body does not mention disallowed/invalid: %s", c.host, w.Body.String())
			}
		})
	}
}

// TestTestIRCServer_RejectsInvalidPort guards the input-validation path
// added alongside the AUDIT-013 fix.
func TestTestIRCServer_RejectsInvalidPort(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, nil, nil)

	cases := []struct {
		name string
		port int
		want int
	}{
		{"negative", -1, http.StatusBadRequest},
		{"too high", 65536, http.StatusBadRequest},
		// 0 is explicitly allowed (treated as default 6667), so we skip it.
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := map[string]interface{}{
				"server_host": "example.com",
				"server_port": c.port,
				"nick":        "test",
			}
			w := callTestIRCServer(t, h, body)
			if w.Code != c.want {
				t.Errorf("port %d: status %d, want %d; body: %s", c.port, w.Code, c.want, w.Body.String())
			}
		})
	}
}

// TestTestIRCServer_RejectsMissingHost — `binding:"required"` should catch
// it; this also exercises the bind error path.
func TestTestIRCServer_RejectsMissingHost(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, nil, nil)

	body := map[string]interface{}{
		"server_port": 6667,
		"nick":        "test",
	}
	w := callTestIRCServer(t, h, body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing host: status %d, want 400", w.Code)
	}
}

func callTestIRCServer(t *testing.T, h *Handler, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/irc/test", h.TestIRCServer)

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest("POST", "/irc/test", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}
