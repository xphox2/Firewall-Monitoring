package shell

import (
	"os"
	"strings"
	"testing"
)

// TestNginxCompanionConfig_AUDIT097 pins that the hardened companion
// reverse-proxy config exists and carries every feature the audit said the
// stock docker-compose.proxy.yml was missing — TLS termination, HSTS,
// gzip, WebSocket upgrade for the live pages, and real client IP — and that
// the compose file points operators at it.
func TestNginxCompanionConfig_AUDIT097(t *testing.T) {
	const confPath = "../../docs/nginx.conf"
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("docs/nginx.conf not found at %s — AUDIT-097 ships this hardened proxy example; err: %v", confPath, err)
	}
	conf := string(data)

	features := []struct {
		needle string
		why    string
	}{
		{"ssl_certificate", "TLS termination must be configured"},
		{"Strict-Transport-Security", "HSTS header must be sent"},
		{"gzip on", "gzip compression must be enabled"},
		{"$connection_upgrade", "WebSocket Upgrade/Connection mapping must be present"},
		{"proxy_set_header Upgrade", "WebSocket upgrade headers must be forwarded"},
		{"real_ip_header", "real client IP forwarding must be configured"},
		{"admin/connections", "the live connection-map WS route must be proxied with upgrade headers"},
		{"admin/irc", "the IRC console WS route must be proxied with upgrade headers"},
	}
	for _, f := range features {
		if !strings.Contains(conf, f.needle) {
			t.Errorf("docs/nginx.conf is missing %q: %s (AUDIT-097).", f.needle, f.why)
		}
	}

	// The compose file must reference the example so operators discover it.
	const composePath = "../../docker-compose.proxy.yml"
	cdata, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("docker-compose.proxy.yml not found at %s; err: %v", composePath, err)
	}
	if !strings.Contains(string(cdata), "docs/nginx.conf") {
		t.Error("docker-compose.proxy.yml does not reference docs/nginx.conf (AUDIT-097): the hardened config must be discoverable from the compose file.")
	}
}
