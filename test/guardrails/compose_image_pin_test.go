package guardrails

import (
	"os"
	"strings"
	"testing"
)

// TestComposeImagesPinned_NoMutableTags pins the supply-chain fix: the compose
// files must not reference a mutable image tag (`latest`/`stable`) without an
// immutable `@sha256:<digest>`, and the nginx-proxy-manager admin UI must be
// loopback-bound so it is not exposed to the internet.
func TestComposeImagesPinned_NoMutableTags(t *testing.T) {
	// The proxy compose: NPM image pinned + admin UI loopback-bound.
	proxy, err := os.ReadFile("../../docker-compose.proxy.yml")
	if err != nil {
		t.Skipf("docker-compose.proxy.yml not found: %v", err)
	}
	proxyBody := string(proxy)
	if strings.Contains(proxyBody, `image: jc21/nginx-proxy-manager:latest`) &&
		!strings.Contains(proxyBody, `image: jc21/nginx-proxy-manager:latest@sha256:`) {
		t.Error("docker-compose.proxy.yml references jc21/nginx-proxy-manager:latest without an @sha256 digest — pin the image.")
	}
	if !strings.Contains(proxyBody, `"127.0.0.1:81:81"`) {
		t.Error("docker-compose.proxy.yml must bind the nginx-proxy-manager admin UI to 127.0.0.1 (\"127.0.0.1:81:81\"), not expose it on 0.0.0.0.")
	}

	// The main compose: the firewall-mon image default must carry a digest.
	main, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Skipf("docker-compose.yml not found: %v", err)
	}
	if !strings.Contains(string(main), "xphox/firewall-mon:latest@sha256:") {
		t.Error("docker-compose.yml defaults the firewall-mon image to a mutable tag without an @sha256 digest — pin it.")
	}
}
