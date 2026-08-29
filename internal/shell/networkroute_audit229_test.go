package shell

import (
	"os"
	"strings"
	"testing"
)

// AUDIT-229: web/network.html, admin-network.js and the sidebar link were
// deleted in ca301f2, but cmd/api/main.go still registered
// admin.GET("/network", … RenderHTML("network.html")). The route was dead and
// errored (the template no longer exists). This pins that the dead route and
// every reference to the deleted template stays gone.
func TestNetworkRoute_Removed_AUDIT229(t *testing.T) {
	b, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatalf("read cmd/api/main.go: %v", err)
	}
	src := string(b)

	if strings.Contains(src, `admin.GET("/network"`) {
		t.Error("AUDIT-229 regression: the dead admin.GET(\"/network\") route is back in cmd/api/main.go")
	}
	if strings.Contains(src, "network.html") {
		t.Error("AUDIT-229 regression: cmd/api/main.go references the deleted network.html template")
	}

	// The deleted assets must stay deleted.
	for _, p := range []string{
		"../../web/network.html",
		"../../cmd/api/static/js/admin-network.js",
	} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("AUDIT-229 regression: %s was resurrected; its route was removed", p)
		}
	}
}
