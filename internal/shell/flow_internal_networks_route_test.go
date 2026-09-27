package shell

import (
	"os"
	"strings"
	"testing"
)

// TestFlowInternalNetworksRouteAdminOnly: the effective internal-network list
// reveals the operator's network layout, so it must stay in adminOnlyRoutes —
// RequireRole otherwise defaults a GET to the viewer role. Same source-scan
// pattern as TestConfigHistoryReadRoutesAdminOnly.
func TestFlowInternalNetworksRouteAdminOnly(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	if start < 0 {
		t.Fatal("adminOnlyRoutes marker not found")
	}
	end := strings.Index(body[start:], "))")
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	if !strings.Contains(adminOnly, `"/admin/api/flows/internal-networks":true`) {
		t.Error("/admin/api/flows/internal-networks must be in adminOnlyRoutes")
	}
	if !strings.Contains(body, `admin.GET("/api/flows/internal-networks", handler.GetFlowInternalNetworks)`) {
		t.Error("the internal-networks route is not registered")
	}
}

// TestFlowClassificationSettingsAreSavedAndTracked: saveSettings and the dirty
// tracker historically collected only input/select, so a textarea would be
// neither saved nor marked unsaved. Both must include the network list.
func TestFlowClassificationSettingsAreSavedAndTracked(t *testing.T) {
	main := readJS(t, "admin-main.js")
	for _, sub := range []string{
		"document.querySelectorAll('#settings-flow-classification input, #settings-flow-classification textarea')",
		`name="flow_internal_networks"`,
		"apiFetch(API_BASE + '/flows/internal-networks')",
	} {
		if !strings.Contains(main, sub) {
			t.Errorf("admin-main.js is missing %q", sub)
		}
	}
	tracker := readJS(t, "admin-settings.js")
	for _, sub := range []string{"'#settings-flow-classification',", "c + ' textarea'", "el.matches('input, select, textarea')"} {
		if !strings.Contains(tracker, sub) {
			t.Errorf("admin-settings.js is missing %q — the list would not mark the page unsaved", sub)
		}
	}
}
