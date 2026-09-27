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

// TestFlowReclassifyRoutes: Reapply rewrites all stored flow history, so it is
// admin-only; its progress carries no network detail and stays viewer-visible
// for the Flows page. adminOnlyRoutes keys on the path for every method, so
// the two must be separate paths.
func TestFlowReclassifyRoutes(t *testing.T) {
	data, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	start := strings.Index(body, "adminOnlyRoutes — role=admin")
	end := strings.Index(body[start:], "))")
	adminOnly := strings.Join(strings.Fields(body[start:start+end]), "")
	if !strings.Contains(adminOnly, `"/admin/api/flows/reclassify":true`) {
		t.Error("POST /admin/api/flows/reclassify must be in adminOnlyRoutes")
	}
	if strings.Contains(adminOnly, `"/admin/api/flows/reclassify/status"`) {
		t.Error("the reclassification status must stay viewer-visible (the Flows page shows it)")
	}
	for _, reg := range []string{
		`admin.GET("/api/flows/reclassify/status", handler.GetFlowReclassStatus)`,
		`admin.POST("/api/flows/reclassify", handler.ReapplyFlowClassification)`,
	} {
		if !strings.Contains(body, reg) {
			t.Errorf("route not registered: %s", reg)
		}
	}
}

// The reclassification progress reaches both pages, and Reapply is wired
// through the confirm dialog to the admin-only POST.
func TestFlowReclassUIWired(t *testing.T) {
	flows := readJS(t, "admin-flows.js")
	if !strings.Contains(flows, "AC.apiFetch('/admin/api/flows/reclassify/status')") || !strings.Contains(flows, "loadReclassStatus();") {
		t.Error("the Flows page does not load the reclassification status")
	}
	main := readJS(t, "admin-main.js")
	for _, sub := range []string{
		"'flow-reapply': function() { reapplyFlowClassification(); },",
		"apiFetch(API_BASE + '/flows/reclassify', { method: 'POST' })",
		"AC.confirm('Re-classify all stored flow history",
	} {
		if !strings.Contains(main, sub) {
			t.Errorf("admin-main.js is missing %q", sub)
		}
	}
	common := readJS(t, "admin-common.js")
	if !strings.Contains(common, "flowReclassText: flowReclassText,") {
		t.Error("AdminCommon.flowReclassText is not exported")
	}
}
