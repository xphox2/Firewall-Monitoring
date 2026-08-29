package notifier

import (
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

func fireAlert(sev models.Severity) *models.Alert {
	return &models.Alert{
		Timestamp:    time.Now(),
		DeviceID:     7,
		AlertType:    "CPU_HIGH",
		Severity:     sev,
		Message:      "cpu_usage is 97.0 (threshold: 90.0)",
		MetricName:   "cpu_usage",
		Threshold:    90,
		CurrentValue: 97,
	}
}

// recoveryAlert mirrors the alert shape sendRecovery hands to the notifier:
// the _RESOLVED type with the FIRE's MetricName (LC-42 — the persisted
// companion row keeps metric_name="recovery", but the notify copy carries the
// original metric so the dedup key below reproduces the fire's).
func recoveryAlert() *models.Alert {
	a := fireAlert("info")
	a.AlertType = "CPU_HIGH_RESOLVED"
	a.MetricName = "cpu_usage"
	return a
}

// TestPagerDutyPayload_TriggerAndResolve pins the Events API v2 shape: fires
// trigger with severity mapping and a deterministic dedup key; the companion
// _RESOLVED alert sends event_action=resolve with the SAME dedup key so the
// incident closes instead of double-paging.
func TestPagerDutyPayload_TriggerAndResolve(t *testing.T) {
	fire := buildPagerDutyPayload(fireAlert("critical"), "rk-123")
	if fire["event_action"] != "trigger" || fire["routing_key"] != "rk-123" {
		t.Fatalf("fire payload wrong: %+v", fire)
	}
	body := fire["payload"].(map[string]interface{})
	if body["severity"] != "critical" {
		t.Errorf("severity mapping: %v", body["severity"])
	}

	res := buildPagerDutyPayload(recoveryAlert(), "rk-123")
	if res["event_action"] != "resolve" {
		t.Fatalf("recovery must resolve: %+v", res)
	}
	if fire["dedup_key"] != res["dedup_key"] {
		t.Errorf("dedup keys must match across fire/resolve: %v vs %v", fire["dedup_key"], res["dedup_key"])
	}
	if _, hasBody := res["payload"]; hasBody {
		t.Error("resolve events carry no payload body")
	}
}

// TestOpsgeniePayload_PriorityAndAlias pins priority mapping + alias identity.
func TestOpsgeniePayload_PriorityAndAlias(t *testing.T) {
	p := buildOpsgeniePayload(fireAlert("critical"))
	if p["priority"] != "P1" {
		t.Errorf("critical → %v, want P1", p["priority"])
	}
	if p["alias"] != alertDedupKey(fireAlert("critical")) {
		t.Errorf("alias must be the dedup key: %v", p["alias"])
	}
	if buildOpsgeniePayload(fireAlert("warning"))["priority"] != "P3" {
		t.Error("warning → want P3")
	}
}

// TestOpsgenieCloseURL_EscapesAlias (AUDIT-208): the close-by-alias URL
// interpolates the dedup key into the URL PATH, and keys embed MetricName —
// interface names like "interface_GigabitEthernet0/0" carry '/'. Unescaped,
// the slash splits the path and Opsgenie 404s the close, so the incident stays
// open forever. The alias must arrive as ONE path segment with the slash as
// %2F; alertDedupKey itself (the fire payload's alias) stays byte-identical.
func TestOpsgenieCloseURL_EscapesAlias(t *testing.T) {
	var gotEscapedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	orig := opsgenieAlertsURL
	opsgenieAlertsURL = srv.URL + "/v2/alerts"
	defer func() { opsgenieAlertsURL = orig }()

	n := &Notifier{client: srv.Client()}
	a := fireAlert("info")
	a.AlertType = "INTERFACE_DOWN_RESOLVED"
	a.MetricName = "interface_GigabitEthernet0/0"
	if err := n.sendOpsgenie(a, NotifyConfig{OpsgenieAPIKey: "gk"}); err != nil {
		t.Fatalf("sendOpsgenie: %v", err)
	}
	want := "/v2/alerts/" + neturl.PathEscape(alertDedupKey(a)) + "/close"
	if gotEscapedPath != want {
		t.Errorf("close path = %q, want %q", gotEscapedPath, want)
	}
	if !strings.Contains(gotEscapedPath, "%2F") {
		t.Errorf("alias slash not %%2F-escaped on the wire: %q", gotEscapedPath)
	}

	// A space-containing metric must build a valid request (no NewRequest error).
	b := fireAlert("info")
	b.AlertType = "INTERFACE_DOWN_RESOLVED"
	b.MetricName = "interface with space"
	if err := n.sendOpsgenie(b, NotifyConfig{OpsgenieAPIKey: "gk"}); err != nil {
		t.Errorf("space-containing metric: %v", err)
	}
}

// TestTeamsPayload_SeverityColorAndResolveTitle pins the MessageCard shape.
func TestTeamsPayload_SeverityColorAndResolveTitle(t *testing.T) {
	card := buildTeamsPayload(fireAlert("critical"))
	if card["themeColor"] != "E81123" {
		t.Errorf("critical color: %v", card["themeColor"])
	}
	if card["@type"] != "MessageCard" {
		t.Errorf("type: %v", card["@type"])
	}
	res := buildTeamsPayload(recoveryAlert())
	title, _ := res["title"].(string)
	if title != "Firewall-Mon: CPU_HIGH (resolved)" {
		t.Errorf("resolve title: %q", title)
	}
}

// TestIncidentChannelEligibility: incident channels require BOTH a credential
// AND an active policy that opted in — no presence-only fallback (paging a
// human is an explicit routing decision).
func TestIncidentChannelEligibility(t *testing.T) {
	cases := []struct {
		name       string
		nc         NotifyConfig
		pd, og, tm bool
	}{
		{"all off", NotifyConfig{}, false, false, false},
		{"creds without policy stay off",
			NotifyConfig{PagerDutyRoutingKey: "rk", OpsgenieAPIKey: "gk", TeamsWebhookURL: "https://x"},
			false, false, false},
		{"policy opt-in without creds stays off",
			NotifyConfig{PolicyActive: true, EnablePagerDuty: true, EnableOpsgenie: true, EnableTeams: true},
			false, false, false},
		{"creds + policy opt-in fire",
			NotifyConfig{PolicyActive: true, EnablePagerDuty: true, EnableOpsgenie: true, EnableTeams: true,
				PagerDutyRoutingKey: "rk", OpsgenieAPIKey: "gk", TeamsWebhookURL: "https://x"},
			true, true, true},
		{"selective opt-in",
			NotifyConfig{PolicyActive: true, EnablePagerDuty: true,
				PagerDutyRoutingKey: "rk", OpsgenieAPIKey: "gk", TeamsWebhookURL: "https://x"},
			true, false, false},
	}
	for _, tc := range cases {
		pd, og, tm := incidentChannelEligibility(tc.nc)
		if pd != tc.pd || og != tc.og || tm != tc.tm {
			t.Errorf("%s: got (%v,%v,%v), want (%v,%v,%v)", tc.name, pd, og, tm, tc.pd, tc.og, tc.tm)
		}
	}
}
