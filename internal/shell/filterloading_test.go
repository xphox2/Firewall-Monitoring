package shell

import (
	"regexp"
	"strings"
	"testing"
)

// Every server-side search and filter runs under the shared loading overlay
// with Cancel (v0.11.271). These pin the parts that regress silently: a load
// that cannot be cancelled, a cancelled load that leaves the controls naming a
// query whose results are not on screen, page state (offsets, selection)
// advanced before the page arrives, a poll that overwrites a load the user
// started, and an overlay that covers the controls it should leave usable.

func mustContain(t *testing.T, file, src, sub, why string) {
	t.Helper()
	if !strings.Contains(src, sub) {
		t.Errorf("%s is missing %q — %s", file, sub, why)
	}
}

func TestFilterLoad_HelperContract(t *testing.T) {
	js := readJS(t, "admin-common.js")
	must := func(sub, why string) { t.Helper(); mustContain(t, "admin-common.js", js, sub, why) }
	must("var escScope = chartContainers(opts.escScope || []);", "Esc also cancels while focus is in the filter controls that started the load")
	must("if (k === keyOrPrefix || k.indexOf(keyOrPrefix) === 0) chartLoads[k].supersede();", "chartLoadCancel stops a page's loads by key prefix")
	must("var entry = { supersede: function() { abortFetch(); finish({ cancelled: true, superseded: true }); } };",
		"an app-initiated cancel resolves superseded, so it never restores or notifies")
	must("if (k.indexOf(keyOrPrefix) === 0) return true;", "chartLoadBusy matches a prefix (per-row keys)")
	must("chartLoadBusy: chartLoadBusy,", "exported")
	must("chartLoadCancel: chartLoadCancel,", "exported")
	must("(opts.dim === false ? ' fwmon-chart-notice-plain' : '')", "a notice over a table does not dim its rows")
	close := funcBody(t, js, `function closeModal\(modalId\)`)
	ev := strings.Index(close, "new CustomEvent('fwmon:modalclose'")
	early := strings.Index(close, "if (!record) return;")
	if ev < 0 || early < 0 || ev > early {
		t.Error("closeModal must dispatch fwmon:modalclose before its early return, so every close stops the dialog's load")
	}
}

func TestFilterLoad_RestoreMechanics(t *testing.T) {
	js := readJS(t, "admin-controls.js")
	mustContain(t, "admin-controls.js", js, "d.onChange(state, prev);", "the loader receives the previous committed query for its Cancel branch")
	mustContain(t, "admin-controls.js", js, "restore:  restore,", "restore is exported")
	body := funcBody(t, js, `function restore\(snap\)`)
	if strings.Contains(body, "onChange(") {
		t.Error("restore must not call onChange — it puts the old query back WITHOUT loading it")
	}
	if !strings.Contains(body, "repaint();") {
		t.Error("restore must repaint the inputs, chips and URL")
	}

	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	sup := strings.Index(run, "if (r.superseded) return;")
	rest := strings.Index(run, "analyticsPages[page].restore(opts.prev)")
	if sup < 0 || rest < 0 || sup > rest {
		t.Error("runFilterLoad must return on a superseded load before the Cancel restore")
	}
	if strings.Index(run, "onOK(r.data);") < rest {
		t.Error("onOK must run only after the cancel/error branches")
	}
	mustContain(t, "admin-main.js", run, "if (AC.chartLoadBusy(loadKey)) return Promise.resolve();", "a poll skips while the user's load runs")
	mustContain(t, "admin-main.js", run, "if (filterGen[key] !== gen || !data) return;", "a poll in flight when the user starts a load is dropped")
	for _, page := range []string{"loadSyslog", "loadAlerts", "loadTraps", "loadAuditLogs"} {
		mustContain(t, "admin-main.js", main, "onChange: function(state, prev) { "+page+"({ prev: prev }); }", "the filter change hands the previous query to the loader")
	}
	mustContain(t, "admin-main.js", main, "loadSyslog({ fromPoll: true });", "the syslog auto-refresh is a silent poll")
}

// Offsets and selection change only in the success branch — onOK, which starts
// at the loader's second function argument. Before it, a cancelled Prev/Next
// would move the pager to a page that is not on screen.
func TestFilterLoad_StateOnlyOnSuccess(t *testing.T) {
	main := readJS(t, "admin-main.js")
	cases := []struct{ sig, state string }{
		{`function loadSyslog\(opts\)`, "syslogOffset ="},
		{`function syslogPage\(target\)`, "syslogOffset ="},
		{`function auditPage\(target, prev\)`, "auditOffset ="},
		{`function loadAlerts\(opts\)`, "alertsOffset ="},
		{`function loadAlerts\(opts\)`, "clearAlertSelection();"},
		{`function alertsPage\(target\)`, "alertsOffset ="},
		{`function refreshAlertsAtCurrentPage\(\)`, "alertsOffset ="},
		{`function loadTraps\(opts\)`, "trapsOffset ="},
		{`function loadMoreTraps\(\)`, "trapsOffset ="},
	}
	for _, c := range cases {
		body := funcBody(t, main, c.sig)
		ok := regexp.MustCompile(`\}, function\((result|got)\) \{`).FindStringIndex(body)
		if ok == nil {
			t.Fatalf("%s: no success callback found", c.sig)
		}
		if !strings.Contains(body, c.state) {
			t.Errorf("%s no longer contains %q", c.sig, c.state)
		}
		for i := strings.Index(body, c.state); i >= 0; {
			if i < ok[0] {
				t.Errorf("%s assigns %q before the success branch", c.sig, c.state)
				break
			}
			n := strings.Index(body[i+1:], c.state)
			if n < 0 {
				break
			}
			i += 1 + n
		}
	}
	for _, sig := range []string{`function prevSyslog\(\)`, `function nextSyslog\(\)`, `function prevAlerts\(\)`, `function nextAlerts\(\)`} {
		if regexp.MustCompile(`Offset\s*[-+]?=[^=]`).MatchString(funcBody(t, main, sig)) {
			t.Errorf("%s changes the offset itself; the page loader does it when the page arrives", sig)
		}
	}
	for _, dead := range []string{"loadMoreSyslog", "loadMoreAlerts", "load-more-syslog", "load-more-alerts"} {
		if strings.Contains(main, dead) {
			t.Errorf("admin-main.js still references %s (dead: no element ever emitted it)", dead)
		}
	}

	ti := readJS(t, "admin-threatintel.js")
	search := funcBody(t, ti, `function runSearch\(offset\)`)
	if strings.Index(search, "searchOffset = target;") < strings.Index(search, "if (r.error) {") {
		t.Error("runSearch sets searchOffset before the result is known")
	}
	mustContain(t, "admin-threatintel.js", search, "if (lastSearch) setSearchControls(lastSearch);", "Cancel puts the shown search back in the controls")

	er := readJS(t, "admin-event-rules.js")
	lr := funcBody(t, er, `function loadRules\(profileId, filter\)`)
	okAt := strings.Index(lr, "rules = (r.data && r.data.data) || [];")
	for _, st := range []string{"currentProfileId = pid;", "currentRuleFilter = nextFilter;", "groupCollapsed = {};"} {
		if i := strings.Index(lr, st); i < 0 || i > okAt || i < strings.Index(lr, "if (r.error) {") {
			t.Errorf("loadRules must assign %q only in the success branch", st)
		}
	}
	mustContain(t, "admin-event-rules.js", lr, "return { ok: true };", "consumers act only on a load that succeeded")
	ep := readJS(t, "admin-event-profiles.js")
	if n := strings.Count(ep, "window.FwmonEventRules.loadRules(0).then(function (lr) {\n"); n != 2 {
		t.Errorf("both loadRules consumers must take the result; found %d", n)
	}
	if n := strings.Count(ep, "if (!lr || !lr.ok) return;"); n != 2 {
		t.Errorf("both loadRules consumers must return unless ok; found %d", n)
	}
}

// Each surface has its own explicit key, passes the abort signal, and is silent
// when superseded.
func TestFilterLoad_Surfaces(t *testing.T) {
	cases := []struct {
		file string
		subs []string
	}{
		{"admin-threatintel.js", []string{"key: 'ti-lookup'", "key: 'ti-search'", "{ signal: signal }"}},
		{"admin-flows.js", []string{"key: 'flows-samples'", "key: 'flows-detections'", "AC.apiFetch(url, { signal: signal })"}},
		{"admin-reports.js", []string{"key: 'report-preview'", "AC.apiFetch(url, { signal: signal })", "if (r.superseded) return;"}},
		{"diagram-panels.js", []string{"AC.chartLoadCancel('panel-');", "'panel-traffic-' + connId", "'panel-flows-' + connId", "'panel-events-' + connId",
			"'panel-iface-' + rowId", "'panel-tunnel-' + rowId", "window.apiFetch(url, { signal: signal })", "if (r.superseded) return null;"}},
		{"admin-connection-detail.js", []string{"'cd-traffic'", "'cd-flows'", "'cd-group-' + canvasId", "AC.apiFetch(url, { signal: signal })",
			"if (r.superseded) return null;", "loadTrafficChart({ fromPoll: true })", "loadFlowStats({ fromPoll: true })"}},
		{"admin-device-detail.js", []string{"key: 'config-diff'", "signal: signal })", "if (!modal.classList.contains('active')) return;",
			"if (e.target && e.target.id === 'config-diff-modal') AC.chartLoadCancel('config-diff');"}},
		{"admin-event-profiles.js", []string{"key: 'ep-effective'", "{ signal: signal }", "if (r.superseded) return;"}},
		{"admin-event-rules.js", []string{"key: 'event-rules'", "{ signal: signal }", "if (r.superseded) return { cancelled: true, superseded: true };"}},
	}
	for _, c := range cases {
		js := readJS(t, c.file)
		for _, s := range c.subs {
			mustContain(t, c.file, js, s, "loading/Cancel contract for this surface")
		}
	}

	main := readJS(t, "admin-main.js")
	for _, k := range []string{"'threat-intel': ['ti-']", "flows: ['flows-']", "reports: ['report-']", "connections: ['panel-']", "'event-rules': ['event-rules', 'ep-']", "syslog: ['filter-syslog']"} {
		mustContain(t, "admin-main.js", main, k, "leaving the page stops its loads silently")
	}
}

// Connection detail's 30 s poll must neither cancel nor overwrite a load the
// user started.
func TestFilterLoad_ConnectionDetailPolls(t *testing.T) {
	js := readJS(t, "admin-connection-detail.js")
	body := funcBody(t, js, `function cdLoad\(key, host, url, opts\)`)
	busy := strings.Index(body, "if (opts.fromPoll && AC.chartLoadBusy(key)) return Promise.resolve(null);")
	gen := strings.Index(body, "var gen = loadGen[key] = (loadGen[key] || 0) + 1;")
	if busy < 0 || gen < 0 || busy > gen {
		t.Error("a poll must check busy BEFORE bumping the generation (bumping first would drop the user's own result)")
	}
	if strings.Count(body, "loadGen[key] === gen") != 2 {
		t.Error("both the poll and the user path must drop a response that is no longer the newest")
	}
	mustContain(t, "admin-connection-detail.js", js, "if (!groupHostHeld('src-tunnel-charts')) renderTunnelCharts(", "the poll does not rebuild a host whose chart is loading or shows a notice")
	mustContain(t, "admin-connection-detail.js", js, "if (!groupHostHeld('dst-tunnel-charts')) renderTunnelCharts(", "same for the destination side")
	mustContain(t, "admin-connection-detail.js", js, "return AC.chartLoadBusy('cd-group-' + hostId) ||", "held = a prefix-busy group chart")
	mustContain(t, "admin-connection-detail.js", js, "if (gk) groupRanges[gk] = prevRange;", "a cancelled group range is not re-applied by the next poll")
	mustContain(t, "admin-connection-detail.js", js, "loadTrafficChart({ onCancel: function() { applyTrafficRange(prev); } });", "a cancelled traffic range is put back")
	mustContain(t, "admin-connection-detail.js", js, "loadFlowStats({ onCancel: function() { applyFlowRange(prev); } });", "a cancelled flows range is put back")
}

// The connection-map panel's empty flows result used to REPLACE the flows
// markup, so every later range change wrote into elements that no longer
// existed.
func TestFilterLoad_PanelEmptyFlowsKeepsMarkup(t *testing.T) {
	js := readJS(t, "diagram-panels.js")
	body := funcBody(t, js, `async function loadPanelFlowStats\(connId, hours, prevPill\)`)
	if strings.Contains(body, "content.innerHTML") {
		t.Error("an empty flows result must hide #panel-flow-content, not replace its markup")
	}
	mustContain(t, "diagram-panels.js", body, "if (content) content.hidden = !hasData;", "the content comes back on the next non-empty result")
	mustContain(t, "diagram-panels.js", body, "delete panelChartInstances[k];", "the charts are dropped so the tab reloads them")
	mustContain(t, "diagram-panels.js", body, "if (!data || currentPanelConnId !== connId) return;", "a result for a panel since closed or replaced is dropped")
}

// The overlay covers results only: never the filter bar, the controls row or a
// modal header, which must stay usable (and hold Cancel's alternatives).
func TestFilterLoad_HostsNeverWrapControls(t *testing.T) {
	for _, page := range []string{"admin.html", "connection-detail.html", "device-detail.html"} {
		html := readFile(t, "../../web/admin/"+page)
		for _, m := range regexp.MustCompile(`<div[^>]*class="[^"]*\bfwmon-load-host\b[^"]*"[^>]*>`).FindAllStringIndex(html, -1) {
			inner := elementInner(html, m[0])
			for _, ctl := range []string{"filter-bar", "fwmon-flows-filter-row", "modal-header", "<select", "range-pill"} {
				if strings.Contains(inner, ctl) {
					t.Errorf("%s: a .fwmon-load-host at byte %d contains %q — the overlay would cover the controls", page, m[0], ctl)
				}
			}
			// Row checkboxes (select-all) belong to the results; any other
			// input is a filter control.
			for _, in := range regexp.MustCompile(`<input[^>]*>`).FindAllString(inner, -1) {
				if !strings.Contains(in, `type="checkbox"`) {
					t.Errorf("%s: a .fwmon-load-host at byte %d contains the control %s", page, m[0], in)
				}
			}
		}
	}
	html := readFile(t, "../../web/admin/admin.html")
	for _, id := range []string{"syslog-load-host", "alerts-load-host", "traps-load-host", "audit-load-host", "ti-search-host", "flows-samples-host",
		"syslog-charts-host", "alerts-charts-host", "traps-charts-host", "report-host", `id="event-rules-table-wrap" class="fwmon-load-host"`} {
		if !strings.Contains(html, id) {
			t.Errorf("admin.html is missing the load host %q", id)
		}
	}
	mustContain(t, "admin.html", html, ".panel-chart-container { position: relative; }", "per-row panel chart overlays need a positioned container")
}

// elementInner returns the markup between the <div> opening at start and its
// matching </div>.
func elementInner(html string, start int) string {
	depth := 0
	re := regexp.MustCompile(`<div\b|</div>`)
	for _, m := range re.FindAllStringIndex(html[start:], -1) {
		if html[start+m[0]:start+m[1]] == "</div>" {
			depth--
			if depth == 0 {
				return html[start : start+m[0]]
			}
		} else {
			depth++
		}
	}
	return html[start:]
}
