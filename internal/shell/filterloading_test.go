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
	rest := strings.Index(run, "if (back && ap && ap.restore && !siblingBusy()) ap.restore(back);")
	if sup < 0 || rest < 0 || sup > rest {
		t.Error("runFilterLoad must return on a superseded load before the Cancel restore")
	}
	if strings.Index(run, "onOK(r.data);") < rest {
		t.Error("onOK must run only after the cancel/error branches")
	}
	// Which query a Cancel restores: the one whose results are on screen,
	// recorded on success — not the last committed one, which may have been
	// superseded or failed and never displayed (fresh review, HIGH).
	mustContain(t, "admin-main.js", run, "var back = shownQuery[page] || opts.prev;", "Cancel restores the SHOWN query")
	if n := strings.Count(run, "if (want) shownQuery[page] = want;"); n != 2 {
		t.Errorf("the shown query must be recorded on BOTH success paths (user load and poll); found %d", n)
	}
	if !strings.Contains(run, "if (want) shownQuery[page] = want;\n            onOK(r.data);") {
		t.Error("the shown query is recorded in the success branch, right before onOK")
	}
	mustContain(t, "admin-main.js", run, "if (AC.chartLoadBusy(loadKey)) return Promise.resolve();", "a poll skips while the user's load runs")
	mustContain(t, "admin-main.js", run, "if (filterGen[key] !== gen || !data) return;", "a poll in flight when the user starts a load is dropped")
	for _, page := range []string{"loadSyslog", "loadAlerts", "loadTraps", "loadAuditLogs"} {
		mustContain(t, "admin-main.js", main, "onChange: function(state, prev) { "+page+"({ prev: prev }); }", "the filter change hands the previous query to the loader")
	}
	mustContain(t, "admin-main.js", main, "loadSyslog({ fromPoll: true });", "the syslog auto-refresh is a silent poll")
}

// Cancel puts the controls back to the previous query, so a Retry that simply
// reloaded from the controls would fetch the OLD results (found in the browser
// check). Every surface re-applies the cancelled query before retrying.
func TestFilterLoad_RetryAfterCancelReappliesQuery(t *testing.T) {
	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "if (want && ap.restore && !siblingBusy()) ap.restore(want);", "Retry re-applies the cancelled query")
	mustContain(t, "admin-main.js", run, "onRetry: retryCancelled", "the Cancel notice uses that Retry")
	mustContain(t, "admin-main.js", run, "var want = (ap && ap.getState) ? ap.getState() : null;", "the requested query is captured when the load starts")
	mustContain(t, "admin-threatintel.js", readJS(t, "admin-threatintel.js"), "onRetry: function() { setSearchControls(query); runSearch(target); }", "threat-intel Retry re-applies the cancelled search")
	mustContain(t, "admin-reports.js", readJS(t, "admin-reports.js"), "if (sel) sel.value = want.period;", "reports Retry re-applies the cancelled period")
	mustContain(t, "diagram-panels.js", readJS(t, "diagram-panels.js"), "again = () => { activatePill(wantPill); retry(); };", "panel Retry re-activates the cancelled range's pill")
	mustContain(t, "admin-event-rules.js", readJS(t, "admin-event-rules.js"), "if (wrap && wrap.offsetParent) syncRuleFilterChips();", "the chips follow the filter that loaded")
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
			"if (!e.target || e.target.id !== 'config-diff-modal') return;\n        AC.chartLoadCancel('config-diff');\n        updateConfigCompareButton();"}},
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
	if !strings.Contains(body, "if (loadGen[key] !== gen) return null;") || !strings.Contains(body, "return loadGen[key] === gen ? r.data : null;") {
		t.Error("both the poll and the user path must drop a response that is no longer the newest")
	}
	mustContain(t, "admin-connection-detail.js", js, "if (!groupHostHeld('src-tunnel-charts')) renderTunnelCharts(", "the poll does not rebuild a host whose chart is loading or shows a notice")
	mustContain(t, "admin-connection-detail.js", js, "if (!groupHostHeld('dst-tunnel-charts')) renderTunnelCharts(", "same for the destination side")
	mustContain(t, "admin-connection-detail.js", js, "return !!host && AC.chartLoadBusy('cd-group-' + hostId);", "held = a prefix-busy group chart (a notice alone does not freeze the refresh)")
	// Cancel restores the range whose data is on screen, recorded on success.
	mustContain(t, "admin-connection-detail.js", js, "var shown = shownGroupRanges[gk] || '24h';", "a cancelled group range goes back to the drawn one")
	mustContain(t, "admin-connection-detail.js", js, "if (gk) shownGroupRanges[gk] = range;", "the drawn group range is recorded on success")
	mustContain(t, "admin-connection-detail.js", js, "if (shownTrafficRange !== null) applyTrafficRange(shownTrafficRange);", "a cancelled traffic range goes back to the drawn one")
	mustContain(t, "admin-connection-detail.js", js, "if (!result) return;\n            shownTrafficRange = range;", "the drawn traffic range is recorded on success")
	mustContain(t, "admin-connection-detail.js", js, "if (shownFlowHours !== null) applyFlowRange(shownFlowHours);", "a cancelled flows range goes back to the drawn one")
	mustContain(t, "admin-connection-detail.js", js, "if (!result) return;\n            shownFlowHours = hours;", "the drawn flows range is recorded on success")
}

// The connection-map panel's empty flows result used to REPLACE the flows
// markup, so every later range change wrote into elements that no longer
// existed.
func TestFilterLoad_PanelEmptyFlowsKeepsMarkup(t *testing.T) {
	js := readJS(t, "diagram-panels.js")
	body := funcBody(t, js, `async function loadPanelFlowStats\(connId, hours\)`)
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

// Panel pills, hidden loads and a cancelled profile switch (fresh review,
// HIGH/MEDIUM): each Cancel puts back what is actually drawn.
func TestFilterLoad_CancelRestoresWhatIsShown(t *testing.T) {
	dp := readJS(t, "diagram-panels.js")
	pl := funcBody(t, dp, `function panelLoad\(key, host, url, pillsBox, retry\)`)
	mustContain(t, "diagram-panels.js", pl, "const shown = pillsBox ? shownPills.get(pillsBox) : null;", "Cancel re-activates the pill whose data is drawn")
	mustContain(t, "diagram-panels.js", pl, "if (active) shownPills.set(pillsBox, active);", "the drawn pill is recorded on success")
	if strings.Index(pl, "shownPills.set(") < strings.Index(pl, "if (r.error) {") {
		t.Error("the drawn pill must be recorded only in the success branch")
	}

	fl := readJS(t, "admin-flows.js")
	sl := funcBody(t, fl, `function samplesLoad\(offset, append\)`)
	mustContain(t, "admin-flows.js", sl, "var host = mounted.appendChild ? mounted : null;", "a hidden samples load puts no notice on the host")

	er := readJS(t, "admin-event-rules.js")
	lr := funcBody(t, er, `function loadRules\(profileId, filter\)`)
	sw := strings.Index(lr, "if (pid !== currentProfileId) {")
	ph := strings.Index(lr, "Rules for this profile were not loaded.")
	if sw < 0 || ph < 0 || ph < sw || ph > strings.Index(lr, "targetProfileId = null;") {
		t.Error("a cancelled profile switch must replace the old profile's rows (and keep targetProfileId) before clearing the target")
	}
}

// Second fresh review: reloads follow the VIEWED profile, titles change with
// the data, polls clear stale notices, Load more cannot mix filters, and the
// config-diff Compare button is re-enabled before the closed-modal return.
func TestFilterLoad_ReviewRound2(t *testing.T) {
	er := readJS(t, "admin-event-rules.js")
	if strings.Contains(er, "loadRules(currentProfileId, currentRuleFilter)") {
		t.Error("save/delete must reload the viewed profile (viewedProfileId), not the last loaded one")
	}
	if n := strings.Count(er, "loadRules(viewedProfileId(), currentRuleFilter)"); n != 2 {
		t.Errorf("both save and delete reload the viewed profile; found %d", n)
	}

	main := readJS(t, "admin-main.js")
	for _, c := range []struct{ sig, title string }{
		{`function loadAlertCharts\(\)`, "chartTitle.textContent = 'Alert Trend ('"},
		{`function loadTrapCharts\(\)`, "chartTitle.textContent = 'Trap Frequency ('"},
	} {
		body := funcBody(t, main, c.sig)
		ok := strings.Index(body, "}, function(result) {")
		if i := strings.Index(body, c.title); i < 0 || ok < 0 || i < ok {
			t.Errorf("%s must set its title in the success branch (a cancelled load would name an undrawn range)", c.sig)
		}
	}
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "if (host) AC.chartNoticeClear(host);", "a poll's fresh rows clear a stale Cancel notice")
	mustContain(t, "admin-main.js", run, "shownQuery[page] ? 'Cancelled — showing the previous results' : 'Cancelled'", "a first-load Cancel does not claim previous results")
	mustContain(t, "admin-common.js", readJS(t, "admin-common.js"), "chartNoticeClear: clearChartNotice,", "exported")

	fl := readJS(t, "admin-flows.js")
	mustContain(t, "admin-flows.js", funcBody(t, fl, `function loadMoreSamples\(\)`), "AC.chartLoadBusy('flows-samples')) return;", "Load more waits for a pending reload")

	dd := readJS(t, "admin-device-detail.js")
	od := funcBody(t, dd, `function openConfigDiff\(fromID, toID\)`)
	upd := strings.Index(od, "updateConfigCompareButton();")
	act := strings.Index(od, "if (!modal.classList.contains('active')) return;")
	if upd < 0 || act < 0 || upd > act {
		t.Error("Compare must be re-enabled BEFORE the closed-modal return, or closing mid-load leaves it disabled")
	}
}

// Third fresh review: failed switches, charts-vs-table restores, connection
// detail polls, and the remaining Cancel/Retry surfaces.
func TestFilterLoad_ReviewRound3(t *testing.T) {
	er := readJS(t, "admin-event-rules.js")
	lr := funcBody(t, er, `function loadRules\(profileId, filter\)`)
	errAt := strings.Index(lr, "if (r.error) {")
	// The error branch ends where the success path begins (its own clear of
	// targetProfileId is not part of the error path).
	errEnd := strings.Index(lr[errAt:], "targetProfileId = null;\n            if (pid !== currentProfileId) groupCollapsed")
	if errAt < 0 || errEnd < 0 {
		t.Fatal("loadRules error/success boundary not found")
	}
	errBody := lr[errAt : errAt+errEnd]
	sw := strings.Index(errBody, "if (pid !== currentProfileId) {")
	clr := strings.Index(errBody, "targetProfileId = null;\n                if (wrap) AC.chartNotice(wrap, 'Could not load results'")
	if sw < 0 || clr < 0 || clr < sw {
		t.Error("a FAILED profile switch must keep targetProfileId (the viewed profile) — clear it only after the switch branch")
	}
	// Exactly two clears on the error path: the 403 placeholder and the
	// same-profile error. Any other would drop the viewed profile on a
	// failed switch.
	if n := strings.Count(errBody, "targetProfileId = null;"); n != 2 {
		t.Errorf("the error path clears targetProfileId %d times; want 2 (403 placeholder, same-profile error)", n)
	}

	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "function siblingBusy() { return key !== page && AC.chartLoadBusy('filter-' + page); }", "a charts load never restores over a running table load")
	mustContain(t, "admin-main.js", run, "if (want && ap.restore && !siblingBusy()) ap.restore(want);", "nor does its Retry")
	mustContain(t, "admin-main.js", run, "if (back && ap && ap.restore && !siblingBusy()) ap.restore(back);", "the Cancel branch")

	cd := readJS(t, "admin-connection-detail.js")
	body := funcBody(t, cd, `function cdLoad\(key, host, url, opts\)`)
	mustContain(t, "admin-connection-detail.js", body, "if (host) AC.chartNoticeClear(host);", "a poll's fresh data clears a stale notice")
	mustContain(t, "admin-connection-detail.js", body, "opts.hadResult ? 'Cancelled — showing the previous results' : 'Cancelled'", "a first-load Cancel does not claim previous results")

	mustContain(t, "admin-flows.js", readJS(t, "admin-flows.js"), "AC.chartNotice(noticeHost, 'Cancelled — showing the previous results', { dim: false, onRetry: loadDetections });", "detections Cancel has a notice and Retry")
	mustContain(t, "admin-threatintel.js", readJS(t, "admin-threatintel.js"), "el('ti-lookup-q').value = q; // re-apply the cancelled lookup", "lookup Retry re-runs the cancelled lookup")

	dd := readJS(t, "admin-device-detail.js")
	od := funcBody(t, dd, `function openConfigDiff\(fromID, toID\)`)
	if strings.Index(od, "if (r.superseded) return;") > strings.Index(od, "updateConfigCompareButton();") {
		t.Error("a superseded diff load must not re-enable Compare while the newer load runs")
	}
	mustContain(t, "admin-event-profiles.js", readJS(t, "admin-event-profiles.js"), "// Nothing is displayed yet, so a cancelled lookup clears the pickers.\n            effShown = { device: '', site: '' };", "nothing is displayed on render, so nothing is 'shown'")
}

// Fourth fresh review: Esc with any dialog open, Traps Load more during a
// reload, hidden rule lookups, and first-load Cancel leftovers.
func TestFilterLoad_ReviewRound4(t *testing.T) {
	ac := readJS(t, "admin-common.js")
	mustContain(t, "admin-common.js", ac, "if (Object.keys(__fwmonOpenModals).length) return;", "any open dialog owns Esc, even with focus on <body>")
	main := readJS(t, "admin-main.js")
	lmt := funcBody(t, main, `function loadMoreTraps\(\)`)
	if i := strings.Index(lmt, "if (AC.chartLoadBusy('filter-traps')) return;"); i < 0 || i > strings.Index(lmt, "runFilterLoad(") {
		t.Error("Traps Load more must wait for a running filter reload")
	}
	mustContain(t, "admin-event-rules.js", readJS(t, "admin-event-rules.js"), "if (wrap && wrap.offsetParent) syncRuleFilterChips();", "a hidden lookup does not reset the user's chip")
	mustContain(t, "admin-design-system.css", readFile(t, "../../cmd/api/static/css/admin-design-system.css"), ".fwmon-load-host:has(> .fwmon-chart-notice) { min-height: 120px; }", "a first-load notice gets room")
	mustContain(t, "admin-event-profiles.js", readJS(t, "admin-event-profiles.js"), "if (!had) out.innerHTML = '';", "no Resolving… left behind")
	mustContain(t, "diagram-panels.js", readJS(t, "diagram-panels.js"), "if (!container.querySelector('table') && !AC.chartLoadBusy('panel-events-' + connId)) {", "no Loading events… left behind")
}
