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
	sup := strings.Index(run, "if (r.superseded) return { superseded: true };")
	rest := strings.Index(run, "if (back && apC && apC.restore && !siblingBusy()) restoreQuery(apC, page, back);")
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
	if n := strings.Count(run, "if (want && key === page) shownQuery[page] = want;"); n != 2 {
		t.Errorf("the shown query must be recorded on BOTH success paths (user load and poll); found %d", n)
	}
	if !strings.Contains(run, "if (want && key === page) shownQuery[page] = want;\n            onOK(r.data);") {
		t.Error("the shown query is recorded in the success branch, right before onOK")
	}
	mustContain(t, "admin-main.js", run, "if (AC.chartLoadBusy(loadKey)) return Promise.resolve();", "a poll skips while the user's load runs")
	mustContain(t, "admin-main.js", run, "if (filterGen[key] !== gen || !data) return;", "a poll in flight when the user starts a load is dropped")
	for _, page := range []string{"loadSyslog", "loadAlerts", "loadTraps", "loadAuditLogs"} {
		mustContain(t, "admin-main.js", main, "onChange: function(state, prev) { "+page+"({ prev: prev, state: state }); }", "the filter change hands the previous query AND its own state to the loader (the handle does not exist yet on a first load)")
	}
	mustContain(t, "admin-main.js", main, "loadSyslog({ fromPoll: true });", "the syslog auto-refresh is a silent poll")
}

// Cancel puts the controls back to the previous query, so a Retry that simply
// reloaded from the controls would fetch the OLD results (found in the browser
// check). Every surface re-applies the cancelled query before retrying.
func TestFilterLoad_RetryAfterCancelReappliesQuery(t *testing.T) {
	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "var ap = apNow(); if (want && ap && ap.restore && !siblingBusy()) restoreQuery(ap, page, want);", "Retry re-applies the cancelled query")
	mustContain(t, "admin-main.js", run, "onRetry: retryCancelled", "the Cancel notice uses that Retry")
	mustContain(t, "admin-main.js", run, "var src = opts.snap || opts.state || ((ap0 && ap0.getState) ? ap0.getState() : null);", "the requested query is captured when the load starts, even on a first load")
	mustContain(t, "admin-threatintel.js", readJS(t, "admin-threatintel.js"), "var retry = function() { if (!paging) setSearchControls(query); runSearch(target, paging ? query : undefined); };", "threat-intel Retry re-applies the cancelled search")
	mustContain(t, "admin-reports.js", readJS(t, "admin-reports.js"), "function retryWanted() { applyChoices(want); loadPreview(); }", "reports Retry re-applies the cancelled period")
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
		{`function auditPage\(target, prev, st, paging\)`, "auditOffset ="},
		{`function loadAlerts\(opts\)`, "alertsOffset ="},
		{`function loadAlerts\(opts\)`, "clearAlertSelection();"},
		{`function alertsPage\(target\)`, "alertsOffset ="},
		{`function refreshAlertsAtCurrentPage\(opts\)`, "alertsOffset ="},
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
	search := funcBody(t, ti, `function runSearch\(offset, snap\)`)
	if strings.Index(search, "searchOffset = target;") < strings.Index(search, "if (r.error) {") {
		t.Error("runSearch sets searchOffset before the result is known")
	}
	mustContain(t, "admin-threatintel.js", search, "if (lastSearch && !paging) setSearchControls(lastSearch);", "Cancel puts the shown search back in the controls")

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
	if n := strings.Count(ep, "if (!lr || !lr.ok) return;") + strings.Count(ep, "if (!lr || !lr.ok) {\n                            window.FwmonEventRules.keepPendingPrefill(pending);"); n != 2 {
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
		{"admin-event-rules.js", []string{"key: 'event-rules'", "{ signal: signal }", "                    rulesReloadDeferred = false; // the page reloads its rules on return\n                }\n                return { cancelled: true, superseded: true };"}},
	}
	for _, c := range cases {
		js := readJS(t, c.file)
		for _, s := range c.subs {
			mustContain(t, c.file, js, s, "loading/Cancel contract for this surface")
		}
	}

	main := readJS(t, "admin-main.js")
	for _, k := range []string{"'threat-intel': ['ti-']", "flows: ['flows-']", "reports: ['report-']", "'event-rules': ['event-rules', 'ep-']", "syslog: ['filter-syslog']"} {
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
	if sw < 0 || ph < 0 || ph < sw || ph > strings.Index(lr, "targetProfileId = null;\n                syncRuleFilterChips();") {
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
	clr := strings.Index(errBody, "targetProfileId = null;\n                syncRuleFilterChips(); // the chips name the filter whose rows are shown")
	if sw < 0 || clr < 0 || clr < sw {
		t.Error("a FAILED profile switch must keep targetProfileId (the viewed profile) — clear it only after the switch branch")
	}
	// Exactly two clears on the error path: the 403 placeholder and the
	// same-profile error. Any other would drop the viewed profile on a
	// failed switch.
	if n := strings.Count(errBody, "targetProfileId = null;"); n != 3 {
		t.Errorf("the error path clears targetProfileId %d times; want 3 (403 placeholder, hidden lookup, same-profile error)", n)
	}

	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "function siblingBusy() { return key !== page && AC.chartLoadBusy('filter-' + page, true); }", "a charts load never restores over a running table load")
	mustContain(t, "admin-main.js", run, "var ap = apNow(); if (want && ap && ap.restore && !siblingBusy()) restoreQuery(ap, page, want);", "nor does its Retry")
	mustContain(t, "admin-main.js", run, "if (back && apC && apC.restore && !siblingBusy()) restoreQuery(apC, page, back);", "the Cancel branch")

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
	if i := strings.Index(lmt, "if (AC.chartLoadBusy('filter-traps', true)) return;"); i < 0 || i > strings.Index(lmt, "runFilterLoad(") {
		t.Error("Traps Load more must wait for a running filter reload")
	}
	mustContain(t, "admin-event-rules.js", readJS(t, "admin-event-rules.js"), "if (wrap && wrap.offsetParent) syncRuleFilterChips();", "a hidden lookup does not reset the user's chip")
	mustContain(t, "admin-design-system.css", readFile(t, "../../cmd/api/static/css/admin-design-system.css"), ".fwmon-load-host:has(> .fwmon-chart-notice) { min-height: 120px; }", "a first-load notice gets room")
	mustContain(t, "admin-event-profiles.js", readJS(t, "admin-event-profiles.js"), "if (!had) out.innerHTML = '';", "no Resolving… left behind")
	mustContain(t, "diagram-panels.js", readJS(t, "diagram-panels.js"), "if (!container.dataset.loaded && !AC.chartLoadBusy('panel-events-' + connId)) {", "no Loading events… left behind")
}

// Fifth fresh review: the modal's capture-phase Esc handler closes the dialog
// (emptying the registry) BEFORE chartLoad's handler runs, so the registry
// check alone was dead; defaultPrevented is what survives. Behaviour is
// verified in the browser check; these pin the lines.
func TestFilterLoad_ReviewRound5(t *testing.T) {
	ac := readJS(t, "admin-common.js")
	on := funcBody(t, ac, `function onKey\(e\)`)
	dp := strings.Index(on, "if (e.defaultPrevented) return;")
	if dp < 0 || dp > strings.Index(on, "cancel();") {
		t.Error("chartLoad's Esc handler must bail on defaultPrevented before cancelling")
	}
	mustContain(t, "admin-common.js", ac, "if (exact) return false;", "an exact-key busy check")
	fl := readJS(t, "admin-flows.js")
	if i := strings.Index(fl, "if (e.defaultPrevented) return; // a dialog's Esc"); i < 0 || i > strings.Index(fl, "cancelStatsLoad();\n            });") {
		t.Error("the flows stats Esc handler must bail on defaultPrevented")
	}
	mustContain(t, "diagram-panels.js", readJS(t, "diagram-panels.js"), "container.dataset.loaded = '1';", "an empty result counts as shown")
}

// Sixth review (Opus 5.5 — Fable was rate-limited): every navigation path
// stops other pages' loads, Load more follows the shown query, Show snoozed
// travels with the query, hidden lookups report errors visibly, and Cancel
// does not blur a pending edit.
func TestFilterLoad_ReviewRound6(t *testing.T) {
	main := readJS(t, "admin-main.js")
	if n := strings.Count(main, "cancelOtherPageLoads(page);\n"); n != 4 {
		t.Errorf("cancelOtherPageLoads must run on loadPageData and all three reseedFromURL paths; found %d calls", n)
	}
	for _, re := range []string{"cancelOtherPageLoads(page);\n                analyticsPages[page].reseedFromURL();", "cancelOtherPageLoads(page);\n            analyticsPages[page].reseedFromURL();"} {
		if !strings.Contains(main, re) {
			t.Errorf("a reseedFromURL path does not cancel other pages' loads first: %q", re)
		}
	}
	mustContain(t, "admin-main.js", main, "if (want && PAGE_EXTRAS[page] && want.__extra === undefined) want.__extra = PAGE_EXTRAS[page].get();", "Show snoozed is part of the query snapshot")
	mustContain(t, "admin-main.js", main, "if (PAGE_EXTRAS[page] && snap && snap.__extra !== undefined) PAGE_EXTRAS[page].set(snap.__extra);", "and restored with it")

	ac := readJS(t, "admin-common.js")
	on := funcBody(t, ac, `function onKey\(e\)`)
	mustContain(t, "admin-common.js", on, "if (!list.some(function(c) { return c.getClientRects().length; })) return;", "Esc never cancels a load whose results are not rendered")
	mustContain(t, "admin-common.js", ac, "cancelBtn.addEventListener('mousedown', function(ev) { ev.preventDefault(); });", "pressing Cancel does not blur a pending edit")

	fl := readJS(t, "admin-flows.js")
	sl := funcBody(t, fl, `function samplesLoad\(offset, append\)`)
	mustContain(t, "admin-flows.js", sl, "var url = samplesURL(100, offset, append ? shownSamplesState : null);", "Load more continues the SHOWN rows' query")
	if i := strings.Index(sl, "if (!append) shownSamplesState = want;"); i < 0 || i < strings.Index(sl, "if (r.error || !r.data) {") {
		t.Error("the shown samples query is recorded only on success")
	}
	su := funcBody(t, fl, `function samplesURL\(limit, offset, st\)`)
	if regexp.MustCompile(`\bstate\.`).MatchString(su) {
		t.Error("samplesURL must read only st (the passed query), never the live state directly")
	}

	er := readJS(t, "admin-event-rules.js")
	lr := funcBody(t, er, `function loadRules\(profileId, filter\)`)
	hid := strings.Index(lr, "if (!(wrap && wrap.offsetParent)) {\n                    // A hidden lookup")
	toast := strings.Index(lr, "AC.showError('Failed to load event rules: ' + err.message);")
	if hid < 0 || toast < hid || toast > strings.Index(lr, "if (pid !== currentProfileId) {\n                    // A failed profile switch") {
		t.Error("a hidden lookup's error must be shown as a toast (its table is not on screen)")
	}
	mustContain(t, "admin.html", readFile(t, "../../web/admin/admin.html"), `id="report-host" style="padding:6px;overflow:clip;">`, "overflow:clip keeps the sticky Cancel box working (hidden made the card its scroll container)")
}

// Seventh review (Opus 5.5): an error restores like Cancel, a filter change
// drops "select all matching", restore drops pending debounced edits, Flows
// says plainly which rows the list shows, and the remaining surfaces.
func TestFilterLoad_ReviewRound7(t *testing.T) {
	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	errAt := strings.Index(run, "if (r.error || !r.data) {")
	rest := strings.Index(run, "if (shown && apE && apE.restore && !siblingBusy() && !typing) restoreQuery(apE, page, shown);")
	if errAt < 0 || rest < errAt {
		t.Error("an error must restore the controls to the shown query, like Cancel")
	}
	mustContain(t, "admin-main.js", run, "'Could not load results — showing the previous results' : 'Could not load results', { dim: false, onRetry: retryCancelled });", "error Retry re-applies the failed query")
	la := funcBody(t, main, `function loadAlerts\(opts\)`)
	if i := strings.Index(la, "if (selectAllMatchingMode) selectAllMatchingMode = false;"); i < 0 || i > strings.Index(la, "runFilterLoad(") {
		t.Error("a filter change must drop 'select all matching' BEFORE the load (bulk-ack uses the live filter)")
	}
	// The toolbar repaint must come AFTER the load is registered, or the
	// banner (which checks chartLoadBusy) re-offers "select all" — caught in
	// the browser check, not by a source pin.
	if strings.Index(la, "updateAlertBulkToolbar();") < strings.Index(la, "var loading = runFilterLoad(") {
		t.Error("loadAlerts repaints the bulk toolbar before the load is registered")
	}

	ctl := readJS(t, "admin-controls.js")
	mustContain(t, "admin-controls.js", funcBody(t, ctl, `function restore\(snap\)`), "if (autoApply) autoApply.cancelPending();", "restore drops a pending debounced edit")
	mustContain(t, "admin-controls.js", ctl, "autoApply = bindAutoApply({", "the handle is kept")

	fl := readJS(t, "admin-flows.js")
	mustContain(t, "admin-flows.js", fl, "else AC.showError('Could not load the flow samples');", "a hidden samples failure is visible")
	mustContain(t, "admin-flows.js", fl, "else AC.showError('Could not load flow detections');", "a hidden detections failure is visible")
	mustContain(t, "admin-flows.js", fl, "the list still shows the previous filter", "Flows says which rows the list shows")

	cd := readJS(t, "admin-connection-detail.js")
	mustContain(t, "admin-connection-detail.js", cd, "{ key: key, label: 'Loading…', escScope: opts.escScope }", "Esc from a range select cancels")
	mustContain(t, "admin-connection-detail.js", cd, "escScope: document.getElementById('traffic-range-select')", "traffic select")
	mustContain(t, "admin-connection-detail.js", cd, "escScope: document.getElementById('flow-range-select')", "flows select")

	ti := readJS(t, "admin-threatintel.js")
	mustContain(t, "admin-threatintel.js", ti, "if (shownLookupQ !== null) el('ti-lookup-q').value = shownLookupQ;", "lookup Cancel restores the shown query")
	mustContain(t, "admin-threatintel.js", ti, "shownLookupQ = q;\n            renderLookup(", "recorded on success")

	mustContain(t, "admin-event-profiles.js", readJS(t, "admin-event-profiles.js"), "window.FwmonEventRules.keepPendingPrefill(pending);\n                            // Superseded = the user left the page", "a create-from-alert prefill survives a failed lookup")
	mustContain(t, "admin-event-rules.js", readJS(t, "admin-event-rules.js"), "try { sessionStorage.setItem('fwmon_rule_prefill', JSON.stringify(p)); }", "it is written back for the next visit")
}

// Eighth review (Opus 5.5): the filter-based bulk ack acts on the SHOWN
// query, select-all cannot be re-armed during a load, errors restore on every
// surface, background alert refreshes stay on their page, and a background
// error never wipes what the user is typing.
func TestFilterLoad_ReviewRound8(t *testing.T) {
	main := readJS(t, "admin-main.js")
	mustContain(t, "admin-main.js", main, "var params = buildAlertParams(0, shownQuery.alerts);", "bulk ack by filter uses the shown query")
	mustContain(t, "admin-main.js", main, "var s = snap || (analyticsPages.alerts && analyticsPages.alerts.getState()) || {};", "buildAlertParams honours the snapshot")
	mustContain(t, "admin-main.js", main, "var withSnoozed = (snap && snap.__extra !== undefined) ? !!snap.__extra : !!(snoozed && snoozed.checked);", "including Show snoozed")
	en := funcBody(t, main, `function enableSelectAllMatching\(\)`)
	if !strings.HasPrefix(strings.TrimSpace(en), "// Not while a filter load runs") || !strings.Contains(en, "if (AC.chartLoadBusy('filter-alerts', true)) return;") {
		t.Error("select-all-matching cannot be armed while a filter load runs")
	}
	mustContain(t, "admin-main.js", main, "if (pageFullySelected && hasMoreMatching && !AC.chartLoadBusy('filter-alerts', true)) {", "nor offered")
	ra := funcBody(t, main, `function refreshAlertsAtCurrentPage\(opts\)`)
	if i := strings.Index(ra, "if (!alertsPage || !alertsPage.classList.contains('active')) return;"); i < 0 || i > strings.Index(ra, "runFilterLoad(") {
		t.Error("an alert refresh from another page must not run the Alerts load in the background")
	}
	mustContain(t, "admin-main.js", main, "var typing = !!(apE && apE.hasPendingEdit && apE.hasPendingEdit());", "a background error does not wipe a pending edit")

	mustContain(t, "admin-threatintel.js", readJS(t, "admin-threatintel.js"), "if (lastSearch && !paging && !typingNewSearch(query)) setSearchControls(lastSearch);", "search error restores (unless typing the next search)")
	rp := readJS(t, "admin-reports.js")
	if strings.Count(rp, "if (shown) applyChoices(shown);") != 2 {
		t.Error("reports: both Cancel and error put the shown choices back")
	}
	mustContain(t, "admin-event-profiles.js", readJS(t, "admin-event-profiles.js"), "// Like Cancel: the pickers go back to the scope whose result is shown.", "effective coverage error restores")
	cd := funcBody(t, readJS(t, "admin-connection-detail.js"), `function cdLoad\(key, host, url, opts\)`)
	eb := cd[strings.Index(cd, "if (r.error) {"):]
	if !strings.Contains(eb[:200], "if (opts.onCancel) opts.onCancel();") {
		t.Error("connection detail: an error restores the drawn range too")
	}
	mustContain(t, "diagram-panels.js", readJS(t, "diagram-panels.js"), "if (r.cancelled || r.error) {\n                // Cancel and error alike", "panel: an error restores the drawn pill too")
	mustContain(t, "admin-flows.js", readJS(t, "admin-flows.js"), "var cMsg = (append || !shownSamplesState) ? 'Cancelled' :", "a cancelled Load more (or first load) claims no previous rows")
}

// Ninth review (Opus 5.5, proven with a harness): the page handle does not
// exist during a page's first load, so the query must travel with onChange;
// paging and bulk actions continue the SHOWN query and wait for a running
// filter load; routing after a superseded lookup is skipped.
func TestFilterLoad_ReviewRound9(t *testing.T) {
	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "function apNow() { return analyticsPages[page]; }", "the handle is resolved when the load settles")
	for _, c := range []struct{ sig, guard, snap string }{
		{`function syslogPage\(target\)`, "if (AC.chartLoadBusy('filter-syslog', true)) return;", "buildSyslogParams(10, snap)"},
		{`function alertsPage\(target\)`, "if (AC.chartLoadBusy('filter-alerts', true) && !alertsQuietRefreshRunning) return;", "buildAlertParams(10, snap)"},
		{`function auditPage\(target, prev, st, paging\)`, "if (paging && AC.chartLoadBusy('filter-audit', true)) return;", "buildAuditParams(10, snap)"},
	} {
		b := funcBody(t, main, c.sig)
		if i := strings.Index(b, c.guard); i < 0 || i > strings.Index(b, "runFilterLoad(") {
			t.Errorf("%s must wait for a running filter load", c.sig)
		}
		mustContain(t, "admin-main.js", b, c.snap, "paging continues the shown query")
	}
	for _, s := range []string{"auditPage(Math.max(0, auditOffset - 20), undefined, undefined, true);", "auditPage(auditOffset, undefined, undefined, true);", "auditPage(0, opts.prev, opts.state);"} {
		mustContain(t, "admin-main.js", main, s, "audit paging is explicit")
	}
	mustContain(t, "admin-main.js", funcBody(t, main, `function refreshAlertsAtCurrentPage\(opts\)`), "buildAlertParams(pageSize, shownQuery.alerts)", "a refresh after ack continues the shown query")
	mustContain(t, "admin-main.js", funcBody(t, main, `function loadMoreTraps\(\)`), "buildTrapParams(100, shownQuery.traps)", "Load more continues the shown query")
	mustContain(t, "admin-main.js", funcBody(t, main, `function alertsPage\(target\)`), "if (loading && loading.then) loading.then(function() { updateAlertBulkToolbar(); runDeferredAlertsRefresh(); });", "Prev/Next repaint the select-all banner after registering")

	ep := readJS(t, "admin-event-profiles.js")
	mustContain(t, "admin-event-profiles.js", ep, "if (!(lr && lr.superseded) && epPage && epPage.classList.contains('active')) routeFromHash();", "no routing (URL rewrite) after the user left the page")
	mustContain(t, "admin-event-profiles.js", funcBody(t, ep, `function showGrid\(\)`), "AC.chartLoadCancel('ep-effective');", "leaving the effective view stops its lookup")
	mustContain(t, "admin-event-profiles.js", funcBody(t, ep, `function showEffective\(\)`), "AC.chartLoadCancel('ep-effective');", "re-rendering it too")
	mustContain(t, "admin-threatintel.js", readJS(t, "admin-threatintel.js"), "'Could not look up — showing the previous result' : 'Could not look up', { dim: false, onRetry:", "lookup errors offer Retry")
}

// Tenth review (Opus 5.5, harness-proven HIGH): the ack refresh waits for a
// running filter load; only TABLE loads record the shown query; first pages
// are built from the same state snapshot as the pages after them; "typing"
// means a pending edit; threat-intel paging continues the shown search.
func TestFilterLoad_ReviewRound10(t *testing.T) {
	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	if strings.Count(run, "if (want && key === page) shownQuery[page] = want;") != 2 {
		t.Error("both success paths must record the shown query for the TABLE load only")
	}
	if strings.Contains(run, "if (want) shownQuery[page] = want;") {
		t.Error("a charts load must not record the shown query")
	}
	mustContain(t, "admin-main.js", run, "var typing = !!(apE && apE.hasPendingEdit && apE.hasPendingEdit());", "typing = a pending edit, not focus")
	ra := funcBody(t, main, `function refreshAlertsAtCurrentPage\(opts\)`)
	if i := strings.Index(ra, "if (AC.chartLoadBusy('filter-alerts', true)) { alertsRefreshDeferred = true; return; }"); i < 0 || i > strings.Index(ra, "runFilterLoad(") {
		t.Error("the refresh after an ack must not supersede a running filter load")
	}
	mustContain(t, "admin-main.js", main, "buildSyslogParams(10, firstPageQuery('syslog', opts))", "syslog page 1 from the state snapshot")
	mustContain(t, "admin-main.js", main, "buildTrapParams(100, firstPageQuery('traps', opts))", "traps page 1 from the state snapshot")
	mustContain(t, "admin-main.js", main, "var snap = paging ? shownQuery.audit : firstPageQuery('audit', { state: st });", "audit page 1 from the state snapshot")
	for _, bad := range []string{"buildSyslogParams(10)", "buildTrapParams(100)", "buildAuditParams(10)"} {
		if strings.Contains(main, bad) {
			t.Errorf("%s reads the DOM; every page must come from one query snapshot", bad)
		}
	}
	if strings.Contains(main, "connections: ['panel-']") {
		t.Error("leaving Connections must not stop the side panel's loads (the panel stays open)")
	}
	ctl := readJS(t, "admin-controls.js")
	mustContain(t, "admin-controls.js", ctl, "pendings.push(function() { return pending !== null; });", "pending edits are observable")
	// Caught in the browser check: without this the flag stayed true after
	// the debounce fired, and every later error skipped its restore.
	mustContain(t, "admin-controls.js", ctl, "pending = setTimeout(function() { pending = null; commit(); }, debounceMs);", "the pending flag clears when the edit commits")
	mustContain(t, "admin-controls.js", ctl, "hasPendingEdit: function() { return !!(autoApply && autoApply.hasPending()); },", "and exposed on the page handle")

	ti := readJS(t, "admin-threatintel.js")
	mustContain(t, "admin-threatintel.js", ti, "if (AC.chartLoadBusy('ti-search', true)) { if (isRefresh) searchRefreshDeferred = true; return; }\n        runSearch(offset, lastSearch);", "search paging continues the shown search and waits")
	if strings.Count(ti, "pageSearch(searchOffset") != 4 {
		t.Error("Prev, Next and the refresh after a delete must all page through pageSearch")
	}
	mustContain(t, "admin-threatintel.js", ti, "shownLookupQ = null; // the result area was just cleared", "re-entering resets the shown lookup")
}

// Eleventh review (Opus 5.5; no HIGH/MEDIUM): config-diff header names the
// pair loading; an ack/delete refresh deferred by a running load runs when it
// settles; threat-intel errors keep a search being typed; Flows first-load
// wording; Effective coverage stops lookups against a replaced view.
func TestFilterLoad_ReviewRound11(t *testing.T) {
	dd := readJS(t, "admin-device-detail.js")
	od := funcBody(t, dd, `function openConfigDiff\(fromID, toID\)`)
	if i := strings.Index(od, "if (metaEl) metaEl.textContent = 'rev #' + fromID"); i < 0 || i > strings.Index(od, "AC.chartLoad(") {
		t.Error("the config-diff header must name the pair being loaded before the load starts")
	}
	main := readJS(t, "admin-main.js")
	if strings.Count(main, "runDeferredAlertsRefresh(); });") != 2 || !strings.Contains(main, "            updateAlertBulkToolbar();\n            runDeferredAlertsRefresh();\n        });") {
		t.Error("the filter load, paging and the ack refresh itself must run a deferred ack refresh when they settle")
	}
	mustContain(t, "admin-main.js", funcBody(t, main, `function runDeferredAlertsRefresh\(\)`), "if (!alertsRefreshDeferred || AC.chartLoadBusy('filter-alerts', true)) return;", "the deferred refresh waits for idle")
	ti := readJS(t, "admin-threatintel.js")
	mustContain(t, "admin-threatintel.js", ti, "pageSearch(searchOffset, true);", "the refresh after a delete is deferred, not dropped")
	mustContain(t, "admin-threatintel.js", ti, "runDeferredSearchRefreshSoon();", "and run when the search settles")
	mustContain(t, "admin-threatintel.js", ti, "escScope: searchForm() }", "Esc cancels a search only from the search form")
	ep := readJS(t, "admin-event-profiles.js")
	se := funcBody(t, ep, `function showEffective\(\)`)
	then := strings.Index(se, "]).then(function (r) {")
	if then < 0 || !strings.Contains(se[then:then+300], "AC.chartLoadCancel('ep-effective');") {
		t.Error("showEffective must stop lookups again right before it replaces the view")
	}
	mustContain(t, "admin-event-profiles.js", ep, "if (!out.isConnected) return; // a view since replaced\n            effShown = want;", "a lookup for a replaced view records nothing")
}

// Twelfth review (Opus 5.5, harness-proven MEDIUM): the ack refresh runs a
// refresh deferred WHILE it ran; deferred refreshes are quiet (no overlay, the
// Cancel/Retry notice survives) and toast on error; Event rules picks its
// Cancel wording from what is on screen and drops a stale target on leave.
func TestFilterLoad_ReviewRound12(t *testing.T) {
	main := readJS(t, "admin-main.js")
	ra := funcBody(t, main, `function refreshAlertsAtCurrentPage\(opts\)`)
	mustContain(t, "admin-main.js", ra, "            updateAlertBulkToolbar();\n            runDeferredAlertsRefresh();\n        });", "an ack during the refresh is not lost")
	mustContain(t, "admin-main.js", ra, "noOverlay: !!(opts && opts.quiet)", "a deferred refresh is quiet")
	mustContain(t, "admin-main.js", funcBody(t, main, `function runDeferredAlertsRefresh\(\)`), "refreshAlertsAtCurrentPage({ quiet: true });", "deferred = quiet")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "var host = opts.noOverlay ? null : document.getElementById(", "no host for a quiet load")
	mustContain(t, "admin-main.js", run, "else AC.showError('Could not load results'); // a quiet load has no host to annotate", "a quiet load's error is visible")
	er := readJS(t, "admin-event-rules.js")
	mustContain(t, "admin-event-rules.js", er, "var hadRows = wrap && !wrap.querySelector('[data-rules-placeholder]');", "Cancel wording follows what is on screen")
	mustContain(t, "admin-event-rules.js", er, "AC.chartNotice(wrap, hadRows ? 'Cancelled — showing the previous results' : 'Cancelled',", "and is used")
	if strings.Count(er, "data-rules-placeholder style=") != 2 {
		t.Error("both 'not loaded' placeholders must be marked")
	}
	mustContain(t, "admin-threatintel.js", readJS(t, "admin-threatintel.js"), "if (!tiPage || !tiPage.classList.contains('active')) return;", "no background search after leaving")
}

// Thirteenth review (Opus 5.5; LOW only): the threat-intel deferred refresh is
// consumed even off-page; a save/delete rules reload defers to a running load;
// paging may supersede a quiet ack refresh; threat-intel paging Cancel/Retry
// never touch the search box.
func TestFilterLoad_ReviewRound13(t *testing.T) {
	ti := readJS(t, "admin-threatintel.js")
	rd := funcBody(t, ti, `function runDeferredSearchRefresh\(\)`)
	if strings.Index(rd, "searchRefreshDeferred = false;") > strings.Index(rd, "if (!tiPage") {
		t.Error("the deferred threat-intel refresh must be consumed before the page-active check")
	}
	mustContain(t, "admin-threatintel.js", ti, "var paging = !!snap;", "paging loads are told apart")
	er := readJS(t, "admin-event-rules.js")
	if strings.Contains(er, "loadRules(viewedProfileId(), currentRuleFilter); //") || strings.Count(er, "reloadViewedRules();") != 2 {
		t.Error("save and delete must reload through reloadViewedRules (deferred while a rules load runs)")
	}
	mustContain(t, "admin-event-rules.js", funcBody(t, er, `function reloadViewedRules\(\)`), "if (AC.chartLoadBusy('event-rules', true)) { rulesReloadDeferred = true; return; }", "deferred while busy")
	mustContain(t, "admin-event-rules.js", er, "if (!(res && res.superseded)) setTimeout(runDeferredRulesReload, 0);", "and run when the load settles")
	main := readJS(t, "admin-main.js")
	ra := funcBody(t, main, `function refreshAlertsAtCurrentPage\(opts\)`)
	mustContain(t, "admin-main.js", ra, "if (opts && opts.quiet) alertsQuietRefreshRunning = true;", "a quiet refresh is marked")
	mustContain(t, "admin-main.js", ra, "            if (opts && opts.quiet) {\n                alertsQuietRefreshRunning = false;", "and unmarked when it settles")
	mustContain(t, "CHANGELOG.md", readFile(t, "../../CHANGELOG.md"), "(the Connections map side panel, which stays open, keeps loading)", "the panel exception is stated")
}

// Fourteenth review (Opus 5.5, harness-proven LOW): a quiet ack refresh that
// paging or a filter change interrupts is re-armed, so the ack still shows if
// that load is cancelled or fails; a page leave drops a deferred rules reload.
func TestFilterLoad_ReviewRound14(t *testing.T) {
	main := readJS(t, "admin-main.js")
	run := funcBody(t, main, `function runFilterLoad\(key, run, onOK, opts\)`)
	mustContain(t, "admin-main.js", run, "if (r.superseded) return { superseded: true };", "callers can tell a superseded load")
	ra := funcBody(t, main, `function refreshAlertsAtCurrentPage\(opts\)`)
	mustContain(t, "admin-main.js", ra, "if (res && res.superseded && AC.chartLoadBusy('filter-alerts', true)) alertsRefreshDeferred = true;", "an interrupted quiet refresh is re-armed")
	mustContain(t, "admin-event-rules.js", readJS(t, "admin-event-rules.js"), "rulesReloadDeferred = false; // the page reloads its rules on return", "a page leave consumes the deferred rules reload")
}
