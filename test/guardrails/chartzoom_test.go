package guardrails

import (
	"os"
	"strings"
	"testing"
)

// Drag-to-zoom re-queries real data (v0.11.270). These pin the mechanisms that
// would silently regress to "zoom only stretches the points already loaded",
// or to a loading state that cannot be cancelled or never goes away.

func TestChartLoad_OverlayContract(t *testing.T) {
	js := readJS(t, "admin-common.js")
	must := func(sub, why string) {
		t.Helper()
		if !strings.Contains(js, sub) {
			t.Errorf("admin-common.js is missing %q — %s", sub, why)
		}
	}
	must("var CHART_OVERLAY_DELAY_MS = 250;", "the overlay appears only after 250 ms, so fast loads never flicker")
	must("clearTimeout(showTimer);", "a load finishing inside 250 ms must clear the overlay timer")
	must("clearInterval(tick);", "every exit clears the elapsed-seconds ticker")
	must("document.removeEventListener('keydown', onKey);", "every exit removes the Esc listener")
	must("if (chartLoads[key]) chartLoads[key].supersede();", "a newer load for the same chart supersedes the old one")
	must("if (done) return;", "a result arriving after Cancel or supersede is ignored")
	must("run(ctrl ? ctrl.signal : undefined)", "the fetch gets the abort signal, so Cancel stops the request")
	must("if (!field || list.concat(escScope).some(function(c) { return c.contains(t); })) cancel();", "Esc cancels, also from the controls in opts.escScope")
	must("if (t && t.closest && t.closest('[role=\"dialog\"], .fwmon-confirm-overlay')) return;", "Esc inside a dialog closes the dialog and never cancels the page's load")
	must("if (overlays.length) document.addEventListener('keydown', onKey);", "a load with no visible overlay cannot be stopped by an Esc meant for something else")
	must("c.setAttribute('aria-busy', 'true');", "the chart is marked busy while loading")
	must("o.setAttribute('role', 'status');", "the overlay is announced")
	must("chartLoad: chartLoad,", "exported")
	must("chartNotice: chartNotice,", "exported")
	must("var field = t && t.closest && t.closest('input, textarea, select');", "Esc cancels unless focus is in a field that owns Esc (a clicked range button keeps focus)")
	must(`'<span class="fwmon-chart-overlay-elapsed" aria-live="off"></span>'`, "the per-second counter is not re-announced")
}

func TestDeviceCharts_ZoomRequeries(t *testing.T) {
	js := readJS(t, "admin-device-detail-charts.js")
	must := func(sub, why string) {
		t.Helper()
		if !strings.Contains(js, sub) {
			t.Errorf("admin-device-detail-charts.js is missing %q — %s", sub, why)
		}
	}
	must("hooks: { setSelect: [onSelect] },", "a drag selection triggers a re-query")
	must("if (!ev || ev.type !== 'mouseup') return;", "only the chart the user dragged on acts (synced charts get no event)")
	must("drag: { x: true, y: false, setScale: true, dist: 2 },", "a 1-px drag neither previews nor fetches")
	must("dblclick: function() { return function() { resetZoom(); return null; }; }", "double-click resets properly, not just to the zoomed data")
	must("'/status-history?' +\n            (win ? 'from=' + encodeURIComponent(win.from) + '&to=' + encodeURIComponent(win.to)", "a zoom asks the server for the window")
	must("AC.chartLoad(hostWraps(),", "loads run under the overlay with Cancel")
	must("AC.apiFetch(url, { signal: signal })", "the fetch is cancellable")
	must("window.AdminCommon.chartNotice(hostWraps(), msg, { onRetry: onRetry });", "an empty or failed zoom keeps the charts and shows a notice")
	must("'<div class=\"chart-host-wrap\" id=\"' + id + '-wrap\">", "the overlay mounts on a wrapper, not the host a redraw replaces")
	must("if (firstPaint) showEmpty('Load cancelled — pick a range');", "a cancelled first load is not left on its placeholder")
	must("if (range === state.range && !state.window && hasCharts()) return;", "the active pill reloads when nothing is drawn")
	if strings.Contains(js, "function showEmpty") {
		i := strings.Index(js, "function failLoad")
		body := js[i : i+400]
		if strings.Index(body, "destroyCharts();") > strings.Index(body, "showEmpty(msg);") {
			t.Error("showEmpty must only be reached after the charts are destroyed (a kept chart would point at a wiped host)")
		}
	}
}

func TestIfaceTunnelCharts_ZoomKeepsChart(t *testing.T) {
	js := readJS(t, "admin-device-detail.js")
	must := func(sub, why string) {
		t.Helper()
		if !strings.Contains(js, sub) {
			t.Errorf("admin-device-detail.js is missing %q — %s", sub, why)
		}
	}
	must("fetch(url, { credentials: 'same-origin', signal: signal })", "chart fetches are cancellable")
	must("AC.chartLoad(box, function(signal) {", "interface/tunnel loads run under the overlay")
	must("syncBwControls('chart-container-' + ifIndex, ifaceControlsCfg(ifIndex));", "a zoom re-renders only the control strip")
	must("if (lo <= 0 && hi >= ms.length - 1) return; // the full extent (a reset), not a zoom", "undoing a preview must not trigger a fetch")
	must("ifaceSearchTimer = setTimeout(function() { filterIfaces(currentFilter); }, 400);", "interface search is debounced")
	for _, fn := range []struct{ name, forbidden string }{{"function zoomIfaceTo", "filterIfaces("}, {"function zoomTunnelTo", "renderVPN("}} {
		i := strings.Index(js, fn.name)
		if i < 0 {
			t.Fatalf("%s not found", fn.name)
		}
		end := strings.Index(js[i+10:], "\n    function ")
		if end < 0 {
			end = len(js) - i - 10
		}
		if strings.Contains(js[i:i+10+end], fn.forbidden) {
			t.Errorf("%s calls %s — that rebuilds the whole table and blanks the chart before its data arrives", fn.name, fn.forbidden)
		}
	}
}

func TestPublicModal_ZoomRequeries(t *testing.T) {
	js := readJS(t, "public-dashboard.js")
	must := func(sub, why string) {
		t.Helper()
		if !strings.Contains(js, sub) {
			t.Errorf("public-dashboard.js is missing %q — %s", sub, why)
		}
	}
	must("onZoomComplete: function(ctx) { onModalZoom(ctx.chart); }", "a drag or wheel zoom re-queries")
	must("if (lo <= 0 && hi >= n - 1) return;", "zooming out to the whole loaded range fetches nothing")
	must("if (modalLastReq && modalLastReq[0] === lo && modalLastReq[1] === hi) return;", "duplicate callbacks are absorbed")
	must("modalLastReq = null; // labels are re-based", "the memo resets on every render")
	must("if (modalWidgetDef) { modalWindow = null; loadModal(); }", "Reset re-fetches the dashboard range")
	must("fetch(url, { signal: signal })", "the modal fetch is cancellable")
	must("if (restore) restore();\n                showModalNotice(", "an empty zoom restores the previous view and says so")
	must("var failed = modalWindow; // Retry asks for the view that failed", "Retry re-asks for the window that failed")
	if strings.Contains(js, "setTimeout(function() { onModalZoom") || strings.Contains(js, "wheelTimer") {
		t.Error("no app-side wheel debounce: chartjs-plugin-zoom already debounces wheel before onZoomComplete")
	}
	i := strings.Index(js, "btn-reset-zoom")
	if i < 0 || strings.Contains(js[i:i+400], "modalChart.resetZoom()") {
		t.Error("the Reset button must re-fetch, not call the plugin's resetZoom (which stretches back only to the zoomed data)")
	}
	html, err := os.ReadFile("../../web/public/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "@media (prefers-reduced-motion: reduce) { .chart-load-overlay, .chart-load-spinner { animation: none; } }") {
		t.Error("the public overlay must respect reduced motion")
	}
}
