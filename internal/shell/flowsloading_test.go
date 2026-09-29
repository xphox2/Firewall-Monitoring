package shell

import (
	"os"
	"strings"
	"testing"
)

// The Flows page streams long reports with progress (v0.11.260). These pin the
// behaviours that would silently regress: an EventSource that is not closed
// after its answer reconnects and runs the whole report again; a stream that
// dies mid-report must not be re-run as a 20 s request that can only return a
// partial answer; responses from an older load must not overwrite a newer one;
// and a partial result must be announced above the figures, not below them.
func TestFlowsPage_StreamedLoadGuards(t *testing.T) {
	js := readJS(t, "admin-flows.js")
	must := func(sub, why string) {
		t.Helper()
		if !strings.Contains(js, sub) {
			t.Errorf("admin-flows.js is missing %q — %s", sub, why)
		}
	}
	must("/admin/api/flows/stats/stream?", "the page must load stats through the progress stream")
	must("addEventListener('result', function(ev) {\n            es.close();", "the stream must be closed on its result, or EventSource reconnects and reruns the report")
	must("addEventListener('fail', function(ev) {\n            es.close();", "the stream must be closed on the server's fail event")
	must("es.onerror = function() {\n            es.close();", "the stream must be closed on a transport error")
	must("if (!heard) {", "only a stream that never answered may fall back to the plain request")
	must("The connection was lost while the report was loading.", "a stream that dies mid-report goes to the error state, not a silent re-run")
	must("if (gen !== statsGen) return;", "events from an older load must be ignored")
	must("{ signal: statsAbort.signal }", "the fallback request must be abortable by a newer load")
	if n := strings.Count(js, "console."); n > 3 {
		t.Errorf("admin-flows.js has %d console. calls; new code logs through fwmonLog (AUDIT-151)", n)
	}
}

func TestFlowsPage_PartialNoticeAboveFigures(t *testing.T) {
	b, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	notice := strings.Index(html, `id="flows-degraded-warning"`)
	grid := strings.Index(html, `id="flows-stats-grid"`)
	if notice < 0 || grid < 0 || notice > grid {
		t.Fatalf("the partial-result notice must sit above the stat tiles (notice at %d, tiles at %d)", notice, grid)
	}
	if strings.Count(html, `id="flows-degraded-warning"`) != 1 {
		t.Fatal("exactly one partial-result notice")
	}
	for _, id := range []string{`id="flows-loading"`, `id="flows-loading-cancel"`, `id="flows-load-retry"`, `id="flows-loading-bar"`} {
		if !strings.Contains(html, id) {
			t.Errorf("admin.html is missing %s", id)
		}
	}
}

// The distribution panels (protocols, applications, direction) carry BYTES in
// `count` and the sampled-record count in `records` (v0.11.262). Protocols once
// printed a record count through formatBytes ("1.5 MB" for 1.48M records) and
// applications/direction ranked by records, so a byte formatter must never be
// swapped back to formatCount on these lists, and the record count must stay
// reachable on hover.
func TestFlowsPage_DistributionsAreBytes(t *testing.T) {
	js := readJS(t, "admin-flows.js")
	for _, id := range []string{"flows-top-protocols", "flows-by-category", "flows-by-direction"} {
		i := strings.Index(js, "renderList('"+id+"'")
		if i < 0 {
			t.Fatalf("admin-flows.js no longer renders %s", id)
		}
		// The whole call, however it is wrapped: up to the closing ");".
		call := js[i : i+strings.Index(js[i:], ");")]
		if strings.Contains(call, "formatCount") {
			t.Errorf("%s is rendered with formatCount; its values are bytes: %s", id, call)
		}
	}
	for _, sub := range []string{
		"if (typeof r.records === 'number') {",
		`title="' + esc(labelTitle) + '"`,
		"valueAria = ' aria-label=",
	} {
		if !strings.Contains(js, sub) {
			t.Errorf("renderList must surface the record count on the label title and the value's aria-label (missing %q)", sub)
		}
	}
}

// Top services (v0.11.263) filters by the service port NUMBER. The old Top
// ports rows were keyed by display name, so clicking "HTTPS" sent
// dst_port=HTTPS, which the server silently ignored. The service filter must
// also reach both the stats and the samples requests, and a panel partial for
// its own reason must be badged without the page-wide "last hour" banner.
func TestFlowsPage_TopServicesFilterByNumber(t *testing.T) {
	js := readJS(t, "admin-flows.js")
	for _, sub := range []string{
		"renderList('flows-top-services',     d.top_services     || [], 'ports',     'svc',      function(v, r) { return r && r.port ? String(r.port) : ''; });",
		"var filterVal = toFilterValue(r.key, r);",
		"params.push('service_port=' + encodeURIComponent(state.svc));",
		"p.push('service_port=' + encodeURIComponent(st.svc));",
		"markPartialPanels(blocks.concat(d.partial_blocks || []), d.partial_reasons || {});",
		"el.removeAttribute('data-partial');",
	} {
		if !strings.Contains(js, sub) {
			t.Errorf("admin-flows.js is missing %q", sub)
		}
	}
	if strings.Contains(js, "flows-top-ports") || strings.Contains(js, "top_ports") {
		t.Error("admin-flows.js still references the removed Top ports panel")
	}
}
