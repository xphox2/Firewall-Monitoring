package guardrails

import (
	"regexp"
	"strings"
	"testing"
)

// PR 5 covers the console's read surface: the event and security filters,
// the syslog/trap/flow pagination, the report export, the collector's deploy
// info and the manual refresh.
//
// Two of the bugs the design pre-verification found are the kind that a
// glance cannot catch, so they are pinned here:
//
//   - The API client UNWRAPPED the response envelope and DROPPED every
//     sibling of `data`. Four handlers put metadata beside `data` — the
//     backfill's `history`/`resumable`/`hint`, the backfill and restore
//     confirmations' `estimate`, and the display settings' `is_admin` — and
//     none of them could ever reach the console.
//   - The backfill panel read `state`, `processed`, `total` and
//     `last_error`. The server's model has `status`, `rows_scanned`,
//     `rows_written` and `error` — so the status line always read "idle".
//
// The filter rules are unit-tested in ui-v2/src/lib/event-filters.test.ts,
// ui-v2/src/lib/list-filters.ts and ui-v2/src/lib/flows.test.ts. The tests
// here guard the WIRING, which a unit test cannot see.

// TestV2TheApiClientKeepsTheEnvelopeSiblings pins the unwrap.
//
// The envelope is `{ success, data, error, message, ...siblings }`. The old
// code returned `data` alone, so a sibling was dropped on the floor.
func TestV2TheApiClientKeepsTheEnvelopeSiblings(t *testing.T) {
	api := readV2(t, "lib/api.ts")
	if !strings.Contains(api, "unwrapEnvelope") {
		t.Error("lib/api.ts has no unwrapEnvelope — the response envelope is unwrapped inline, and the siblings of `data` are dropped with it")
	}
	// The siblings have to be MERGED INTO the unwrapped data, not returned
	// beside it: the callers expect one object.
	if !regexp.MustCompile(`\.\.\.siblings`).MatchString(api) {
		t.Error("lib/api.ts does not spread the envelope's siblings — every key beside `data` is lost")
	}
	// And they have to be spread INTO the data, not over it: a spread over
	// the data would let a sibling named `events` replace the payload. The
	// check is on the ORDER — the data first, the siblings second — so the
	// siblings are added to the payload rather than replacing it.
	if !regexp.MustCompile(`\.\.\.\(data as Record<string, unknown>\),\s*\.\.\.siblings`).MatchString(api) {
		t.Error("lib/api.ts does not merge the siblings INTO the unwrapped data — the order is wrong, so a sibling could replace the payload")
	}
	// The envelope's own keys have to be DESTRUCTURED OUT, not merely
	// mentioned: a keyword check passes on a file that never drops them.
	for _, key := range []string{"success", "error", "message"} {
		if !regexp.MustCompile(`\{[^}]*\b` + key + `\b[^}]*\bdata\b[^}]*\.\.\.siblings`).MatchString(api) {
			t.Errorf("lib/api.ts does not destructure %q out of the envelope — the envelope's own keys leak into the payload", key)
		}
	}
	// An ARRAY payload must not be merged into: there is nothing to merge
	// into, and the callers expect an array.
	if !regexp.MustCompile(`!Array\.isArray\(data\)`).MatchString(api) {
		t.Error("lib/api.ts does not exclude an array payload from the merge — the traps, flows and settings endpoints return a bare array")
	}
}

// TestV2TheBackfillReadsTheServersKeys pins the backfill panel.
//
// The server's `models.NormalizeBackfillJob` has `status`, `rows_scanned`,
// `rows_written` and `error`. It has no `state`, no `processed`, no `total`
// and no `last_error` — so reading them renders a panel that says "idle"
// no matter what the job is doing.
func TestV2TheBackfillReadsTheServersKeys(t *testing.T) {
	system := readV2(t, "pages/SystemWorkspace.tsx")
	for _, key := range []string{"status", "rows_scanned", "rows_written", "error"} {
		if !strings.Contains(system, key) {
			t.Errorf("SystemWorkspace.tsx does not read the backfill's %q — that is the server's field name", key)
		}
	}
	// The keys that do NOT exist on the server must be gone.
	for _, key := range []string{"backfillStatus?.state", "backfillStatus?.processed", "backfillStatus?.total", "backfillStatus?.last_error"} {
		if strings.Contains(system, key) {
			t.Errorf("SystemWorkspace.tsx still reads %q — the server's model has no such field, so the panel rendered the wrong value", key)
		}
	}
	// The siblings the envelope drops are only reachable because the API
	// client keeps them, so the panel has to ask for them.
	for _, key := range []string{"resumable", "hint", "history"} {
		if !strings.Contains(system, key) {
			t.Errorf("SystemWorkspace.tsx does not use the backfill's %q — it is a SIBLING of `data` in the response, so it only arrives because the API client keeps the siblings", key)
		}
	}
}

// TestV2TheEventFiltersUseTheSharedBuilder pins that the event streams
// build their query through the tested builder.
//
// The builder is where the two server rules live: a numeric filter that
// does not parse is a 400 (AUDIT-251), and an address that is not an
// address is a 400. A hand-written query string would have to repeat them.
func TestV2TheEventFiltersUseTheSharedBuilder(t *testing.T) {
	events := readV2(t, "pages/EventsWorkspace.tsx")
	for _, needle := range []string{"buildNetEventQuery", "buildSecEventQuery"} {
		if !strings.Contains(events, needle) {
			t.Errorf("EventsWorkspace.tsx does not use %s — the numeric and address filters have to go through the tested builder", needle)
		}
	}
	// A hand-written numeric filter is exactly the bug: the server rejects
	// a non-numeric one with a 400 rather than ignoring it.
	if regexp.MustCompile(`params\.set\('(device_id|probe_id|site_id|activity|action|class|severity)'`).MatchString(events) {
		t.Error("EventsWorkspace.tsx sets a numeric filter by hand — a non-numeric value is a 400, not a no-match, so it has to go through the builder")
	}
}

// TestV2TheEventStreamsArePaginated pins the pagination.
//
// The net-event stream showed the first hundred rows and no more, with no
// way to reach the rest; the syslog and trap lists were the same.
func TestV2TheEventStreamsArePaginated(t *testing.T) {
	for path, needle := range map[string]string{
		"pages/EventsWorkspace.tsx": "EventPager",
		"pages/SyslogWorkspace.tsx": "EventPager",
		"pages/TrapsWorkspace.tsx":  "EventPager",
	} {
		src := readV2(t, path)
		if !strings.Contains(src, needle) {
			t.Errorf("%s has no %s — the list showed the first page and no way to reach the rest", path, needle)
		}
	}
	// The offset has to be sent, or every page is the first page.
	for path, builder := range map[string]string{
		"pages/EventsWorkspace.tsx": "buildNetEventQuery",
		"pages/SyslogWorkspace.tsx": "buildSyslogQuery",
		"pages/TrapsWorkspace.tsx":  "buildTrapQuery",
	} {
		src := readV2(t, path)
		if !strings.Contains(src, builder) {
			t.Errorf("%s does not use %s — without the offset every page is the first page", path, builder)
		}
	}
}

// TestV2TheFlowFiltersAreComplete pins the flow filters.
//
// The console offered seven of the server's sixteen flow filters, so a
// conversation could not be narrowed by its site, probe, service port,
// application category, direction, destination country or destination ASN.
func TestV2TheFlowFiltersAreComplete(t *testing.T) {
	lib := readV2(t, "lib/flows.ts")
	for _, field := range []string{
		"probeId", "siteId", "servicePort", "appCategory", "direction", "dstCountry", "dstAsn",
	} {
		if !strings.Contains(lib, field) {
			t.Errorf("lib/flows.ts has no %q filter — the server accepts it and the console did not offer it", field)
		}
	}
	// The export cap: the server's ceiling is 10,000 and the legacy console
	// exported the whole thing. The console exported half.
	page := readV2(t, "pages/FlowsWorkspace.tsx")
	if !strings.Contains(page, "FLOW_EXPORT_LIMIT") {
		t.Error("FlowsWorkspace.tsx does not use the shared export limit")
	}
	if !strings.Contains(lib, "FLOW_EXPORT_LIMIT = 10000") {
		t.Error("lib/flows.ts does not define FLOW_EXPORT_LIMIT as the server's 10,000 ceiling")
	}
}

// TestV2TheReportExportIsClientSide pins the report export.
//
// There is NO server-side PDF endpoint: the legacy console PRINTED the
// preview iframe, and the HTML was a client-side Blob download. Building a
// backend PDF export would target an endpoint that does not exist.
func TestV2TheReportExportIsClientSide(t *testing.T) {
	system := readV2(t, "pages/SystemWorkspace.tsx")
	for _, needle := range []string{"exportPdf", "exportHtml", "contentWindow?.print"} {
		if !strings.Contains(system, needle) {
			t.Errorf("SystemWorkspace.tsx is missing %q — the PDF export is the browser printing the preview, and the HTML export is a Blob download", needle)
		}
	}
	// The preview's own parameters: without them the preview is always the
	// daily dark web one.
	for _, needle := range []string{"previewPeriod", "previewTheme", "previewLayout"} {
		if !strings.Contains(system, needle) {
			t.Errorf("SystemWorkspace.tsx does not send the preview's %q — the server's preview takes a period, a theme and a layout", needle)
		}
	}
}

// TestV2TheDeployInfoHandlesTheKeyMask pins the deploy info.
//
// The registration key is shown ONCE, at creation. Every later read returns
// the redaction mask, which is TRUTHY — so without the check the deploy
// modal would render '********' as if it were a copyable key.
func TestV2TheDeployInfoHandlesTheKeyMask(t *testing.T) {
	lib := readV2(t, "lib/probe-deploy.ts")
	if !strings.Contains(lib, "isRealRegistrationKey") {
		t.Error("lib/probe-deploy.ts has no isRealRegistrationKey — the redaction mask is truthy, so the deploy modal would render it as a copyable key")
	}
	if !strings.Contains(lib, "PROBE_REGISTRATION_KEY") {
		t.Error("lib/probe-deploy.ts does not build the PROBE_REGISTRATION_KEY line")
	}
	drawer := readV2(t, "components/collectors/probe-deploy-drawer.tsx")
	if !strings.Contains(drawer, "isRealRegistrationKey") {
		t.Error("the deploy drawer does not use isRealRegistrationKey")
	}
	// And the env block is CLIENT-composed: there is no server endpoint for
	// it, so a call to one would be a 404.
	page := readV2(t, "pages/CollectorsWorkspace.tsx")
	if strings.Contains(page, "deploy-env") || strings.Contains(page, "api/probes/.*/deploy") {
		t.Error("CollectorsWorkspace.tsx looks for a server-side deploy endpoint — the env block is composed on the client")
	}
}

// TestV2ThereIsAManualRefresh pins the manual refresh.
//
// The console polled every ten to thirty seconds, but there was no way to
// ask for a fresh reading: an operator watching an incident had to wait for
// the next poll.
func TestV2ThereIsAManualRefresh(t *testing.T) {
	button := readV2(t, "components/ui/refresh-button.tsx")
	if !strings.Contains(button, "invalidateQueries") {
		t.Error("the refresh button does not invalidate any query — it would not refresh anything")
	}
	for _, path := range []string{
		"pages/EventsWorkspace.tsx",
		"pages/SyslogWorkspace.tsx",
		"pages/TrapsWorkspace.tsx",
		"pages/FlowsWorkspace.tsx",
	} {
		src := readV2(t, path)
		if !strings.Contains(src, "<RefreshButton") {
			t.Errorf("%s has no manual refresh — the page polls, but an operator cannot ask for a fresh reading", path)
		}
	}
}
