package guardrails

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The V2 console's workflows must stay in step with the server's, and its
// failures must not be silent.
//
// Each test here pins something that was WRONG in the V2 console and would
// otherwise drift back:
//
//   - the V2 console could not CREATE or EDIT a device connection (only
//     delete), although the server's endpoints were live and unused;
//   - the V2 console could not acknowledge or snooze alerts ACROSS PAGES,
//     although the server's by-filter endpoints were live and unused;
//   - 7 of the console's 59 mutations had no error handler, so a failed
//     action — revoking an API token, retiring a device — failed SILENTLY;
//   - the connection-type list the console offers was not pinned to the
//     server's allowlist, which is the AUDIT-184 guard (connection_type is
//     rendered by the badge helpers, so a value outside the list is
//     rejected by the server and must not be offered).
//
// The mutations check parses the TypeScript rather than grepping for it: a
// mutation's options object is brace-matched, so an `onError` belonging to a
// NEIGHBOURING mutation cannot be mistaken for this one's.

// v2Src is the V2 console's source root.
const v2Src = "../../ui-v2/src"

func readV2(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(v2Src, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

// TestV2ConsoleCreatesAndEditsConnections pins the create/edit workflow.
//
// The server's endpoints: POST /admin/api/connections (create) and
// PUT /admin/api/connections/:id (partial update). The V2 console had only
// DELETE, so a link between two devices could not be declared or corrected
// from it at all.
func TestV2ConsoleCreatesAndEditsConnections(t *testing.T) {
	editor := readV2(t, "components/topology/connection-editor.tsx")
	workspace := readV2(t, "pages/TopologyWorkspace.tsx")

	for _, needle := range []string{
		// Both verbs, against the right paths.
		"'/admin/api/connections'",
		"/admin/api/connections/${connection.id}",
		"method: connection ? 'PUT' : 'POST'",
		// The endpoints are the ONLY way to declare a link; the console must
		// actually offer them, not merely be able to call them.
		"New connection",
		"setConnToEdit(row.original)",
		"<ConnectionEditor",
	} {
		if !strings.Contains(editor+workspace, needle) {
			t.Errorf("the V2 console is missing %q — it must be able to CREATE and EDIT a device connection, not only delete one", needle)
		}
	}

	// The fields the server binds. A body the server does not accept is
	// silently dropped, so the form must send the server's names.
	for _, needle := range []string{
		"source_device_id",
		"dest_device_id",
		"connection_type",
	} {
		if !strings.Contains(editor, needle) {
			t.Errorf("connection-editor.tsx missing %q — the server binds this field name", needle)
		}
	}
}

// TestV2ConsoleBulkActionsCanCrossPages pins the cross-page selection.
//
// The server's endpoints: POST /admin/api/alerts/bulk-acknowledge-filter and
// POST /admin/api/alerts/bulk-snooze-filter. Both take the filter in the
// QUERY and require at least one filter.
func TestV2ConsoleBulkActionsCanCrossPages(t *testing.T) {
	alerts := readV2(t, "pages/AlertsWorkspace.tsx")

	for _, needle := range []string{
		"/admin/api/alerts/bulk-acknowledge-filter?",
		"/admin/api/alerts/bulk-snooze-filter?",
		"setSelectAllMatching(true)",
		"selectAllMatching ? bulkAckFilter.mutate() : bulkAck.mutate()",
		"selectAllMatching ? bulkSnoozeFilter.mutate() : bulkSnooze.mutate()",
	} {
		if !strings.Contains(alerts, needle) {
			t.Errorf("AlertsWorkspace.tsx missing %q — the operator must be able to act on every alert matching the filter, not only the rows on one page", needle)
		}
	}

	// The site filter is NOT one of the filters the endpoint accepts
	// (internal/api/handlers/handlers_analytics.go: device_id, alert_type,
	// severity, acknowledged, include_snoozed). A request built from a
	// site-filtered view would reach alerts outside the site on screen, so
	// the console must withhold the shortcut rather than build a request
	// the server cannot scope.
	if !strings.Contains(alerts, "bulkFilterCanScopeBySite") {
		t.Error("AlertsWorkspace.tsx missing the site-filter guard — the bulk-by-filter endpoint cannot filter by site, so acting across pages under a site filter would reach alerts the operator cannot see")
	}
	if strings.Contains(alerts, "params.set('site_id'") {
		t.Error("AlertsWorkspace.tsx must not send site_id to the bulk-by-filter endpoint — the server ignores it, which would silently widen the action")
	}
	// The query builder may have moved into lib/alerts.ts, so that file is
	// checked too: the LIST query legitimately sends site_id, but the BULK
	// query must not, and the two live in the same module.
	if bulk := readV2(t, "lib/alerts.ts"); strings.Contains(bulk, "params.set('site_id'") {
		// Allowed only inside buildAlertQuery (the list). The bulk builder
		// must not have it: split the file and check the bulk function only.
		if bulkFn := regexp.MustCompile(`(?s)export function buildAlertBulkFilterQuery\(.*?\n\}`).FindString(bulk); bulkFn != "" {
			if strings.Contains(bulkFn, "site_id") {
				t.Error("lib/alerts.ts buildAlertBulkFilterQuery sends site_id — the server ignores it, which would silently widen the action")
			}
		} else {
			t.Error("lib/alerts.ts missing buildAlertBulkFilterQuery — the cross-page bulk action must build its query in one tested place")
		}
	}
}

// TestV2MutationsAllReportFailures pins that no mutation fails silently.
//
// A mutation without an onError leaves the operator looking at a button that
// did nothing. Revoking an API token that failed silently is the worst case:
// the operator believes the token is dead when it is still live.
func TestV2MutationsAllReportFailures(t *testing.T) {
	var files []string
	err := filepath.Walk(v2Src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", v2Src, err)
	}
	sort.Strings(files)

	// useMutation( — the call, not the import.
	call := regexp.MustCompile(`useMutation`)

	total := 0
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		src := string(body)
		for _, loc := range call.FindAllStringIndex(src, -1) {
			line := strings.Count(src[:loc[0]], "\n") + 1
			// The WHOLE line, so an import statement is recognised: the match
			// sits mid-line, so slicing from the match would miss the
			// "import" keyword.
			lineStart := strings.LastIndexByte(src[:loc[0]], '\n') + 1
			lineEnd := strings.IndexByte(src[loc[0]:], '\n')
			if lineEnd < 0 {
				lineEnd = len(src)
			} else {
				lineEnd += loc[0]
			}
			lineText := src[lineStart:lineEnd]
			if strings.Contains(lineText, "import") {
				continue // the import statement
			}
			// The options object: the first '{' after the call.
			open := strings.IndexByte(src[loc[1]:], '{')
			if open < 0 {
				continue
			}
			open += loc[1]
			depth := 0
			end := open
			for ; end < len(src); end++ {
				switch src[end] {
				case '{':
					depth++
				case '}':
					depth--
					if depth == 0 {
						end++
						goto done
					}
				}
			}
		done:
			if end <= open {
				continue
			}
			total++
			if !strings.Contains(src[open:end], "onError") {
				t.Errorf("%s:%d — a useMutation with no onError fails SILENTLY: the operator sees a button that did nothing", file, line)
			}
		}
	}
	if total == 0 {
		t.Fatal("no useMutation calls found — the scan is broken, not the console clean")
	}
	t.Logf("scanned %d useMutation call sites", total)
}

// TestV2ConnectionTypesMatchTheServer pins the console's list of connection
// types to the server's allowlist.
//
// The server rejects anything outside the list (AUDIT-184: connection_type is
// rendered by the badge helpers, so it is an XSS vector and is allowlisted).
// The console must offer exactly what the server accepts — no more, because
// an offered type would 400; no less, because a valid type that is not
// offered cannot be used.
//
// The server's list is PARSED from the Go source, not copied here: a copy
// would pass against a stale server allowlist and let the two drift apart
// unnoticed, which is the whole point of the test.
func TestV2ConnectionTypesMatchTheServer(t *testing.T) {
	editor := readV2(t, "components/topology/connection-editor.tsx")

	block := regexp.MustCompile(`(?s)CONNECTION_TYPES\s*=\s*\[(.*?)\]`).FindStringSubmatch(editor)
	if block == nil {
		t.Fatal("connection-editor.tsx missing the CONNECTION_TYPES list — the console must offer the connection types the server accepts")
	}
	quoted := regexp.MustCompile(`'([a-z0-9_]+)'`).FindAllStringSubmatch(block[1], -1)
	got := map[string]bool{}
	for _, m := range quoted {
		got[m[1]] = true
	}

	// The server's allowlist, parsed from its source.
	goSrc := readRepoFile(t, "internal/api/handlers/handlers_connections.go")
	serverBlock := regexp.MustCompile(`(?s)var validConnectionTypes = map\[string\]bool\{(.*?)\n\}`).FindStringSubmatch(goSrc)
	if serverBlock == nil {
		t.Fatal("handlers_connections.go: validConnectionTypes not found — the server's allowlist is the source of truth for the console's list")
	}
	serverQuoted := regexp.MustCompile(`"([a-z0-9_]+)"`).FindAllStringSubmatch(serverBlock[1], -1)
	want := map[string]bool{}
	for _, m := range serverQuoted {
		want[m[1]] = true
	}
	if len(want) == 0 {
		t.Fatal("the server's connection-type allowlist parsed empty — the parser is broken, not the server")
	}

	for typ := range want {
		if !got[typ] {
			t.Errorf("the console does not offer connection type %q — the server accepts it, so not offering it makes a valid link impossible to declare", typ)
		}
	}
	for typ := range got {
		if !want[typ] {
			t.Errorf("the console offers connection type %q — the server rejects it with 400 (AUDIT-184 allowlist)", typ)
		}
	}
}

// TestV2ConnectionEditorSendsOnlyRealColumns pins the connection editor's
// request body to the columns the model actually has.
//
// models.DeviceConnection has NO Description column (only Notes), but the
// server's update allowlist listed "description". A client that sent it got
// a 500 on EVERY update, because a GORM map update turns the key into a
// column name. The console had the same field, so every edit failed.
//
// The check is general: every field the editor's body carries must be a
// column of the model, and a column the model does not have must not be
// offered as a form field.
func TestV2ConnectionEditorSendsOnlyRealColumns(t *testing.T) {
	editor := readV2(t, "components/topology/connection-editor.tsx")

	// The body the editor builds.
	body := regexp.MustCompile(`(?s)const body: Record<string, unknown> = \{(.*?)\n      \};`).FindStringSubmatch(editor)
	if body == nil {
		t.Fatal("connection-editor.tsx: could not find the request body — the guard is looking for `const body: Record<string, unknown> = {`")
	}
	sent := regexp.MustCompile(`(?m)^\s*([a-z_]+):`).FindAllStringSubmatch(body[1], -1)
	if len(sent) == 0 {
		t.Fatal("connection-editor.tsx: the request body is empty — the guard is broken, not the editor")
	}

	// The model's columns.
	modelSrc := readRepoFile(t, "internal/models/models.go")
	structBlock := regexp.MustCompile(`(?s)type DeviceConnection struct \{(.*?)\n\}`).FindStringSubmatch(modelSrc)
	if structBlock == nil {
		t.Fatal("models.go: type DeviceConnection not found")
	}
	columns := map[string]bool{}
	for _, m := range regexp.MustCompile(`json:"([a-z0-9_]+)`).FindAllStringSubmatch(structBlock[1], -1) {
		columns[m[1]] = true
	}
	if len(columns) == 0 {
		t.Fatal("the model's columns parsed empty — the parser is broken, not the model")
	}

	for _, m := range sent {
		field := m[1]
		if !columns[field] {
			t.Errorf("connection-editor.tsx sends %q, which is not a column of models.DeviceConnection — the server would ignore it on create and 500 on update", field)
		}
	}
}

// readRepoFile is the package's existing helper (passkey_ui_test.go): it
// reads a file from the repository root.
