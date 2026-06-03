package shell

import (
	"os"
	"strings"
	"testing"
)

// TestAPIVersioningRewrite_BehaviorPinned_AUDIT138 is a static
// regression for the audit: the path-rewrite middleware in
// `cmd/api/main.go` (added in v0.10.219) rewrites `/api/v1/*`
// to `/api/*` and `/admin/api/v1/*` to `/admin/api/*`. The audit
// flagged this as "safe today but fragile" because the rewrite
// is hand-coded rather than driven by config. The right
// long-term fix is real versioning (AUDIT-090), which would
// make the version list a config value; until that lands, the
// rewrite is the intentional interim design.
//
// The test pins the current rewrite logic by reading
// `cmd/api/main.go` and asserting four things:
//
//  1. Both prefix patterns are present (the rewrite handles
//     both /api/v1/ and /admin/api/v1/).
//  2. Both rewrites use `p[len(prefix):]` slicing (the safe
//     form that consumes the prefix exactly, rather than
//     `strings.Replace` or similar which could over-replace).
//  3. The middleware is mounted before route registration
//     (so the rewrite happens before route matching).
//  4. The audit ID is referenced in a comment (so the
//     fragility is documented, and a future agent who
//     removes the rewrite without addressing AUDIT-090 fails
//     the test).
//
// A future refactor that drops the rewrite (e.g. as part of
// AUDIT-090) would need to update this test in the same
// commit, which is the right forcing function.
func TestAPIVersioningRewrite_BehaviorPinned_AUDIT138(t *testing.T) {
	const path = "../../cmd/api/main.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cmd/api/main.go not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// 1. Both prefix patterns must be present.
	for _, want := range []string{`/api/v1/`, `/admin/api/v1/`} {
		if !strings.Contains(body, want) {
			t.Errorf("main.go missing the %q prefix; the rewrite must handle both /api/v1/* and /admin/api/v1/* (AUDIT-138).", want)
		}
	}

	// 2. Both rewrites must use the safe `p[len(prefix):]` form.
	// The fragile alternatives (strings.Replace, regex, etc.)
	// would NOT match this exact form.
	safeForm := `p[len("/api/v1/"):]`
	if !strings.Contains(body, safeForm) {
		t.Errorf("main.go missing the safe slice form %q for the /api/v1/ rewrite; a future refactor that switches to strings.Replace or a regex would be a security regression (a `..` in the path could escape the prefix). The safe form consumes the prefix exactly.", safeForm)
	}
	safeFormAdmin := `p[len("/admin/api/v1/"):]`
	if !strings.Contains(body, safeFormAdmin) {
		t.Errorf("main.go missing the safe slice form %q for the /admin/api/v1/ rewrite.", safeFormAdmin)
	}

	// 3. The middleware must be registered with `router.Use`
	// (so it runs before route matching). A future agent who
	// accidentally moves the rewrite into a per-route handler
	// would still let the request hit the canonical routes
	// without the rewrite, which is a routing-regression
	// rather than a security one but still worth catching.
	if !strings.Contains(body, "router.Use(func(c *gin.Context)") {
		t.Errorf("main.go's path-rewrite is not mounted via `router.Use`; the rewrite must run before route matching (the audit's #1 design constraint).")
	}

	// 4. The audit ID must be referenced in a comment. A
	// future agent who removes the rewrite without addressing
	// AUDIT-090 fails here loudly with the audit ID.
	if !strings.Contains(body, "AUDIT-138") {
		t.Errorf("main.go's path-rewrite is no longer tagged with `AUDIT-138` in a comment; the fragility is undocumented and a future refactor is more likely to drop the rewrite silently. Add the audit ID to the doc block (e.g. `// AUDIT-138: ...`).")
	}
}
