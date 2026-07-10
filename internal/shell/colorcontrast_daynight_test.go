package shell

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestNoThemeBlindInlineTextColor pins the v0.11.70 Day/Night contrast sweep.
//
// Root cause of the recurring "light grey text on a white background" reports:
// JS-built HTML baked GitHub-dark palette hexes as inline `color:#hex` styles.
// Those resolve identically in both themes, so anything readable in night mode
// (e.g. #8b949e faint grey) washes out on the day surfaces — the Connections
// Discovery column and the Alert Policies cards were the reported instances.
//
// The sweep replaced every theme-blind inline text color with a `var(--fwmon-*)`
// token (identical values in dark, day-ink values in light). This test makes
// the bug class un-reintroducible: none of the swept palette hexes may appear
// as an unquoted inline `color:#hex` in HTML-template strings or markup.
//
// Scope: web/**/*.html + cmd/api/static/js (hand-written admin JS). Exempt:
//   - vendored bundles (chart.umd*, uplot*, cytoscape*) — third-party
//   - public-dashboard.js + web/public — the public page is un-themed
//   - login.html — intentionally outside the design system
//   - CSS files — token definitions legitimately hold these hexes
//     (admin-design-system.css) and admin-tw-bridge.css re-points them
//
// Quoted object-literal colors (`color: '#hex'`, canvas fillStyle) are allowed
// only when they flow through AdminCommon.cssVar(); the unquoted inline-style
// form this test bans has no such indirection and is always theme-blind.
func TestNoThemeBlindInlineTextColor(t *testing.T) {
	// The GitHub-dark / slate palette that the v0.11.70 sweep retargeted to
	// tokens. Any of these as an inline text color is a day-mode regression.
	sweptHexes := []string{
		"8b949e", "768390", "c9d1d9", "e6edf3", // dark text ramp
		"64748b", "94a3b8", "e2e8f0", "f8fafc", "475569", // slate ramp
		"484f58", "6e7681", "9ca3af", // AUDIT-066/067 + tailwind placeholder grey
		"58a6ff", "79c0ff", // accent blues (token: --fwmon-accent)
	}
	// Unquoted `color:#hex` inside a style string; [^-\w] guard excludes
	// background-color/border-color and identifiers.
	inlineText := regexp.MustCompile(`(?i)(^|[^-\w])color: ?#(` + strings.Join(sweptHexes, "|") + `)\b`)

	exempt := func(path string) bool {
		base := filepath.Base(path)
		switch {
		case strings.Contains(base, "chart.umd"),
			strings.Contains(base, "uplot"),
			strings.Contains(base, "cytoscape"),
			base == "public-dashboard.js",
			base == "login.html":
			return true
		case strings.Contains(filepath.ToSlash(path), "/web/public/"):
			return true
		}
		return false
	}

	roots := []string{"../../web", "../../cmd/api/static/js"}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			switch filepath.Ext(path) {
			case ".html", ".js":
			default:
				return nil
			}
			if exempt(path) {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			for _, line := range strings.Split(string(data), "\n") {
				// DevTools console %c styling can't resolve CSS vars —
				// literal hex is correct there.
				if strings.Contains(line, "%c") {
					continue
				}
				for _, m := range inlineText.FindAllString(line, -1) {
					t.Errorf("%s: theme-blind inline text color %q — use color:var(--fwmon-*) so day mode resolves its own ink", path, strings.TrimSpace(m))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

// TestTextTokensClearAA pins the token values themselves: every --fwmon-text*
// tier must clear WCAG AA (>= 4.5:1) against the theme's bg, card and panel
// surfaces. v0.11.70 nudged --fwmon-text-mute in both themes (#768390 was
// 3.9:1 on the dark panel; #6b7a85 was 4.0:1 on the day bg).
func TestTextTokensClearAA(t *testing.T) {
	ds, err := os.ReadFile("../../cmd/api/static/css/admin-design-system.css")
	if err != nil {
		t.Fatalf("read admin-design-system.css: %v", err)
	}
	css := string(ds)

	// Split the sheet at the light-theme block so same-named tokens resolve
	// per theme (dark tokens are defined first, in :root).
	lightStart := strings.Index(css, `:root[data-theme="light"]`)
	if lightStart < 0 {
		t.Fatal("light theme block not found")
	}
	darkCSS, lightCSS := css[:lightStart], css[lightStart:]

	token := func(block, name string) string {
		re := regexp.MustCompile(regexp.QuoteMeta(name) + `:\s*(#[0-9a-fA-F]{6})`)
		m := re.FindStringSubmatch(block)
		if m == nil {
			t.Fatalf("token %s not found in theme block", name)
		}
		return m[1]
	}

	lum := func(hex string) float64 {
		var rgb [3]float64
		for i := 0; i < 3; i++ {
			v, perr := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
			if perr != nil {
				t.Fatalf("bad hex %s: %v", hex, perr)
			}
			c := float64(v) / 255
			if c <= 0.03928 {
				c = c / 12.92
			} else {
				c = math.Pow((c+0.055)/1.055, 2.4)
			}
			rgb[i] = c
		}
		return 0.2126*rgb[0] + 0.7152*rgb[1] + 0.0722*rgb[2]
	}
	ratio := func(a, b string) float64 {
		la, lb := lum(a), lum(b)
		if la < lb {
			la, lb = lb, la
		}
		return (la + 0.05) / (lb + 0.05)
	}

	for _, theme := range []struct {
		name  string
		block string
	}{{"dark", darkCSS}, {"light", lightCSS}} {
		surfaces := map[string]string{
			"--fwmon-bg":       token(theme.block, "--fwmon-bg"),
			"--fwmon-card-bg":  token(theme.block, "--fwmon-card-bg"),
			"--fwmon-panel-bg": token(theme.block, "--fwmon-panel-bg"),
		}
		for _, txt := range []string{"--fwmon-text", "--fwmon-text-dim", "--fwmon-text-faint", "--fwmon-text-mute"} {
			ink := token(theme.block, txt)
			for surfName, surf := range surfaces {
				if r := ratio(ink, surf); r < 4.5 {
					t.Errorf("%s theme: %s (%s) on %s (%s) = %.2f:1 — fails WCAG AA (need 4.5:1)",
						theme.name, txt, ink, surfName, surf, r)
				}
			}
		}
	}
}
