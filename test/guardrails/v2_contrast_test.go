package guardrails

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The signal colours are chosen for the theme's SURFACES: a border, an
// icon, a chart series, a fill. They are not chosen for TEXT, and on the
// light theme they are marginal even as plain text on a white card - the
// green measures 4.35:1 where WCAG AA wants 4.5:1.
//
// The console therefore has a TEXT variant of each signal colour, and a
// signal colour used as text is always the text variant. These tests pin
// both halves: the tokens exist with their measured values, and no call
// site uses a base signal colour as text.
//
// The measurements came from a real walk of the console against a copy of
// the production database: axe found the chips at 3.6:1 (the light warn
// chip), 3.8:1 (the light crit chip) and 4.0:1 (the dark crit chip), and
// 4.37:1 for the accent link on the preview banner's tint.

// TestV2TheSignalTextTokensExist pins the tokens.
//
// The values are the measured ones, not a guess: each clears 4.5:1 on its
// own 15% tint AND on the plain card, in its own theme.
func TestV2TheSignalTextTokensExist(t *testing.T) {
	css := readRepoFile(t, "ui-v2/src/styles/globals.css")

	// The Tailwind mapping, so `text-sig-crit-text` resolves.
	for _, token := range []string{
		"--color-sig-ok-text",
		"--color-sig-warn-text",
		"--color-sig-crit-text",
	} {
		if !strings.Contains(css, token) {
			t.Errorf("the theme has no %s - a signal colour used as text has no variant that clears the contrast bar on a tinted background", token)
		}
	}

	dark := themeBlock(t, css, "dark")
	light := themeBlock(t, css, "light")

	for _, c := range []struct {
		theme  string
		block  string
		token  string
		expect string
	}{
		{"dark", dark, "--fwmon-sig-crit-text", "#ff7b7f"},
		{"dark", dark, "--fwmon-sig-ok-text", "#36c98a"},
		{"dark", dark, "--fwmon-sig-warn-text", "#e7b53c"},
		{"light", light, "--fwmon-sig-crit-text", "#b52a30"},
		{"light", light, "--fwmon-sig-ok-text", "#0e6b4a"},
		{"light", light, "--fwmon-sig-warn-text", "#7d5609"},
	} {
		if !strings.Contains(c.block, c.token+": "+c.expect+";") {
			t.Errorf("the %s theme's %s is not %s - the measured value is what clears 4.5:1 on the tinted chip and on the card", c.theme, c.token, c.expect)
		}
	}
}

// TestV2NoSignalColourIsUsedAsTextWithoutItsTextVariant pins the rule at
// the call sites.
//
// A base signal colour as text is what the walk found failing. The check
// is on the CLASS LIST, so a comment cannot satisfy it, and it catches the
// variant-prefixed forms (`hover:text-sig-crit`) too.
func TestV2NoSignalColourIsUsedAsTextWithoutItsTextVariant(t *testing.T) {
	// `text-sig-ok`, `hover:text-sig-ok`, but NOT `text-sig-ok-text`.
	baseText := regexp.MustCompile(`(?:^|[\s"'])(?:[a-z-]+:)*text-sig-(ok|warn|crit)(?:["'\s]|$)`)
	textVariant := regexp.MustCompile(`text-sig-(ok|warn|crit)-text`)

	root := "../../ui-v2/src"
	offenders := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".tsx", ".ts":
		default:
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel := strings.TrimPrefix(path, "../../")
		for i, line := range strings.Split(string(data), "\n") {
			stripped := stripComments(line)
			if !baseText.MatchString(stripped) {
				continue
			}
			// A class list that already says `text-sig-X-text` is fine.
			if textVariant.MatchString(stripped) {
				continue
			}
			offenders++
			trimmed := strings.TrimSpace(stripped)
			if len(trimmed) > 120 {
				trimmed = trimmed[:120]
			}
			t.Errorf(
				"%s:%d uses a base signal colour as text - use the text variant (text-sig-ok-text / -warn-text / -crit-text): %s",
				rel, i+1, trimmed,
			)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if offenders == 0 {
		t.Log("no base signal colour is used as text")
	}
}

// themeBlock returns the body of a theme's CSS block, so a test can read
// one theme's tokens without the other theme's.
func themeBlock(t *testing.T, css, theme string) string {
	t.Helper()
	marker := `:root[data-theme="` + theme + `"]`
	start := strings.Index(css, marker)
	if start < 0 {
		t.Fatalf("the stylesheet has no %s block", marker)
	}
	rest := css[start:]
	end := strings.Index(rest[1:], "\n}")
	if end < 0 {
		t.Fatalf("the %s block is not closed", theme)
	}
	return rest[:end+1]
}
