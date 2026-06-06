package shell

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoFaintTextColor_AUDIT067 pins the surgical fix for #6e7681 (~4.1:1 on the
// dark bg — fails WCAG AA for normal text, passes only for large). It must not
// be used as a foreground TEXT color anywhere in the frontend: not as a literal
// `color:` rule, not as a `text-[#6e7681]` Tailwind utility, and the
// `--fwmon-text-faint` token must not equal it. Decorative #6e7681 (borders/
// backgrounds/charts) is still allowed. Text #6e7681 was retargeted to #8b949e
// (~5.8:1) — deliberately NOT #768390 (the AUDIT-066 target) so the two faint
// tiers stay distinct and don't re-create the v0.10.320 flattening revert.
func TestNoFaintTextColor_AUDIT067(t *testing.T) {
	textColor := regexp.MustCompile(`(?i)[^-]color: ?#6e7681`) // excludes border-color/background-color
	twUtil := regexp.MustCompile(`text-\[#6e7681\]`)

	roots := []string{"../../web", "../../cmd/api/static"}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			switch filepath.Ext(path) {
			case ".html", ".css", ".js":
			default:
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			body := string(data)
			if textColor.MatchString(body) {
				t.Errorf("%s uses #6e7681 as a TEXT color (fails WCAG AA normal-text) — should be #8b949e", path)
			}
			if twUtil.MatchString(body) {
				t.Errorf("%s uses the text-[#6e7681] utility — should be text-[#8b949e]", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// The faint-text design token must be retargeted off #6e7681.
	ds, err := os.ReadFile("../../cmd/api/static/css/admin-design-system.css")
	if err != nil {
		t.Fatalf("read admin-design-system.css: %v", err)
	}
	if strings.Contains(string(ds), "--fwmon-text-faint: #6e7681") {
		t.Error("--fwmon-text-faint is still #6e7681 (fails AA for normal text) — should be #8b949e")
	}
}
