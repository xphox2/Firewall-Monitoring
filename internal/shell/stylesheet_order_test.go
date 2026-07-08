package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStylesheetOrder_ConsoleFontsWin guards the font-drift regression that hit
// the server-rendered admin pages (probes/sites/irc/connection-detail before
// they were fixed/folded): admin-design-system.css sets `body{font-family:Inter}`
// but the precompiled tailwind.css ships its own `body{font-family:…Roboto}`
// reset. Whichever is linked LATER wins, so the Console body font only renders
// when tailwind.css loads BEFORE admin-design-system.css. Separately, the nav
// redesign is single-sourced in admin-tw-bridge.css, which must be the LAST
// stylesheet so it overrides tailwind's stale component rules.
//
// This test is self-maintaining: it checks every page that loads the design
// system (so any future standalone page is covered automatically), pinning:
//  1. admin-fonts.css is linked (the @font-face for Inter/Archivo/JetBrains).
//  2. tailwind.css is linked BEFORE admin-design-system.css.
//  3. admin-tw-bridge.css is linked AFTER admin-design-system.css (i.e. last).
//
// login.html is intentionally excluded — it is a pre-auth page with its own
// self-contained typography and does not load the design system.
func TestStylesheetOrder_ConsoleFontsWin(t *testing.T) {
	pages, err := filepath.Glob("../../web/admin/*.html")
	if err != nil {
		t.Fatalf("glob admin pages: %v", err)
	}
	if len(pages) == 0 {
		t.Skip("no admin pages found (run from package root)")
	}

	const (
		fonts  = "admin-fonts.css"
		tw     = "tailwind.css"
		ds     = "admin-design-system.css"
		bridge = "admin-tw-bridge.css"
	)

	checked := 0
	for _, path := range pages {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		body := string(data)
		name := filepath.Base(path)

		dsIdx := strings.Index(body, ds)
		if dsIdx < 0 {
			continue // not a design-system page (e.g. login.html) — skip
		}
		checked++

		if !strings.Contains(body, fonts) {
			t.Errorf("%s loads the design system but not %s: the Inter/Archivo/JetBrains @font-face never register and text falls back to system fonts.", name, fonts)
		}

		twIdx := strings.Index(body, tw)
		if twIdx < 0 {
			t.Errorf("%s loads the design system but not %s.", name, tw)
		} else if twIdx > dsIdx {
			t.Errorf("%s links %s AFTER %s: tailwind's `body{font-family}` reset then overrides the Console font (Inter) and the nav renders in the system font. tailwind.css must come first.", name, tw, ds)
		}

		bridgeIdx := strings.LastIndex(body, bridge)
		if bridgeIdx < 0 {
			t.Errorf("%s loads the design system but not %s (the single-sourced nav CSS).", name, bridge)
		} else if bridgeIdx < dsIdx {
			t.Errorf("%s links %s BEFORE %s: the shared nav/sidebar rules must load last to win over tailwind's stale component styles.", name, bridge, ds)
		}
	}

	if checked == 0 {
		t.Error("no design-system pages were checked — glob or path likely wrong")
	}
}
