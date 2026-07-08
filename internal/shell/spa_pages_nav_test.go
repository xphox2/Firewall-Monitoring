package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestSPAPagesMatchPageDivs guards the navigation contract for the SPA. Probes,
// Sites and IRC were originally standalone HTML documents that must NOT appear
// in SPA_PAGES (listing them made the click interceptor preventDefault() the
// real navigation and load blank). They have since been folded into admin.html
// as real SPA pages, so the modern invariant is simply structural.
//
// Invariant: every key in SPA_PAGES MUST correspond to a `page-<name>` div in
// admin.html (i.e. it is genuinely an in-page SPA tab), and any remaining
// standalone pages must NOT appear in SPA_PAGES.
func TestSPAPagesMatchPageDivs(t *testing.T) {
	js, err := os.ReadFile("../../cmd/api/static/js/admin-main.js")
	if err != nil {
		t.Fatalf("read admin-main.js: %v", err)
	}
	html, err := os.ReadFile("../../web/admin/admin.html")
	if err != nil {
		t.Fatalf("read admin.html: %v", err)
	}

	block := regexp.MustCompile(`(?s)var SPA_PAGES = \{(.*?)\};`).FindSubmatch(js)
	if block == nil {
		t.Fatal("could not find SPA_PAGES in admin-main.js")
	}
	keyRe := regexp.MustCompile(`'?([a-z-]+)'?\s*:\s*1`)
	matches := keyRe.FindAllStringSubmatch(string(block[1]), -1)
	if len(matches) == 0 {
		t.Fatal("parsed no page keys from SPA_PAGES")
	}

	htmlStr := string(html)
	// probes/sites/irc are now folded-in SPA pages with their own page-<name>
	// divs; only genuinely-separate documents remain standalone.
	standalone := map[string]bool{"network": true}
	for _, m := range matches {
		page := m[1]
		if standalone[page] {
			t.Errorf("SPA_PAGES contains standalone page %q — it is served as its own HTML document and will load blank when the click interceptor hijacks it", page)
			continue
		}
		if !strings.Contains(htmlStr, `id="page-`+page+`"`) {
			t.Errorf("SPA_PAGES lists %q but admin.html has no <div id=\"page-%s\"> — clicking it would load blank", page, page)
		}
	}
}
