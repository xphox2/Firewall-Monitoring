package shell

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// v0.11.273: country flags render on every browser. AC.flagEmoji draws a
// regional-indicator pair; Windows has no flag glyphs, so Chrome and Edge there
// showed two letters ("US") beside the ISO code. A self-hosted flag-only face
// (Twemoji Country Flags) supplies the glyphs. Its CC BY 4.0 attribution, and
// DB-IP's link-back on every page that shows geo results, are pinned too.

// The attribution chain, stated identically in the served CSS, NOTICE and
// THIRD-PARTY-NOTICES.md.
const twemojiFlagsAttribution = `Twemoji graphics © 2019 Twitter, Inc and other contributors (CC BY 4.0, https://creativecommons.org/licenses/by/4.0/) → "Twemoji Mozilla" 0.6.0 COLR font by Mozilla (https://github.com/mozilla/twemoji-colr) → flag-only subset by TalkJS (country-flag-emoji-polyfill 0.1.10); redistributed unmodified.`

const twemojiFlagsSHA256 = "9f04f14429bb6a9f415c7a4dd902a918d7e81a4f7526c415496fdb063954e3b8"

func TestFlagFont_AssetAndFace(t *testing.T) {
	b, err := os.ReadFile("../../cmd/api/static/fonts/twemoji-country-flags.woff2")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != twemojiFlagsSHA256 {
		t.Errorf("twemoji-country-flags.woff2 sha256 = %s, want %s (the vendored file changed)", got, twemojiFlagsSHA256)
	}

	css := readFile(t, "../../cmd/api/static/css/admin-fonts.css")
	for _, want := range []string{
		`font-family: "Twemoji Country Flags";`,
		"unicode-range: U+1F1E6-1F1FF, U+1F3F4, U+E0062-E0063, U+E0065, U+E0067,\n        U+E006C, U+E006E, U+E0073-E0074, U+E0077, U+E007F;",
		`src: url("/static/fonts/twemoji-country-flags.woff2") format("woff2");`,
		".fwmon-flag {\n    font-family: \"Twemoji Country Flags\",",
		twemojiFlagsAttribution,
	} {
		mustContain(t, "admin-fonts.css", css, want, "the flag face, its scope, and the span that uses it")
	}

	js := readJS(t, "admin-common.js")
	body := funcBody(t, js, `function flagEmoji\(cc\)`)
	mustContain(t, "admin-common.js", body, `<span class="fwmon-flag"`, "the CSS hook for the flag face")
	if !regexp.MustCompile(`">'\s*\+\s*String\.fromCodePoint\(0x1F1E6`).MatchString(body) {
		t.Error("the fwmon-flag span must hold only the regional-indicator pair (the ISO code goes in its own span)")
	}
}

// adminPagesUsingCommon returns every admin page that loads admin-common.js —
// the pages that can render flags and DB-IP results.
func adminPagesUsingCommon(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob("../../web/admin/*.html")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no admin pages found: %v", err)
	}
	out := map[string]string{}
	for _, p := range paths {
		src := readFile(t, p)
		if strings.Contains(src, "/static/js/admin-common.js") {
			out[filepath.Base(p)] = src
		}
	}
	if len(out) < 3 {
		t.Fatalf("found %d pages loading admin-common.js, want at least admin, device-detail, connection-detail", len(out))
	}
	return out
}

func TestFlagFont_EveryFlagPageLoadsFaceAndCredit(t *testing.T) {
	credit := regexp.MustCompile(`<a class="fwmon-geo-credit" href="https://db-ip\.com"[^>]*>IP Geolocation by DB-IP</a>`)
	for name, src := range adminPagesUsingCommon(t) {
		mustContain(t, name, src, `href="/static/css/admin-fonts.css"`, "the flag face must be loaded wherever flags render")
		i := strings.Index(src, `<div class="sidebar-footer">`)
		if i < 0 {
			t.Errorf("%s: no sidebar-footer", name)
			continue
		}
		end := strings.Index(src[i:], "\n        </div>")
		if end < 0 || !credit.MatchString(src[i:i+end]) {
			t.Errorf("%s: the sidebar footer must link DB-IP.com (\"IP Geolocation by DB-IP\") — DB-IP Lite's CC BY 4.0 terms", name)
		}
	}
	mustContain(t, "admin-shared.css", readFile(t, "../../cmd/api/static/css/admin-shared.css"),
		".fwmon-geo-credit {\n    color: var(--fwmon-text-mute);", "the credit uses the AA text token in both themes")
}

func TestFlagFont_Notices(t *testing.T) {
	notice := readFile(t, "../../NOTICE")
	mustContain(t, "NOTICE", notice, twemojiFlagsAttribution, "the flag font's attribution")
	mustContain(t, "NOTICE", notice, "cmd/api/static/fonts/twemoji-country-flags.woff2", "its file")

	tp := readFile(t, "../../THIRD-PARTY-NOTICES.md")
	for _, want := range []string{
		twemojiFlagsAttribution,
		"`cmd/api/static/fonts/twemoji-country-flags.woff2`",
		"https://creativecommons.org/licenses/by/4.0/",
		"`cmd/api/static/fonts/archivo-latin.woff2`",
		"`internal/classify/geoipdata/dbip-country-lite.mmdb`",
		"`internal/classify/geoipdata/dbip-asn-lite.mmdb`",
		"Applies to: Inter, JetBrains Mono, Archivo.",
		"Applies to: Twemoji Country Flags, DB-IP Lite databases.",
	} {
		mustContain(t, "THIRD-PARTY-NOTICES.md", tp, want, "every vendored font and bundled dataset is listed with its license")
	}
}
