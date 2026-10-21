package guardrails

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
// (Twemoji Country Flags) supplies the glyphs. Its CC BY 4.0 attribution is
// pinned here.
//
// DB-IP's attribution moved out of the UI (v0.11.357): the CC BY 4.0 credit is
// carried by NOTICE / THIRD-PARTY-NOTICES, which ship with the application, and
// the admin pages must NOT reintroduce an in-app credit link.

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

func TestFlagFont_EveryFlagPageLoadsFaceAndNotices(t *testing.T) {
	for name, src := range adminPagesUsingCommon(t) {
		mustContain(t, name, src, `href="/static/css/admin-fonts.css"`, "the flag face must be loaded wherever flags render")
		if strings.Contains(src, "fwmon-geo-credit") {
			t.Errorf("%s: the in-app DB-IP credit was removed; attribution belongs in NOTICE / THIRD-PARTY-NOTICES", name)
		}
	}

	// The attribution must stay in the shipped notices even though it is no
	// longer advertised in the UI.
	notice := readFile(t, "../../NOTICE")
	for _, want := range []string{
		"IP Geolocation by DB-IP",
		"https://db-ip.com",
		"https://creativecommons.org/licenses/by/4.0/",
	} {
		mustContain(t, "NOTICE", notice, want, "DB-IP Lite attribution")
	}
	mustContain(t, "THIRD-PARTY-NOTICES.md", readFile(t, "../../THIRD-PARTY-NOTICES.md"),
		"IP Geolocation by DB-IP", "DB-IP Lite attribution")
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
