package guardrails

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestVendorListsInSync pins the three hand-maintained copies of the vendor
// set to each other: the API allow-list (handlers.go validVendors), the
// device form's <select id="device-vendor"> (admin.html) and the event-rule
// editor's VENDORS array (admin-event-rules.js). A vendor accepted by the API
// but missing from the form cannot be selected; one in the form but not the
// API is a 400 on save; one missing from the rule editor cannot be scoped.
// internal/snmp's apiValidVendors pins the SNMP registry to the same set.
func TestVendorListsInSync(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return string(data)
	}
	names := func(re *regexp.Regexp, text, what string) []string {
		t.Helper()
		var out []string
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			out = append(out, m[1])
		}
		if len(out) == 0 {
			t.Fatalf("%s: no vendor names found — the extractor regex no longer matches the source", what)
		}
		sort.Strings(out)
		return out
	}

	goSrc := read("../../internal/api/handlers/handlers.go")
	block := regexp.MustCompile(`(?s)var validVendors = map\[string\]bool\{(.*?)\n\}`).FindStringSubmatch(goSrc)
	if block == nil {
		t.Fatal("handlers.go: validVendors map literal not found")
	}
	api := names(regexp.MustCompile(`(?m)^\s*"([a-z_]+)":\s*true,`), block[1], "validVendors")

	html := read("../../web/admin/admin.html")
	sel := regexp.MustCompile(`(?s)<select id="device-vendor">(.*?)</select>`).FindStringSubmatch(html)
	if sel == nil {
		t.Fatal("admin.html: <select id=\"device-vendor\"> not found")
	}
	form := names(regexp.MustCompile(`<option value="([a-z_]+)"`), sel[1], "device-vendor options")

	js := read("../../cmd/api/static/js/admin-event-rules.js")
	arr := regexp.MustCompile(`var VENDORS = \[([^\]]*)\]`).FindStringSubmatch(js)
	if arr == nil {
		t.Fatal("admin-event-rules.js: `var VENDORS = [...]` not found")
	}
	rules := names(regexp.MustCompile(`'([a-z_]+)'`), arr[1], "VENDORS")

	for _, other := range []struct {
		what  string
		names []string
	}{{"admin.html device-vendor options", form}, {"admin-event-rules.js VENDORS", rules}} {
		if strings.Join(other.names, ",") != strings.Join(api, ",") {
			t.Errorf("%s = %v, but handlers.go validVendors = %v — the three lists must carry the same vendor set", other.what, other.names, api)
		}
	}
}
