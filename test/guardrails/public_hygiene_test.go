package guardrails

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The public repo must not publish addresses, hosts or paths from anyone's
// real environment. Test data uses reserved ranges instead:
//
//   - RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for outside hosts,
//   - RFC 2544 (198.18.0.0/15) for "our own" public space,
//   - RFC 1918 / CGNAT / link-local for LANs,
//   - RFC 3849 (2001:db8::/32) for IPv6.
//
// TestPublicHygiene_NoRealAddressesOrHomePaths scans every tracked text file
// for IPv4/IPv6 literals outside those ranges (including addresses inside
// mib-2 table OIDs and address templates built from a public prefix) and for
// /Users/<name>, /home/<name> or C:\Users\<name> paths. Anything else that is
// legitimately public (well-known resolvers, placeholders, boundary values in
// range tests) goes on the reviewed allowlist below with a reason.

// hygieneAllowIPv4 lists public IPv4 literals that are allowed, with the reason.
var hygieneAllowIPv4 = map[string]string{
	"1.1.1.1":         "well-known public resolver",
	"8.8.8.8":         "well-known public resolver (also the GeoIP test control)",
	"8.8.4.4":         "well-known public resolver",
	"9.9.9.9":         "well-known public resolver",
	"8.8.8.0":         "network address of the well-known resolver /24 in a CIDR test",
	"1.2.3.4":         "conventional placeholder",
	"2.2.2.2":         "conventional placeholder",
	"3.3.3.3":         "conventional placeholder",
	"5.5.5.5":         "conventional placeholder",
	"5.6.7.8":         "conventional placeholder",
	"63.255.255.255":  "boundary value in a classification range test",
	"99.84.0.1":       "boundary value in a classification range test",
	"100.63.255.255":  "boundary value just below CGNAT 100.64.0.0/10",
	"128.0.0.0":       "boundary value (start of the upper half of IPv4)",
	"169.255.0.1":     "boundary value just above link-local 169.254.0.0/16",
	"192.175.255.255": "boundary value just below 192.176/192.168 checks",
	"142.250.0.1":     "generic well-known CDN address used as an example destination",
	"34.117.0.2":      "generic cloud address used as an example destination",
	"1.3.6.1":         "SNMP OID prefix (iso.org.dod.internet), not an address",
	"12.2.4.1":        "dotted section number, not an address",
	"2.2.1.1":         "ifTable OID tail (…2.2.1.<column>) after an ellipsis, not an address",
	"2.2.1.10":        "ifTable OID tail (…2.2.1.<column>) after an ellipsis, not an address",
}

// hygieneAllowIPv6 lists public IPv6 literals that are allowed.
var hygieneAllowIPv6 = map[string]string{
	"2606:4700:4700::1111": "well-known public resolver",
}

// hygieneAllowHomes lists /home/<name> or /Users/<name> examples that are fine.
var hygieneAllowHomes = map[string]string{
	"/home/fwmon": "the service user created by deploy.sh",
}

var hygieneReserved = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

var (
	dottedRun      = regexp.MustCompile(`[0-9.]*[0-9][0-9.]*`)
	ipv6Cand       = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	homePathRe     = regexp.MustCompile(`/(?:Users|home)/[A-Za-z0-9._-]+`)
	winHomePathRe  = regexp.MustCompile(`[A-Za-z]:\\{1,2}Users\\{1,2}[A-Za-z0-9._-]+`)
	ellipsisRe     = regexp.MustCompile(`\.{2,}`)
	dashedIPv4Re   = regexp.MustCompile(`[0-9]{1,3}(?:-[0-9]{1,3}){3}`)
	hygieneSkipExt = regexp.MustCompile(`\.(mmdb|woff2|png|jpe?g|gif|ico)$`)
)

// hygieneSkip lists generated or vendored files by exact path. First-party
// files next to them (diagram-cytoscape.js, for example) are still scanned.
var hygieneSkip = map[string]bool{
	"package-lock.json":                            true,
	"cmd/api/static/css/tailwind.css":              true, // generated
	"cmd/api/static/css/gridstack.min.css":         true,
	"cmd/api/static/css/uPlot.min.css":             true,
	"cmd/api/static/js/chart.umd.min.js":           true,
	"cmd/api/static/js/chartjs-plugin-zoom.min.js": true,
	"cmd/api/static/js/cose-base.js":               true,
	"cmd/api/static/js/cytoscape-fcose.js":         true,
	"cmd/api/static/js/cytoscape.min.js":           true,
	"cmd/api/static/js/gridstack-all.min.js":       true,
	"cmd/api/static/js/layout-base.js":             true,
	"cmd/api/static/js/uPlot.iife.min.js":          true,
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

func hygieneRepoFiles(t *testing.T) (string, []string) {
	t.Helper()
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not inside a git work tree: %v", err)
	}
	root := strings.TrimSpace(string(top))
	cmd := exec.Command("git", "ls-files", "--full-name", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" && !hygieneSkipExt.MatchString(f) && !hygieneSkip[f] {
			files = append(files, f)
		}
	}
	return root, files
}

// octets parses dotted parts as IPv4 octets (0-255). Leading zeros are
// accepted, so a zero-padded form (010.000.000.001) is the same address.
func octets(parts []string) (netip.Addr, bool) {
	var b [4]byte
	for i, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return netip.Addr{}, false
		}
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// ipv4Allowed reports whether a is in a reserved range or on the allowlist.
func ipv4Allowed(a netip.Addr) bool {
	for _, p := range hygieneReserved {
		if p.Contains(a) {
			return true
		}
	}
	_, ok := hygieneAllowIPv4[a.String()]
	return ok
}

// ipv4Excuses reports whether a, seen as one window of an ambiguous 5-part
// run, is enough to explain the run away. A block defined only by its first
// octet (0/8, 10/8, 127/8, 224/4, 240/4) is not: "10.a.b.c.d" is an index 10
// in front of the address a.b.c.d just as often as it is 10.a.b.c plus an
// index.
func ipv4Excuses(a netip.Addr) bool {
	for _, p := range hygieneReserved {
		if p.Bits() > 8 && p.Contains(a) {
			return true
		}
	}
	_, ok := hygieneAllowIPv4[a.String()]
	return ok
}

// hygieneMib2Tables maps the mib-2 tables indexed by an IPv4 address (the arc
// after 1.3.6.1.2.1) to the positions, counted from the start of the full OID,
// where an address starts in the index.
var hygieneMib2Tables = []struct {
	arc  []string
	addr []int
}{
	{[]string{"4", "20", "1"}, []int{10}},          // ipAddrTable: col.ip
	{[]string{"4", "21", "1"}, []int{10}},          // ipRouteTable: col.dest
	{[]string{"4", "22", "1"}, []int{11}},          // ipNetToMediaTable: col.ifIndex.ip
	{[]string{"4", "24", "4", "1"}, []int{11, 20}}, // ipCidrRouteTable: col.dest.mask.tos.nexthop
	{[]string{"6", "13", "1"}, []int{10, 15}},      // tcpConnTable: col.local.port.remote.port
	{[]string{"7", "5", "1"}, []int{10}},           // udpTable: col.local.port
}

// mib2TableAddrs returns where an IPv4 address starts in parts, when parts is
// a full OID under one of hygieneMib2Tables. Enterprise OIDs (1.3.6.1.4.1…)
// never match.
func mib2TableAddrs(parts []string) []int {
	if len(parts) < 8 || strings.Join(parts[:6], ".") != "1.3.6.1.2.1" {
		return nil
	}
	var out []int
	for _, tb := range hygieneMib2Tables {
		if len(parts) < 6+len(tb.arc) || strings.Join(parts[6:6+len(tb.arc)], ".") != strings.Join(tb.arc, ".") {
			continue
		}
		for _, i := range tb.addr {
			if i+4 <= len(parts) {
				out = append(out, i)
			}
		}
	}
	return out
}

func isASCIILetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_' }

func isWordByte(b byte) bool { return isASCIILetter(b) || b >= '0' && b <= '9' }

// isTemplateTail reports whether rest, the text right after "a.b.c.", builds
// addresses from that prefix: a Printf verb (%d, %03d, %[1]d, %v…), a format
// or template placeholder ({i}, ${i}), a closing quote followed by a Go / JS
// "+" or SQL "||" concatenation, or a placeholder host part (*, x, X, n, N).
func isTemplateTail(rest string) bool {
	if rest == "" {
		return false
	}
	switch rest[0] {
	case '\'', '"', '`':
		r := strings.TrimLeft(rest[1:], " \t")
		return strings.HasPrefix(r, "+") || strings.HasPrefix(r, "||")
	case '%', '{', '$':
		return true
	}
	if strings.HasPrefix(rest, "**") {
		return false // Markdown bold after a version number, not a wildcard
	}
	i := 0
	for i < len(rest) && strings.IndexByte("*xXnN", rest[i]) >= 0 {
		i++
	}
	return i > 0 && (i == len(rest) || !isWordByte(rest[i]))
}

// badIPv4 returns the disallowed addresses in text, following the run rules.
func badIPv4(text string) []string {
	var bad []string
	for _, loc := range dottedRun.FindAllStringIndex(text, -1) {
		// Two or more dots in a row are an ellipsis, not part of a number:
		// each piece between them is checked as a run of its own.
		start := loc[0]
		for _, m := range ellipsisRe.FindAllStringIndex(text[loc[0]:loc[1]], -1) {
			bad = badIPv4Run(text, start, loc[0]+m[0], bad)
			start = loc[0] + m[1]
		}
		bad = badIPv4Run(text, start, loc[1], bad)
	}
	return bad
}

// badIPv4Run checks the dotted run text[s:e] and appends what it flags.
func badIPv4Run(text string, s, e int, bad []string) []string {
	if s >= e {
		return bad
	}
	flag := func(parts []string) {
		if a, ok := octets(parts); ok && !ipv4Allowed(a) {
			bad = append(bad, a.String())
		}
	}
	run := text[s:e]
	oid := false
	if strings.HasPrefix(run, ".") {
		// ".1.3.6.1.2" after a space, quote or bracket is an OID fragment.
		// After a letter ("host.a.b.c.d") the dot is just a separator, so the
		// rest of the run is checked as usual.
		if s == 0 || !isASCIILetter(text[s-1]) {
			oid = true
		}
		run = run[1:]
	}
	trailingDot := strings.HasSuffix(run, ".")
	run = strings.TrimRight(run, ".")
	parts := strings.Split(run, ".")
	n := len(parts)
	if n >= 6 {
		seen := map[int]bool{}
		// mib-2 tables indexed by an address carry it inside the OID.
		for _, i := range mib2TableAddrs(parts) {
			seen[i] = true
			flag(parts[i : i+4])
		}
		// IP-MIB indexes an address as 1.4.a.b.c.d (IPv4, length 4), bare
		// or at the end of a full OID. The enterprises arc 1.3.6.1.4.1 is
		// not such an index, and neither is mib-2's ip group 1.3.6.1.2.1.4
		// in a truncated OID.
		i := n - 6
		enterprises := i >= 3 && parts[i-3] == "1" && parts[i-2] == "3" && parts[i-1] == "6"
		ipGroup := strings.Join(parts[:i], ".") == "1.3.6.1.2"
		if parts[i] == "1" && parts[i+1] == "4" && !enterprises && !ipGroup && !seen[n-4] {
			flag(parts[n-4:])
		}
		return bad
	}
	if oid {
		return bad
	}
	switch n {
	case 3:
		// A template prefix: "a.b.c." followed by a verb, a concatenation
		// or a placeholder.
		if trailingDot && isTemplateTail(text[e:]) {
			if a, ok := octets(append(parts, "1")); ok && !ipv4Allowed(a) {
				bad = append(bad, run+".*")
			}
		}
	case 4:
		flag(parts)
	case 5:
		// IP.index or index.IP (SNMP table OIDs): the run is fine when either
		// window is a strongly allowed address; otherwise flag the window
		// that is public.
		a1, ok1 := octets(parts[:4])
		a2, ok2 := octets(parts[1:])
		if ok1 && ipv4Excuses(a1) || ok2 && ipv4Excuses(a2) {
			break
		}
		if ok1 && !ipv4Allowed(a1) {
			bad = append(bad, a1.String())
		} else if ok2 && !ipv4Allowed(a2) {
			bad = append(bad, a2.String())
		}
	}
	return bad
}

// badDashedIPv4 returns public addresses written with dashes instead of dots,
// the form reverse-DNS names use (A-B-C-D.rev.example.net, and after a word
// such as cpe-A-B-C-D.example.net when a domain follows). A run that is part
// of a longer token (a timestamp 2026-10-03T19-42-15, SVG path data
// "s-3-2-3-9h18", a version) is not one.
func badDashedIPv4(text string) []string {
	var bad []string
	isLetter := func(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	for _, loc := range dashedIPv4Re.FindAllStringIndex(text, -1) {
		s, e := loc[0], loc[1]
		next, after := byte(0), byte(0)
		if e < len(text) {
			next = text[e]
		}
		if e+1 < len(text) {
			after = text[e+1]
		}
		domainFollows := next == '.' && isLetter(after)
		if s > 0 && (isWordByte(text[s-1]) || text[s-1] == '.' || text[s-1] == '-' && !domainFollows) {
			continue
		}
		if isWordByte(next) || next == '-' || next == '.' && isDigit(after) {
			continue
		}
		if a, ok := octets(strings.Split(text[s:e], "-")); ok && !ipv4Allowed(a) {
			bad = append(bad, text[s:e])
		}
	}
	return bad
}

func badIPv6(text string) []string {
	var bad []string
	doc := netip.MustParsePrefix("2001:db8::/32")
	global := netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20}), 3) // the global unicast block
	for _, loc := range ipv6Cand.FindAllStringIndex(text, -1) {
		c := text[loc[0]:loc[1]]
		// A candidate that starts inside a word ("id:2a00:…" matches from
		// the "d") has a fragment for its first group: drop it. One that
		// starts with a lone colon ("addr:2a00:…") loses the colon.
		if loc[0] > 0 && isWordByte(text[loc[0]-1]) {
			if i := strings.IndexByte(c, ':'); i >= 0 {
				c = c[i+1:]
			}
		}
		if strings.HasPrefix(c, ":") && !strings.HasPrefix(c, "::") {
			c = c[1:]
		}
		a, err := netip.ParseAddr(c)
		if err != nil || !a.Is6() || !global.Contains(a) || doc.Contains(a) {
			continue
		}
		if _, ok := hygieneAllowIPv6[a.String()]; !ok {
			bad = append(bad, a.String())
		}
	}
	return bad
}

func badHomes(text string) []string {
	var bad []string
	for _, re := range []*regexp.Regexp{homePathRe, winHomePathRe} {
		for _, m := range re.FindAllString(text, -1) {
			if _, ok := hygieneAllowHomes[m]; !ok {
				bad = append(bad, m)
			}
		}
	}
	return bad
}

func TestPublicHygiene_NoRealAddressesOrHomePaths(t *testing.T) {
	root, files := hygieneRepoFiles(t)
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil || bytes.IndexByte(data, 0) >= 0 {
			continue // unreadable or binary
		}
		text := string(data)
		for _, kind := range []struct {
			name string
			hits []string
		}{
			{"public IPv4 address", badIPv4(text)},
			{"public IPv4 address (dashed form)", badDashedIPv4(text)},
			{"public IPv6 address", badIPv6(text)},
			{"home-directory path", badHomes(text)},
		} {
			for _, h := range kind.hits {
				t.Errorf("%s: %s %q — use a reserved test range / example path, or add it to the reviewed allowlist in public_hygiene_test.go with a reason", f, kind.name, h)
			}
		}
	}
}

// The rule samples below are assembled at run time, so this file holds no
// literal public address or home path and is scanned like any other file.

// sampleIP formats a dotted address from its octets. A trailing format verb
// ("%03d") zero-pads each octet.
func sampleIP(o ...any) string {
	format := "%d"
	if f, ok := o[len(o)-1].(string); ok {
		format, o = f, o[:len(o)-1]
	}
	s := make([]string, len(o))
	for i, v := range o {
		s[i] = fmt.Sprintf(format, v)
	}
	return strings.Join(s, ".")
}

func TestPublicHygiene_Rules(t *testing.T) {
	pub := sampleIP(81, 2, 69, 160)   // a public address
	pub3 := sampleIP(81, 2, 69) + "." // its /24 as a template prefix
	for _, tc := range []struct {
		text string
		bad  int
	}{
		{"peer 203.0.113.7 and 198.19.9.155", 0},
		{"peer " + pub, 1},
		{"oid .1.3.6.1.2.1.4.20.1.1", 0},
		{"oid \".1.3.6.1.4.1.12356.101.4.1.1\"", 0},
		{"ifIndex 192.168.105.1.7", 0},
		{"idx " + pub + ".1", 1},
		// An index in a first-octet-only block does not excuse the address.
		{"idx 10." + pub, 1},
		{"idx 127." + pub, 1},
		{"idx 224." + pub, 1},
		{"idx 240." + pub, 1},
		{"idx 0." + pub, 1},
		{"idx 10.0.0.1.5", 0},
		// IP-MIB index 1.4.a.b.c.d, bare or at the end of a full OID.
		{"ipAddressIfIndex 1.4." + pub, 1},
		{"oid .1.3.6.1.2.1.4.34.1.3.1.4." + pub, 1},
		{"ipAddressIfIndex 1.4.192.168.1.1", 0},
		{"cpmCPUTotalTable (1.3.6.1.4.1.9.9.109)", 0},
		// A dot after a letter is a separator, not the start of an OID.
		{"host." + pub, 1},
		{"key=host.203.0.113.9", 0},
		{"at the end of a sentence " + pub + ".", 1},
		{"fmt.Sprintf(\"" + pub3 + "%d\", i)", 1},
		{"fmt.Sprintf(\"" + pub3 + "%v\", i)", 1},
		{"fmt.Sprintf(\"" + pub3 + "%s\", i)", 1},
		{"ip := \"" + pub3 + "\" + strconv.Itoa(i)", 1},
		{"const ip = `" + pub3 + "${i}`", 1},
		{"SELECT '" + pub3 + "' || g", 1},
		{"fmt.Sprintf(\"198.18.101.%d\", i)", 0},
		{"ip := \"198.18.101.\" + s", 0},
		{"version 0.11.273 and 1.3.45", 0},
		// Addresses inside mib-2 table OIDs, with or without a leading dot.
		{"ipAddrTable .1.3.6.1.2.1.4.20.1.1." + pub, 1},
		{"ipAddrTable 1.3.6.1.2.1.4.20.1.2." + pub + ".1", 1},
		{"ipRouteTable 1.3.6.1.2.1.4.21.1.7." + pub, 1},
		{"ipRouteTable column 4 .1.3.6.1.2.1.4.21.1.4." + pub, 1},
		{"ipNetToMediaTable .1.3.6.1.2.1.4.22.1.2.5." + pub, 1},
		{"ipCidrRouteTable dest .1.3.6.1.2.1.4.24.4.1.4." + pub + ".255.255.255.0.0.192.168.105.1", 1},
		{"ipCidrRouteTable next hop .1.3.6.1.2.1.4.24.4.1.4.10.0.0.0.255.0.0.0.0." + pub, 1},
		{"tcpConnTable remote .1.3.6.1.2.1.6.13.1.1.192.168.105.10.443." + pub + ".50123", 1},
		{"tcpConnTable both .1.3.6.1.2.1.6.13.1.1." + pub + ".443." + pub + ".50123", 2},
		{"udpTable .1.3.6.1.2.1.7.5.1.1." + pub + ".161", 1},
		{"ipAddrTable .1.3.6.1.2.1.4.20.1.1.192.168.105.1", 0},
		{"ipNetToMediaTable .1.3.6.1.2.1.4.22.1.2.5.10.0.0.1", 0},
		{"tcpConnTable .1.3.6.1.2.1.6.13.1.1.10.0.0.1.22.192.168.105.9.50000", 0},
		{"truncated ipCidrRouteTable .1.3.6.1.2.1.4.24.4.1.4", 0},
		{"enterprise .1.3.6.1.4.1.12356.4.20.1.1." + pub, 0},
		// More template forms: JS / SQL concatenation and format tails.
		{"const ip = '" + pub3 + "' + i", 1},
		{"const ip = '" + pub3 + "'+i", 1},
		{"SELECT '" + pub3 + "'||g", 1},
		{"fmt.Sprintf(\"" + pub3 + "%03d\", i)", 1},
		{"fmt.Sprintf(\"" + pub3 + "%[1]d\", i)", 1},
		{"range " + pub3 + "*", 1},
		{"range " + pub3 + "X", 1},
		{"range " + pub3 + "N", 1},
		{"f\"" + pub3 + "{i}\"", 1},
		{"Go 1.25.12 to 1.25.13.** bumped", 0},
		{"version 1.2.3.next", 0},
		// An ellipsis is not an OID's leading dot.
		{"elided ..." + pub, 1},
		{"see..." + pub, 1},
		{pub + "... and more", 1},
		{"ifTable column …2.2.1.10 and ...2.2.1.1", 0},
		{"mask 255.255.255.252", 0},
		// Zero-padded octets are the same address.
		{"0" + pub + " is an address", 1},
		{"peer " + sampleIP(81, 2, 69, 160, "%03d"), 1},
		{"peer " + sampleIP(10, 0, 0, 1, "%03d"), 0},
	} {
		if got := len(badIPv4(tc.text)); got != tc.bad {
			t.Errorf("badIPv4(%q) = %d hits, want %d", tc.text, got, tc.bad)
		}
	}
	dashed := strings.ReplaceAll(pub, ".", "-")
	for _, tc := range []struct {
		text string
		bad  int
	}{
		{"peer " + dashed, 1},
		{"peer " + dashed + ".", 1},
		{"rdns " + dashed + ".rev.example.net", 1},
		{"rdns cpe-" + dashed + ".example.net", 1},
		{"rdns " + strings.ReplaceAll(sampleIP(81, 2, 69, 160, "%03d"), ".", "-"), 1},
		{"host ip-10-0-0-1 and 203-0-113-7.example.com", 0},
		{"placeholder 1-2-3-4", 0},
		{"stamp 2026-10-03-14-30 and 10-03-14-30-00 and T19-42-15-24h", 0},
		{"build 1.2-3-4-5-6 and v" + dashed, 0},
		{"range " + dashed + ".5 and " + dashed + "-7", 0},
		{`<path d="M6 8c0 7-3 9-3 9h18s-3-2-3-9"/> and "11-8 11-8-11-8-11-8z"`, 0},
		{"host ip-" + dashed, 0}, // a word before the dash: only an address with a domain after it counts
	} {
		if got := len(badDashedIPv4(tc.text)); got != tc.bad {
			t.Errorf("badDashedIPv4(%q) = %d hits, want %d", tc.text, got, tc.bad)
		}
	}
	if len(badIPv6("dns 2606:4700:4700::1111 doc 2001:db8::1 mac aa:bb:cc:dd:ee:ff port 2055:2055")) != 0 {
		t.Error("allowed IPv6 forms flagged")
	}
	if len(badIPv6("peer "+strings.Join([]string{"2a00", "1450", "4001", "", "1"}, ":"))) != 1 {
		t.Error("a public IPv6 address was not flagged")
	}
	v6 := strings.Join([]string{"2a00", "1450", "4001", "", "1"}, ":")
	for _, text := range []string{"addr:" + v6, "id:" + v6, "ip=" + v6} {
		if len(badIPv6(text)) != 1 {
			t.Errorf("badIPv6(%q): a public IPv6 address after a word or colon was not flagged", text)
		}
	}
	if len(badIPv6("ula fd00:2a00::1 and std::string")) != 0 {
		t.Error("non-global IPv6 forms flagged")
	}
	if len(badHomes("/home/fwmon/x and /"+"Users"+"/someone/src")) != 1 {
		t.Error("home-path rule wrong")
	}
	for _, text := range []string{`C:\` + `Users\someone\src`, `"C:\\` + `Users\\someone"`, `d:\` + `Users\x`} {
		if len(badHomes(text)) != 1 {
			t.Errorf("badHomes(%q): a Windows home path was not flagged", text)
		}
	}
}
