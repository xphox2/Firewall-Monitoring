package guardrails

import (
	"bytes"
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
// for IPv4/IPv6 literals outside those ranges and for /Users/<name> or
// /home/<name> paths. Anything else that is legitimately public (well-known
// resolvers, placeholders, boundary values in range tests) goes on the reviewed
// allowlist below with a reason.

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
	dottedRun   = regexp.MustCompile(`[0-9.]*[0-9][0-9.]*`)
	ipv6Cand    = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	homePathRe  = regexp.MustCompile(`/(?:Users|home)/[A-Za-z0-9._-]+`)
	hygieneSkip = regexp.MustCompile(`\.(mmdb|woff2|png|jpe?g|gif|ico)$|\.min\.js$|(^|/)package-lock\.json$|(^|/)tailwind\.css$|chart\.umd|cytoscape|uplot|gridstack`)
)

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
		if f != "" && !hygieneSkip.MatchString(f) {
			files = append(files, f)
		}
	}
	return root, files
}

// octets parses dotted parts as IPv4 octets (no leading zeros, 0-255).
func octets(parts []string) (netip.Addr, bool) {
	var b [4]byte
	for i, p := range parts {
		if len(p) == 0 || len(p) > 3 || (len(p) > 1 && p[0] == '0') {
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

func ipv4Allowed(a netip.Addr) bool {
	for _, p := range hygieneReserved {
		if p.Contains(a) {
			return true
		}
	}
	_, ok := hygieneAllowIPv4[a.String()]
	return ok
}

// badIPv4 returns the disallowed addresses in text, following the run rules.
func badIPv4(text string) []string {
	var bad []string
	for _, loc := range dottedRun.FindAllStringIndex(text, -1) {
		run := text[loc[0]:loc[1]]
		if strings.HasPrefix(run, ".") {
			continue // OID fragment such as .1.3.6.1.2
		}
		trailingDot := strings.HasSuffix(run, ".")
		run = strings.TrimRight(run, ".")
		parts := strings.Split(run, ".")
		switch len(parts) {
		case 3:
			// A template prefix: "a.b.c." followed by %d, ' || or x.
			rest := text[loc[1]:]
			if trailingDot && (strings.HasPrefix(rest, "%d") || strings.HasPrefix(rest, "' ||") || strings.HasPrefix(rest, "x")) {
				if a, ok := octets(append(parts, "1")); ok && !ipv4Allowed(a) {
					bad = append(bad, run+".*")
				}
			}
		case 4:
			if a, ok := octets(parts); ok && !ipv4Allowed(a) {
				bad = append(bad, a.String())
			}
		case 5:
			// IP.index or index.IP (SNMP table OIDs): flag only if neither
			// window is an allowed address.
			a1, ok1 := octets(parts[:4])
			a2, ok2 := octets(parts[1:])
			if (ok1 && !ipv4Allowed(a1) || !ok1) && (ok2 && !ipv4Allowed(a2) || !ok2) && (ok1 || ok2) {
				if ok1 {
					bad = append(bad, a1.String())
				} else {
					bad = append(bad, a2.String())
				}
			}
		}
	}
	return bad
}

func badIPv6(text string) []string {
	var bad []string
	doc := netip.MustParsePrefix("2001:db8::/32")
	global := netip.MustParsePrefix("2000::/3")
	for _, c := range ipv6Cand.FindAllString(text, -1) {
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
	for _, m := range homePathRe.FindAllString(text, -1) {
		if _, ok := hygieneAllowHomes[m]; !ok {
			bad = append(bad, m)
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
			{"public IPv6 address", badIPv6(text)},
			{"home-directory path", badHomes(text)},
		} {
			for _, h := range kind.hits {
				t.Errorf("%s: %s %q — use a reserved test range / example path, or add it to the reviewed allowlist in public_hygiene_test.go with a reason", f, kind.name, h)
			}
		}
	}
}

func TestPublicHygiene_Rules(t *testing.T) {
	for _, tc := range []struct {
		text string
		bad  int
	}{
		{"peer 203.0.113.7 and 198.19.9.155", 0},
		{"peer 81.2.69.160", 1},
		{"oid .1.3.6.1.2.1.4.20.1.1", 0},
		{"ifIndex 192.168.105.1.7", 0},
		{"idx 81.2.69.160.1", 1},
		{"at the end of a sentence 81.2.69.160.", 1},
		{"fmt.Sprintf(\"81.2.69.%d\", i)", 1},
		{"fmt.Sprintf(\"198.18.101.%d\", i)", 0},
		{"version 0.11.273 and 1.3.45", 0},
		{"mask 255.255.255.252", 0},
		{"01.2.3.4 is not an address", 0},
	} {
		if got := len(badIPv4(tc.text)); got != tc.bad {
			t.Errorf("badIPv4(%q) = %d hits, want %d", tc.text, got, tc.bad)
		}
	}
	if len(badIPv6("dns 2606:4700:4700::1111 doc 2001:db8::1 mac aa:bb:cc:dd:ee:ff port 2055:2055")) != 0 {
		t.Error("allowed IPv6 forms flagged")
	}
	if len(badIPv6("peer 2a00:1450:4001::1")) != 1 {
		t.Error("a public IPv6 address was not flagged")
	}
	if len(badHomes("/home/fwmon/x and /Users/someone/src")) != 1 {
		t.Error("home-path rule wrong")
	}
}
