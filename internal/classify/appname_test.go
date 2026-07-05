package classify

import "testing"

// TestFromAppName pins the exporter-app-name mapping: known protocol-shaped
// names map to a definite category (case-insensitive, "-base" container
// suffix stripped), everything else reports ok=false so the caller falls
// through to the port heuristic.
func TestFromAppName(t *testing.T) {
	cases := []struct {
		name   string
		want   Category
		wantOK bool
	}{
		{"ssl", Web, true},
		{"SSL", Web, true}, // exporters vary in case
		{"web-browsing", Web, true},
		{"dns", DNS, true},
		{"dns-base", DNS, true}, // PAN container-app convention
		{"ms-rdp", RemoteAccess, true},
		{"ssh", RemoteAccess, true},
		{"bittorrent-base", P2P, true},
		{"  ntp  ", Management, true}, // whitespace-tolerant
		{"", Unknown, false},
		{"salesforce", Unknown, false}, // SaaS name — deliberately unmapped
		{"totally-made-up", Unknown, false},
		{"-base", Unknown, false}, // suffix strip must not match the empty key
	}
	for _, tc := range cases {
		got, ok := FromAppName(tc.name)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("FromAppName(%q) = (%v, %v), want (%v, %v)", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}
