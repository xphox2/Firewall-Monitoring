package httputil

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestIsBlockedIP_AUDIT020 pins the SSRF block list, especially the ranges the
// raw net.IP predicates miss (CGNAT 100.64.0.0/10 and 0.0.0.0/8) plus multicast.
func TestIsBlockedIP_AUDIT020(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},       // loopback
		{"0.0.0.0", true},         // unspecified
		{"0.1.2.3", true},         // 0.0.0.0/8 (NEW)
		{"10.1.2.3", true},        // RFC1918
		{"172.16.5.4", true},      // RFC1918
		{"192.168.1.1", true},     // RFC1918
		{"169.254.1.1", true},     // link-local
		{"100.64.0.1", true},      // CGNAT (NEW)
		{"100.127.255.254", true}, // CGNAT upper edge (NEW)
		{"224.0.0.1", true},       // multicast (NEW)
		{"fc00::1", true},         // ULA (IsPrivate)
		{"::1", true},             // IPv6 loopback
		{"8.8.8.8", false},        // public
		{"1.1.1.1", false},        // public
		{"100.63.255.255", false}, // just below CGNAT — must NOT be blocked
		{"99.84.0.1", false},      // public
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := IsBlockedIP(ip); got != tc.blocked {
			t.Errorf("IsBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
		}
	}
	if !IsBlockedIP(nil) {
		t.Error("IsBlockedIP(nil) = false, want true (fail closed)")
	}
}

// TestSafeDialContext_RefusesBlocked_AUDIT020 verifies the pinned dialer
// refuses a host that resolves to a blocked IP — the TOCTOU close. Using an IP
// literal that resolves to itself makes this deterministic and offline.
func TestSafeDialContext_RefusesBlocked_AUDIT020(t *testing.T) {
	dial := SafeDialContext(2 * time.Second)
	ctx := context.Background()

	// 127.0.0.1 and a 0.0.0.0/8 literal must both be refused before any connect.
	for _, addr := range []string{"127.0.0.1:9", "10.0.0.5:80", "100.64.0.1:443"} {
		conn, err := dial(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			t.Errorf("SafeDialContext dialed blocked %s, want refusal", addr)
			continue
		}
		if !strings.Contains(err.Error(), "blocked address") {
			t.Errorf("SafeDialContext(%s) err = %q, want a 'blocked address' refusal", addr, err)
		}
	}
}
