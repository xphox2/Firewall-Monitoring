package httputil

import (
	"context"
	"fmt"
	"net"
	"time"
)

// AUDIT-020: address ranges that net.IP's built-in predicates
// (IsLoopback/IsUnspecified/IsLinkLocal*/IsPrivate) do NOT cover but that must
// still be blocked for SSRF protection:
//   - 100.64.0.0/10  carrier-grade NAT (RFC 6598)
//   - 0.0.0.0/8      "this host on this network" (RFC 1122) — 0.x.x.x routes to localhost on many stacks
var (
	cgnatNet = mustCIDR("100.64.0.0/10")
	zeroNet  = mustCIDR("0.0.0.0/8")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("httputil: bad CIDR " + s + ": " + err.Error())
	}
	return n
}

// IsBlockedIP reports whether ip must not be the target of a server-initiated
// outbound connection (SSRF guard): loopback, unspecified, link-local,
// multicast, private (RFC1918 / ULA), CGNAT (100.64.0.0/10), or 0.0.0.0/8.
// A nil IP is treated as blocked (fail closed).
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() {
		return true
	}
	return cgnatNet.Contains(ip) || zeroNet.Contains(ip)
}

// SafeDialContext returns a net/http DialContext that closes the SSRF
// DNS-rebinding TOCTOU window. A pre-flight "resolve the hostname and check the
// IPs" gate (isValidExternalIP) can be defeated when the real dial re-resolves
// and the attacker's DNS returns a private/loopback IP the second time. This
// dialer instead resolves the host, validates EVERY candidate IP with
// IsBlockedIP, and dials the validated IP directly — so the address that was
// checked is exactly the address connected to. Wire it into the Transport of
// any http.Client that fetches an operator-supplied URL (e.g. webhooks).
func SafeDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		lastErr := fmt.Errorf("no resolvable address for %q", host)
		for _, ipa := range ips {
			if IsBlockedIP(ipa.IP) {
				lastErr = fmt.Errorf("refusing to dial blocked address %s (host %q)", ipa.IP, host)
				continue
			}
			conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
			if derr != nil {
				lastErr = derr
				continue
			}
			return conn, nil
		}
		return nil, lastErr
	}
}
