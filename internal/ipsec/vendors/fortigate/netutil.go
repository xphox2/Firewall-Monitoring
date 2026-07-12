package fortigate

import "net"

// splitCIDR converts "10.0.0.0/24" into its network IP and dotted-decimal mask
// ("10.0.0.0", "255.255.255.0"). ok is false for a malformed CIDR.
func splitCIDR(cidr string) (ip, mask string, ok bool) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil || len(n.Mask) != 4 {
		return "", "", false
	}
	return n.IP.String(), net.IP(n.Mask).String(), true
}
