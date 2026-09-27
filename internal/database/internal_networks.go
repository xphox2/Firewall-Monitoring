package database

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
	"firewall-mon/internal/netclass"
)

// Settings behind the operator's internal networks (see classify.InternalSet).
const (
	// FlowInternalAutoKey: derive internal networks from the monitored
	// devices' own addresses (default on).
	FlowInternalAutoKey = "flow_internal_auto"
	// FlowInternalNetworksKey: the operator's own list, one CIDR or address
	// per line, canonical form.
	FlowInternalNetworksKey = "flow_internal_networks"
	// FlowReclassTargetRevKey: the classification revision new rows are
	// stamped with (flow class_rev). Internal state, never user-editable; the
	// history reclassification advances it.
	FlowReclassTargetRevKey = "flow_reclass_target_rev"
)

// Limits on the operator's list.
const (
	maxInternalNetworks     = 1000
	maxInternalNetworksText = 32 * 1024
)

// skippedMgmtAddrs remembers the last count of unparseable management
// addresses, so the log line fires on change only.
var skippedMgmtAddrs atomic.Int64

// InternalNetwork is one entry of the effective internal-network list, with
// where it came from so the operator can see why an address counts as theirs.
type InternalNetwork struct {
	Prefix netip.Prefix `json:"-"`
	CIDR   string       `json:"cidr"`
	// Source is "manual", "interface", "subnet" or "management".
	Source string `json:"source"`
	// Device names the device an auto-derived entry came from.
	Device string `json:"device,omitempty"`
}

// ParseInternalNetworks parses the operator's list: CIDRs or bare addresses
// (a host prefix), separated by newlines, commas or spaces. It returns the
// canonical, de-duplicated prefixes and every entry it rejected, with why.
// A catch-all (0.0.0.0/0, ::/0) is rejected: it would make every flow internal
// and silence the outbound detectors.
func ParseInternalNetworks(text string) ([]netip.Prefix, []string) {
	var out []netip.Prefix
	var bad []string
	seen := map[netip.Prefix]bool{}
	if len(text) > maxInternalNetworksText {
		return nil, []string{fmt.Sprintf("the list is longer than %d KB", maxInternalNetworksText/1024)}
	}
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' })
	for _, f := range fields {
		var p netip.Prefix
		if strings.Contains(f, "/") {
			var err error
			if p, err = netip.ParsePrefix(f); err != nil {
				bad = append(bad, f+" (not a network)")
				continue
			}
		} else {
			a, err := netip.ParseAddr(f)
			if err != nil || a.Zone() != "" {
				bad = append(bad, f+" (not an address)")
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		if p.Bits() == 0 {
			bad = append(bad, f+" (covers every address)")
			continue
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) > maxInternalNetworks {
		bad = append(bad, fmt.Sprintf("more than %d networks", maxInternalNetworks))
	}
	return out, bad
}

// CanonicalInternalNetworks is the stored form: one prefix per line.
func CanonicalInternalNetworks(ps []netip.Prefix) string {
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return strings.Join(lines, "\n")
}

// FlowReclassTargetRev is the classification revision new flow rows carry.
func (d *Database) FlowReclassTargetRev() uint16 {
	raw, _ := d.GetSettingValue(FlowReclassTargetRevKey)
	return parseTargetRev(raw)
}

// parseTargetRev is the one rule for reading the target revision: absent,
// unparseable or out of range means 1.
func parseTargetRev(raw string) uint16 {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < 1 || v > 65535 {
		return 1
	}
	return uint16(v)
}

// LoadInternalNetworks returns the effective list of the operator's own
// networks: the manual list, plus — unless FlowInternalAutoKey is off — every
// address of every active device from its latest interface snapshot (as a host
// prefix), that address's connected subnet when netclass.SubnetCIDR accepts it
// (it rejects /30–/32, which are provider links), and each device's management
// address. Private ranges are always internal and are not listed.
//
// interface_addresses comes from SNMP ipAddrTable, which is IPv4 only, so IPv6
// networks must be listed by hand.
func (d *Database) LoadInternalNetworks() ([]InternalNetwork, error) {
	var out []InternalNetwork
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix, source, device string) {
		p = p.Masked()
		if seen[p] || classify.DefaultCovers(p) {
			return
		}
		seen[p] = true
		out = append(out, InternalNetwork{Prefix: p, CIDR: p.String(), Source: source, Device: device})
	}

	if text, ok := d.GetSettingValue(FlowInternalNetworksKey); ok {
		manual, bad := ParseInternalNetworks(text)
		if len(bad) > 0 {
			log.Printf("internal networks: ignoring invalid saved entries: %s", strings.Join(bad, "; "))
		}
		for _, p := range manual {
			add(p, "manual", "")
		}
	}

	if d.GetBoolSetting(FlowInternalAutoKey, true) {
		var devices []models.Device
		if err := d.db.Scopes(ActiveDevices).Select("id, name, ip_address").Find(&devices).Error; err != nil {
			return nil, fmt.Errorf("internal networks: devices: %w", err)
		}
		names := make(map[uint]string, len(devices))
		for _, dev := range devices {
			names[dev.ID] = dev.Name
		}
		addrs, err := d.GetLatestInterfaceAddresses()
		if err != nil {
			return nil, fmt.Errorf("internal networks: interface addresses: %w", err)
		}
		sort.Slice(addrs, func(i, j int) bool {
			if addrs[i].DeviceID != addrs[j].DeviceID {
				return addrs[i].DeviceID < addrs[j].DeviceID
			}
			return addrs[i].IPAddress < addrs[j].IPAddress
		})
		for _, a := range addrs {
			name, active := names[a.DeviceID]
			if !active {
				continue
			}
			ip, err := netip.ParseAddr(a.IPAddress)
			if err != nil {
				continue
			}
			ip = ip.Unmap()
			add(netip.PrefixFrom(ip, ip.BitLen()), "interface", name)
			if cidr, ok := netclass.SubnetCIDR(a.IPAddress, a.NetMask); ok {
				// A 0.0.0.0 or non-canonical netmask comes back as a /0; a
				// device must never make the whole internet "internal".
				if p, err := netip.ParsePrefix(cidr); err == nil && p.Bits() > 0 {
					add(p, "subnet", name)
				}
			}
		}
		skipped := 0
		for _, dev := range devices {
			ip, err := netip.ParseAddr(dev.IPAddress)
			if err != nil {
				skipped++ // a hostname, or empty
				continue
			}
			ip = ip.Unmap()
			add(netip.PrefixFrom(ip, ip.BitLen()), "management", dev.Name)
		}
		// Logged when the count changes, not on every 15-minute refresh.
		if prev := skippedMgmtAddrs.Swap(int64(skipped)); skipped > 0 && int64(skipped) != prev {
			log.Printf("internal networks: %d device management address(es) are not IP addresses and were skipped", skipped)
		}
	}
	return out, nil
}

// InternalSetFrom builds the classifier set from an effective list.
func InternalSetFrom(nets []InternalNetwork, rev uint16) *classify.InternalSet {
	ps := make([]netip.Prefix, len(nets))
	for i, n := range nets {
		ps[i] = n.Prefix
	}
	return classify.NewInternalSet(ps, rev)
}
