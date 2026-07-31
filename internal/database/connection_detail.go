package database

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/l2infer"
	"firewall-mon/internal/models"
	"firewall-mon/internal/netclass"
	"firewall-mon/internal/snmp"

	"gorm.io/gorm"
)

// selectorMirrors reports whether two selector strings — one from each end of a
// tunnel — describe the same side of the same path.
//
// Exact equality is tried FIRST, and is not merely an optimisation: FortiGate's
// SNMP walk serialises selectors as RANGES ("192.168.5.0 - 192.168.5.255", see
// snmp.vendor_fortigate), and net.ParseCIDR — which is what SelectorCovered
// requires of its CONFIGURED argument — cannot read one. Containment therefore
// only resolves for a range when the other side is a parseable CIDR, so two
// mirrored ranges would silently stop matching. Equality is what carries them.
//
// allowNarrowing widens the test to one-way containment in either direction,
// because IKEv2 narrowing legitimately reports a configured /24 as the /32
// actually in use. The caller must only set it for two rows already known to
// belong to the same logical tunnel: containment is asymmetric in its blast
// radius, and a row reporting 0.0.0.0/0 contains EVERY other selector, so an
// unbounded relaxation would pair rows from unrelated tunnels.
// Both sides are NORMALIZED before the equality test, because the two vendors
// serialise the same network differently: a FortiGate reports a host pair as the
// bare address "192.168.13.7" (its selector builder returns the address as-is
// when the MIB exposes no mask, and when end == begin) while OPNsense
// reports "192.168.13.7/32", and those never compare equal as text. Normalizing
// only ever ADDS matches — NormalizeSelector returns anything it cannot convert
// unchanged, so two mirrored ranges still match each other exactly as before.
func selectorMirrors(a, b string, allowNarrowing bool) bool {
	na, nb := netclass.NormalizeSelector(a), netclass.NormalizeSelector(b)
	if na == nb {
		return true
	}
	if !allowNarrowing {
		return false
	}
	return netclass.SelectorCovered([]string{na}, nb) ||
		netclass.SelectorCovered([]string{nb}, na)
}

// Phase2Match is a path BOTH ends independently reported: one row from each
// device, describing the same selector pair from its own side.
//
// It is the sole input to the UI's peer-agreement marker, so it deliberately
// excludes pairs where either row's selectors were cross-filled from the peer —
// see the guards at the build site. A match here means two devices each made a
// claim, not that one device's claim was copied onto the other.
type Phase2Match struct {
	SourceTunnel string `json:"source_tunnel"`
	DestTunnel   string `json:"dest_tunnel"`
	SourcePhase1 string `json:"source_phase1"`
	DestPhase1   string `json:"dest_phase1"`
	LocalSubnet  string `json:"local_subnet"`
	RemoteSubnet string `json:"remote_subnet"`
	SourceStatus string `json:"source_status"`
	DestStatus   string `json:"dest_status"`
	SrcBytesIn   uint64 `json:"src_bytes_in"`
	SrcBytesOut  uint64 `json:"src_bytes_out"`
	DstBytesIn   uint64 `json:"dst_bytes_in"`
	DstBytesOut  uint64 `json:"dst_bytes_out"`
	SrcUptime    uint64 `json:"src_uptime"`
	DstUptime    uint64 `json:"dst_uptime"`
}

// ConnInterfaceRef describes one physical/virtual interface that carries a
// direct (ethernet/lag/l2vlan/bridge/wan) connection. Direct links have no
// vpn_status rows — their telemetry lives in interface_stats — so the detail
// view graphs and lists these instead of tunnels. Resolved from the latest
// interface_stats snapshot for each interface name in the connection's
// TunnelNames (which, for direct links, holds interface names — see
// cmd/poller physical detector).
type ConnInterfaceRef struct {
	DeviceID   uint   `json:"device_id"`
	DeviceName string `json:"device_name"`
	IfName     string `json:"if_name"`
	IfIndex    int    `json:"if_index"`
	IPAddress  string `json:"ip_address"` // interface's IP on the shared LAN segment
	Subnet     string `json:"subnet"`     // network CIDR (e.g. 10.0.5.0/24) — the network that pairs the two ends
	Kind       string `json:"kind"`       // ifType name: l2vlan | bridge | lag | ethernet | …
	VlanID     int    `json:"vlan_id"`    // VLAN id (SNMP dot1qPvid, else config) — groups same-VLAN ifaces
	Parent     string `json:"parent"`     // parent interface this rides on (config: set interface) — groups sub-iface with its bridge
	Speed      uint64 `json:"speed"`
	Status     string `json:"status"`
	InBytes    uint64 `json:"in_bytes"`
	OutBytes   uint64 `json:"out_bytes"`
	InErrors   uint64 `json:"in_errors"`
	OutErrors  uint64 `json:"out_errors"`
}

// computeNetworkCIDR reduces an interface IP + dotted-decimal mask to its
// network address in CIDR form (the same key the physical detector groups on).
// Returns "" for non-IPv4 or unparseable input.
func computeNetworkCIDR(ipStr, maskStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	mask := net.ParseIP(strings.TrimSpace(maskStr))
	if ip == nil || mask == nil {
		return ""
	}
	ip4, mask4 := ip.To4(), mask.To4()
	if ip4 == nil || mask4 == nil {
		return ""
	}
	ones, _ := net.IPMask(mask4).Size()
	return fmt.Sprintf("%s/%d", ip4.Mask(net.IPMask(mask4)).String(), ones)
}

// OverlayInfo describes one overlay interface (VXLAN / L3VLAN) endpoint, built
// from the device's SSH-captured config (VNI, carrier interface, UDP dstport,
// VTEP peers) plus its SNMP interface_stats counters. Lets the detail view
// explain an overlay beyond the carrier tunnel it rides on.
type OverlayInfo struct {
	DeviceID     uint     `json:"device_id"`
	DeviceName   string   `json:"device_name"`
	Type         string   `json:"type"` // vxlan | l3ipvlan
	Name         string   `json:"name"` // overlay interface name
	VNI          int      `json:"vni,omitempty"`
	CarrierIface string   `json:"carrier_iface,omitempty"` // underlying interface the overlay is bound to
	DestPort     int      `json:"dest_port,omitempty"`
	RemoteVTEPs  []string `json:"remote_vteps,omitempty"`
	IfIndex      int      `json:"if_index,omitempty"` // interface_stats index — lets the UI graph the overlay iface itself
	InBytes      uint64   `json:"in_bytes"`
	OutBytes     uint64   `json:"out_bytes"`
	Status       string   `json:"status"`
}

// ConnectionDetailResult holds full detail for a connection including matching tunnels.
type ConnectionDetailResult struct {
	Connection      models.DeviceConnection `json:"connection"`
	Family          string                  `json:"family"` // tunnel | overlay | direct | offnet — drives which detail view the UI renders
	SourceTunnels   []models.VPNStatus      `json:"source_tunnels"`
	DestTunnels     []models.VPNStatus      `json:"dest_tunnels"`
	Interfaces      []ConnInterfaceRef      `json:"interfaces,omitempty"` // populated for the "direct" family only
	Overlays        []OverlayInfo           `json:"overlays,omitempty"`   // populated for the "overlay" family only
	TotalBytesIn    uint64                  `json:"total_bytes_in"`
	TotalBytesOut   uint64                  `json:"total_bytes_out"`
	TotalPacketsIn  uint64                  `json:"total_packets_in"`
	TotalPacketsOut uint64                  `json:"total_packets_out"`
	ThroughputIn    float64                 `json:"throughput_in"`
	ThroughputOut   float64                 `json:"throughput_out"`
	HasFlowData     bool                    `json:"has_flow_data"`
	Phase2Matches   []Phase2Match           `json:"phase2_matches"`
	// Windowed traffic. TotalBytes* above are each side's LATEST CUMULATIVE
	// counters summed, which is not a quantity the two ends can be compared on:
	// they reset at different moments (an OPNsense child SA rekeys independently,
	// a FortiGate per-peer session counter does not), so the sum visibly goes
	// backwards while traffic is still flowing. These are reset-safe deltas over
	// WindowHours instead, and they mean the same thing on both ends.
	WindowHours      int                       `json:"window_hours,omitempty"`
	SourceWindow     VPNWindowTotal            `json:"source_window"`
	DestWindow       VPNWindowTotal            `json:"dest_window"`
	SourcePathTotals map[string]VPNWindowTotal `json:"source_path_totals,omitempty"`
	DestPathTotals   map[string]VPNWindowTotal `json:"dest_path_totals,omitempty"`
	// Whether each end's per-path numbers can be attributed to a path at all —
	// a FortiGate replicates one counter series across every phase2 name, so
	// showing it per path would multiply the tunnel's traffic by its selector
	// count. See GetVPNCounterProvenance.
	SourceProvenance VPNCounterProvenance `json:"source_provenance"`
	DestProvenance   VPNCounterProvenance `json:"dest_provenance"`
	// Evidence explains WHY an L2-inferred direct link is drawn (which
	// LLDP/FDB/ARP rows produced it). Populated for the direct family when
	// the connection's match method is one of the L2 tiers; empty means the
	// evidence has aged out (the UI states that explicitly).
	Evidence []L2EvidenceOut `json:"evidence,omitempty"`
}

// L2EvidenceOut is one evidence row on the connection-detail API. The
// embedded EvidenceRef fields (tier, reporting device, local port, observed
// MAC/IP/remote-port/sysname, VLAN, timestamp, note) are NEIGHBOR- and
// NETWORK-CONTROLLED strings — the UI must escape them.
type L2EvidenceOut struct {
	l2infer.EvidenceRef
	DeviceName string `json:"device_name"`
	Fresh      bool   `json:"fresh"`
}

// connectionFamily maps a connection_type to one of four telemetry families
// that determine which data source and detail view a connection uses:
//
//	tunnel  — ipsec/ssl/gre/tunnel: counters in vpn_status, keyed per tunnel_name
//	          (= Phase 2 selector), aggregated per Phase 1 in the UI.
//	overlay — vxlan/l3ipvlan: no counter of their own; they ride inside a
//	          carrier tunnel, so they graph the carrier's vpn_status (resolved
//	          by the existing peer-remote-IP tunnel matching).
//	direct  — ethernet/lag/l2vlan/bridge/wan: counters in interface_stats,
//	          keyed per (device_id, ifIndex). No tunnels/phase2.
//	offnet  — aggregate of unmatched remote peers.
//
// Unknown/empty types fall back to "tunnel" (the historical default).
func connectionFamily(connType string) string {
	switch strings.ToLower(strings.TrimSpace(connType)) {
	case "vxlan", "l3ipvlan":
		return "overlay"
	case "ethernet", "lag", "l2vlan", "bridge", "wan":
		return "direct"
	case "offnet":
		return "offnet"
	default: // ipsec, ssl, gre, tunnel, and any unknown value
		return "tunnel"
	}
}

// normalizeIfName strips formatting differences so the same logical interface
// matches across devices and across the name stored in a connection vs the name
// in interface_stats (vlan500, "vlan 500", vlan.500, vlan-500, VLAN500 all match
// as "vlan500"). Mirrors the poller's overlay-detector normalization so the
// detail view resolves the same pairs the detector did.
func normalizeIfName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.NewReplacer(" ", "", ".", "", "-", "", "_", "").Replace(n)
}

// resolveConnectionInterfaces resolves a direct connection's interface names
// (stored comma-separated in conn.TunnelNames by the physical/overlay detectors)
// to the latest interface_stats snapshot on each endpoint device. Matching is
// normalized, so an interface named differently on each device (vlan100 vs
// VLAN-100) still resolves on BOTH ends. Deduplicated by (device_id, ifIndex).
func (d *Database) resolveConnectionInterfaces(conn *models.DeviceConnection) []ConnInterfaceRef {
	if conn.TunnelNames == "" {
		return nil
	}
	targets := make(map[string]bool)
	for _, n := range strings.Split(conn.TunnelNames, ",") {
		if n = strings.TrimSpace(n); n != "" {
			targets[normalizeIfName(n)] = true
		}
	}
	if len(targets) == 0 {
		return nil
	}

	type dev struct {
		id   uint
		name string
	}
	devs := []dev{{conn.SourceDeviceID, ""}, {conn.DestDeviceID, ""}}
	if conn.SourceDevice != nil {
		devs[0].name = conn.SourceDevice.Name
	}
	if conn.DestDevice != nil {
		devs[1].name = conn.DestDevice.Name
	}

	seen := make(map[string]bool)
	var refs []ConnInterfaceRef
	for _, dv := range devs {
		// Config-derived parent/vlan map (normalized name → interface config).
		// Lets us recognize that a VLAN sub-interface and its parent bridge are
		// the same logical segment. Absent/masked config simply leaves them empty.
		ifCfg := make(map[string]snmp.FortiGateInterface)
		if rev, err := d.GetLatestConfigRevision(dv.id); err == nil && rev != nil && rev.ConfigText != "" {
			for _, ic := range snmp.ParseFortiGateInterfaceConfig(rev.ConfigText) {
				ifCfg[normalizeIfName(ic.Name)] = ic
			}
		}
		// Match against the device's CURRENT interface set (latest snapshot), so
		// any interface whose normalized name is in the connection's name list is
		// resolved regardless of literal spelling differences between devices.
		for _, st := range d.latestInterfacesForDevice(dv.id) {
			nn := normalizeIfName(st.Name)
			if !targets[nn] {
				continue
			}
			key := fmt.Sprintf("%d:%d", dv.id, st.Index)
			if seen[key] {
				continue
			}
			seen[key] = true
			// Resolve the interface's IP + network so the UI can pair the two
			// ends by the LAN segment that joins them (the detector's grouping
			// key). Gated to the device's current poll — never a stale row.
			addr := d.latestAddressForDeviceIf(dv.id, st.Index)

			vlanID := st.VLANID
			parent := ""
			if ic, ok := ifCfg[nn]; ok {
				parent = ic.Parent
				if vlanID == 0 {
					vlanID = ic.VLANID
				}
			}
			refs = append(refs, ConnInterfaceRef{
				DeviceID:   dv.id,
				DeviceName: dv.name,
				IfName:     st.Name,
				IfIndex:    st.Index,
				IPAddress:  addr.IPAddress,
				Subnet:     computeNetworkCIDR(addr.IPAddress, addr.NetMask),
				Kind:       st.TypeName,
				VlanID:     vlanID,
				Parent:     parent,
				Speed:      st.Speed,
				Status:     st.Status,
				InBytes:    st.InBytes,
				OutBytes:   st.OutBytes,
				InErrors:   st.InErrors,
				OutErrors:  st.OutErrors,
			})
		}
	}
	return refs
}

// latestInterfacesForDevice returns the device's interface_stats rows from its
// most recent poll timestamp (the current interface set).
func (d *Database) latestInterfacesForDevice(deviceID uint) []models.InterfaceStats {
	var latest models.InterfaceStats
	if err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").Limit(1).First(&latest).Error; err != nil {
		return nil
	}
	var rows []models.InterfaceStats
	d.db.Where("device_id = ? AND timestamp = ?", deviceID, latest.Timestamp).Find(&rows)
	return rows
}

// latestAddressForDeviceIf returns the interface's IP from the device's most
// recent ADDRESS poll only — never a historical row. Without this gate the
// interface tab showed stale addresses (e.g. a FortiGate DMZ jack that used
// to carry 10.10.10.x now has no IP, but an 18-day-old interface_addresses
// row kept surfacing under a live link). Returns a zero-value address (empty
// IP) when the interface has no address in the current poll — which is the
// truthful state for an IP-less bridged/switch port.
func (d *Database) latestAddressForDeviceIf(deviceID uint, ifIndex int) models.InterfaceAddress {
	// Anchor on the device's latest INTERFACE poll, not its latest address
	// poll: an interface that used to carry an IP and no longer does leaves
	// its old interface_addresses row as the newest one (the table has no
	// tombstone), so anchoring on the address table would keep returning it.
	// The interface_stats poll is the authority on "seen now"; an address
	// older than that poll (beyond intra-poll batch skew) is stale.
	var latestIface models.InterfaceStats
	if err := d.db.Where("device_id = ?", deviceID).Order("timestamp DESC").Limit(1).First(&latestIface).Error; err != nil {
		return models.InterfaceAddress{}
	}
	cutoff := latestIface.Timestamp.Add(-15 * time.Minute)
	var addr models.InterfaceAddress
	d.db.Where("device_id = ? AND if_index = ? AND timestamp >= ?", deviceID, ifIndex, cutoff).
		Order("timestamp DESC").Limit(1).First(&addr)
	return addr
}

// buildOverlayInfo enriches an overlay (vxlan/l3ipvlan) connection with per-end
// detail drawn from two sources: the device's SSH-captured FortiGate config
// (VNI, carrier interface, UDP dstport, VTEP peer IPs) and its SNMP
// interface_stats (the overlay interface's own index/counters/status). The
// overlay interface names come from the connection's TunnelNames (set by the
// overlay detector), matched normalized so spelling differences don't matter.
func (d *Database) buildOverlayInfo(conn *models.DeviceConnection) []OverlayInfo {
	if conn.TunnelNames == "" {
		return nil
	}
	targets := make(map[string]bool)
	for _, n := range strings.Split(conn.TunnelNames, ",") {
		if n = strings.TrimSpace(n); n != "" {
			targets[normalizeIfName(n)] = true
		}
	}
	if len(targets) == 0 {
		return nil
	}

	type dev struct {
		id   uint
		name string
	}
	devs := []dev{{conn.SourceDeviceID, ""}, {conn.DestDeviceID, ""}}
	if conn.SourceDevice != nil {
		devs[0].name = conn.SourceDevice.Name
	}
	if conn.DestDevice != nil {
		devs[1].name = conn.DestDevice.Name
	}

	var out []OverlayInfo
	for _, dv := range devs {
		// Config-derived VXLAN map for this device, keyed by normalized name.
		vxByName := make(map[string]snmp.FortiGateVxlan)
		if rev, err := d.GetLatestConfigRevision(dv.id); err == nil && rev != nil && rev.ConfigText != "" {
			for _, v := range snmp.ParseFortiGateVxlanConfig(rev.ConfigText) {
				vxByName[normalizeIfName(v.Name)] = v
			}
		}
		for _, st := range d.latestInterfacesForDevice(dv.id) {
			nn := normalizeIfName(st.Name)
			if !targets[nn] {
				continue
			}
			info := OverlayInfo{
				DeviceID:   dv.id,
				DeviceName: dv.name,
				Type:       conn.ConnectionType,
				Name:       st.Name,
				IfIndex:    st.Index,
				InBytes:    st.InBytes,
				OutBytes:   st.OutBytes,
				Status:     st.Status,
			}
			if cfg, ok := vxByName[nn]; ok {
				info.VNI = cfg.VXLANID
				info.CarrierIface = cfg.Interface
				info.DestPort = cfg.DestinationPort
				info.RemoteVTEPs = cfg.RemoteIPs
			}
			out = append(out, info)
		}
	}
	return out
}

// interfacesForDevice returns the subset of refs on a single device. Used to
// build a directionally-coherent aggregate: summing both endpoints of a direct
// link would mix in/out (A's out ≈ B's in), so the Overview graph and KPIs use
// one device's interfaces while the Interfaces tab still lists both ends.
func interfacesForDevice(refs []ConnInterfaceRef, deviceID uint) []ConnInterfaceRef {
	var out []ConnInterfaceRef
	for _, r := range refs {
		if r.DeviceID == deviceID {
			out = append(out, r)
		}
	}
	return out
}

// dropOverlappingParents removes refs that are the parent of another ref on the
// SAME device, so a bridge/parent and its VLAN child aren't both summed (their
// SNMP octet counters overlap — the parent aggregates the child). Refs with no
// parent/child relationship to any sibling are all kept (a real LAG bond). Scoped
// per-device (key deviceID:normalizedName) so identically-named interfaces on the
// two endpoints never cross-cancel. Where the parent name is unknown (masked
// config), the ref is kept — we can't prove overlap, so we don't drop.
func dropOverlappingParents(refs []ConnInterfaceRef) []ConnInterfaceRef {
	if len(refs) <= 1 {
		return refs
	}
	key := func(devID uint, name string) string {
		return fmt.Sprintf("%d:%s", devID, normalizeIfName(name))
	}
	parents := make(map[string]bool)
	for _, r := range refs {
		if r.Parent != "" {
			parents[key(r.DeviceID, r.Parent)] = true
		}
	}
	if len(parents) == 0 {
		return refs
	}
	out := refs[:0:0]
	for _, r := range refs {
		if parents[key(r.DeviceID, r.IfName)] {
			continue // this ref is a parent of another resolved ref → skip to avoid overlap
		}
		out = append(out, r)
	}
	// Never let de-overlap zero out a connection: if every ref normalized to a
	// parent (a pathological name collision where parent and child share a
	// normalized token), fall back to the original set rather than dropping all.
	if len(out) == 0 {
		return refs
	}
	return out
}

// collectDeviceIPs returns all known IPs for a device (management + interface addresses).
func (d *Database) collectDeviceIPs(deviceID uint, device *models.Device) map[string]bool {
	ips := make(map[string]bool)
	if device != nil && device.IPAddress != "" {
		ips[device.IPAddress] = true
	}
	var distinctIPs []string
	d.db.Model(&models.InterfaceAddress{}).
		Where("device_id = ?", deviceID).
		Distinct("ip_address").
		Pluck("ip_address", &distinctIPs)
	for _, ip := range distinctIPs {
		ips[ip] = true
	}
	return ips
}

// GetConnectionDetail returns full detail for a connection with matching tunnels from both sides.
func (d *Database) GetConnectionDetail(connID uint) (*ConnectionDetailResult, error) {
	var conn models.DeviceConnection
	if err := d.db.Preload("SourceDevice").Preload("DestDevice").First(&conn, connID).Error; err != nil {
		return nil, err
	}

	result := &ConnectionDetailResult{Connection: conn, Family: connectionFamily(conn.ConnectionType)}

	// Overlay links (vxlan/l3ipvlan) ride a carrier tunnel (still matched below)
	// but also have their own identity — enrich from config + SNMP.
	if result.Family == "overlay" {
		result.Overlays = d.buildOverlayInfo(&conn)
	}

	// Direct links (ethernet/lag/l2vlan/bridge/wan) carry no VPN tunnels — their
	// telemetry lives in interface_stats. Resolve the member interfaces, derive
	// the byte KPIs from one endpoint (avoids in/out double-count), and skip the
	// tunnel-matching path entirely.
	if result.Family == "direct" {
		// Port-level links (L2-inferred) resolve each SIDE precisely —
		// source port on the source device, dest port on the dest device.
		// The legacy name-list resolution matches TunnelNames on EITHER
		// device, and FortiGates share hardware port names (internal1, dmz):
		// a FW↔FW link would pair unrelated same-named interfaces from both
		// boxes into one segment card with mismatched IPs/subnets.
		result.Interfaces = d.resolveL2EndpointInterfaces(&conn)
		if len(result.Interfaces) == 0 {
			result.Interfaces = d.resolveConnectionInterfaces(&conn)
		}
		primary := interfacesForDevice(result.Interfaces, conn.SourceDeviceID)
		if len(primary) == 0 {
			primary = interfacesForDevice(result.Interfaces, conn.DestDeviceID)
		}
		for _, r := range primary {
			result.TotalBytesIn += r.InBytes
			result.TotalBytesOut += r.OutBytes
		}
		var flowCount int64
		d.db.Model(&models.FlowSample{}).Where("device_id IN ?", []uint{conn.SourceDeviceID, conn.DestDeviceID}).Limit(1).Count(&flowCount)
		result.HasFlowData = flowCount > 0
		result.Evidence = d.buildConnectionEvidence(&conn)
		return result, nil
	}

	// Get latest VPN statuses for both devices
	srcTunnels, _ := d.GetLatestVPNStatuses(conn.SourceDeviceID)
	dstTunnels, _ := d.GetLatestVPNStatuses(conn.DestDeviceID)

	// Collect IPs for the dest device (management + interface addresses)
	destIPs := d.collectDeviceIPs(conn.DestDeviceID, conn.DestDevice)

	// Collect IPs for the source device
	srcIPs := d.collectDeviceIPs(conn.SourceDeviceID, conn.SourceDevice)

	// Build a set of known tunnel names from the connection record (auto-discovery)
	knownTunnels := make(map[string]bool)
	if conn.TunnelNames != "" {
		for _, name := range strings.Split(conn.TunnelNames, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				knownTunnels[name] = true
			}
		}
	}

	// Filter source tunnels: remote IP matches dest device OR tunnel name in known list
	for _, t := range srcTunnels {
		if destIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			// Avoid duplicates
			alreadyAdded := false
			for _, existing := range result.SourceTunnels {
				if existing.TunnelName == t.TunnelName && existing.DeviceID == t.DeviceID {
					alreadyAdded = true
					break
				}
			}
			if alreadyAdded {
				continue
			}
			result.SourceTunnels = append(result.SourceTunnels, t)
			result.TotalBytesIn += t.BytesIn
			result.TotalBytesOut += t.BytesOut
			result.TotalPacketsIn += t.PacketsIn
			result.TotalPacketsOut += t.PacketsOut
		}
	}

	// For indirectly matched connections (NAT'd hub-spoke), dest tunnels' remote IPs
	// are likely source's WAN IPs. Add them to srcIPs so dest tunnels can match.
	// This is safe because the VPN detector already confirmed the connection.
	if conn.MatchMethod == "tunnel_indirect" || conn.MatchMethod == "wan_inferred" {
		for _, t := range dstTunnels {
			if t.RemoteIP != "" {
				srcIPs[t.RemoteIP] = true
			}
		}
	}

	// Filter dest tunnels: remote IP matches source device (including inferred WAN IPs),
	// or tunnel name is in the known list from auto-detection
	for _, t := range dstTunnels {
		if srcIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			// Avoid duplicates
			alreadyAdded := false
			for _, existing := range result.DestTunnels {
				if existing.TunnelName == t.TunnelName && existing.DeviceID == t.DeviceID {
					alreadyAdded = true
					break
				}
			}
			if alreadyAdded {
				continue
			}
			result.DestTunnels = append(result.DestTunnels, t)
		}
	}

	// Cross-fill: if one side has empty subnets, infer from the other side (swapped).
	// Hub-side ADVPN tunnels often have empty Phase 2 selectors in SNMP.
	log.Printf("GetConnectionDetail %d: source_tunnels=%d dest_tunnels=%d", connID, len(result.SourceTunnels), len(result.DestTunnels))
	for i, t := range result.SourceTunnels {
		log.Printf("GetConnectionDetail %d: source_tunnel[%d] name=%s local=%s remote=%s", connID, i, t.TunnelName, t.LocalSubnet, t.RemoteSubnet)
	}
	for i, t := range result.DestTunnels {
		log.Printf("GetConnectionDetail %d: dest_tunnel[%d] name=%s local=%s remote=%s", connID, i, t.TunnelName, t.LocalSubnet, t.RemoteSubnet)
	}
	if len(result.SourceTunnels) > 0 && len(result.DestTunnels) > 0 {
		for i := range result.SourceTunnels {
			if result.SourceTunnels[i].LocalSubnet == "" || result.SourceTunnels[i].RemoteSubnet == "" {
				for _, dst := range result.DestTunnels {
					if dst.LocalSubnet != "" && dst.RemoteSubnet != "" {
						if result.SourceTunnels[i].LocalSubnet == "" {
							result.SourceTunnels[i].LocalSubnet = dst.RemoteSubnet
							result.SourceTunnels[i].SubnetsInferred = true
						}
						if result.SourceTunnels[i].RemoteSubnet == "" {
							result.SourceTunnels[i].RemoteSubnet = dst.LocalSubnet
							result.SourceTunnels[i].SubnetsInferred = true
						}
						break
					}
				}
			}
		}
		for i := range result.DestTunnels {
			if result.DestTunnels[i].LocalSubnet == "" || result.DestTunnels[i].RemoteSubnet == "" {
				for _, src := range result.SourceTunnels {
					if src.LocalSubnet != "" && src.RemoteSubnet != "" {
						if result.DestTunnels[i].LocalSubnet == "" {
							result.DestTunnels[i].LocalSubnet = src.RemoteSubnet
							result.DestTunnels[i].SubnetsInferred = true
						}
						if result.DestTunnels[i].RemoteSubnet == "" {
							result.DestTunnels[i].RemoteSubnet = src.LocalSubnet
							result.DestTunnels[i].SubnetsInferred = true
						}
						break
					}
				}
			}
		}
	}

	// There was a tunnel-uptime cross-fill here. It is gone deliberately.
	//
	// It took the FIRST peer row reporting a non-zero uptime — no selector
	// match, no name match, no identity of any kind — and stamped that number
	// onto every row of this side that reported zero. The result was not an
	// inference about the row it landed on; it was an unrelated row's number
	// wearing this device's name. On connection 23984 every FortiGate row
	// carried the OPNsense tunnel's age.
	//
	// A row that reports no uptime now keeps zero, and the frontends render
	// that as "-". Absent beats invented.

	// Phase 2 inverse matching: a pair of rows, one from each end, describing the
	// SAME path — source's local is dest's remote and vice versa.
	//
	// This is now the sole input to the UI's "both ends report this path" marker,
	// so it must mean exactly that and nothing weaker. Two guards enforce it:
	//
	//   - a row whose selectors were CROSS-FILLED from the peer is skipped. Such
	//     a row was populated from the very row it would be compared against, so
	//     it always "agrees" — with itself, one device having observed nothing.
	//   - narrowing tolerance is allowed only WITHIN one logical tunnel. IKEv2
	//     legitimately reports a configured /24 as a /32, so containment matching
	//     is needed; but containment makes a route-based 0.0.0.0/0 row cover
	//     EVERY peer row, which across tunnels would pair rows of unrelated
	//     tunnels. TunnelGroup already names the logical tunnel, so relax only
	//     when both ends agree on it and fall back to exact equality otherwise.
	for _, src := range result.SourceTunnels {
		if src.LocalSubnet == "" || src.RemoteSubnet == "" || src.SubnetsInferred {
			continue
		}
		for _, dst := range result.DestTunnels {
			if dst.LocalSubnet == "" || dst.RemoteSubnet == "" || dst.SubnetsInferred {
				continue
			}
			sameTunnel := src.TunnelGroup != "" && src.TunnelGroup == dst.TunnelGroup
			if selectorMirrors(src.LocalSubnet, dst.RemoteSubnet, sameTunnel) &&
				selectorMirrors(src.RemoteSubnet, dst.LocalSubnet, sameTunnel) {
				result.Phase2Matches = append(result.Phase2Matches, Phase2Match{
					SourceTunnel: src.TunnelName,
					DestTunnel:   dst.TunnelName,
					SourcePhase1: src.Phase1Name,
					DestPhase1:   dst.Phase1Name,
					LocalSubnet:  src.LocalSubnet,
					RemoteSubnet: src.RemoteSubnet,
					SourceStatus: src.Status,
					DestStatus:   dst.Status,
					SrcBytesIn:   src.BytesIn,
					SrcBytesOut:  src.BytesOut,
					DstBytesIn:   dst.BytesIn,
					DstBytesOut:  dst.BytesOut,
					SrcUptime:    src.TunnelUptime,
					DstUptime:    dst.TunnelUptime,
				})
			}
		}
	}

	// Reset-safe windowed traffic, per side and per path.
	//
	// This is the number the UI shows, instead of the cumulative sums above. A
	// per-child SA that rekeys resets its counter, so summing the latest values
	// across children makes the displayed total DROP while traffic is flowing —
	// observed on connection 23984 going 384,960 -> 206,940 -> 37,020 across two
	// rekeys. Deltas over a fixed window have no such discontinuity, and unlike a
	// lifetime counter they mean the same thing on both ends of the tunnel.
	const detailWindowHours = 24
	result.WindowHours = detailWindowHours
	winTo := time.Now()
	winFrom := winTo.Add(-detailWindowHours * time.Hour)
	result.SourceWindow, result.SourcePathTotals, result.SourceProvenance =
		d.windowedTraffic(conn.SourceDeviceID, result.SourceTunnels, winFrom, winTo)
	result.DestWindow, result.DestPathTotals, result.DestProvenance =
		d.windowedTraffic(conn.DestDeviceID, result.DestTunnels, winFrom, winTo)

	// Compute live throughput (bytes/sec) from the two most recent VPNStatus samples per source tunnel
	for _, t := range result.SourceTunnels {
		var samples []models.VPNStatus
		d.db.Where("device_id = ? AND tunnel_name = ?", t.DeviceID, t.TunnelName).
			Order("timestamp DESC").Limit(2).Find(&samples)
		if len(samples) == 2 {
			dt := samples[0].Timestamp.Sub(samples[1].Timestamp).Seconds()
			if dt > 0 {
				dIn := float64(samples[0].BytesIn) - float64(samples[1].BytesIn)
				dOut := float64(samples[0].BytesOut) - float64(samples[1].BytesOut)
				// Handle counter resets
				if dIn < 0 {
					dIn = float64(samples[0].BytesIn)
				}
				if dOut < 0 {
					dOut = float64(samples[0].BytesOut)
				}
				result.ThroughputIn += dIn / dt
				result.ThroughputOut += dOut / dt
			}
		}
	}

	// Check if sFlow data exists for either device
	var flowCount int64
	d.db.Model(&models.FlowSample{}).Where("device_id IN ?", []uint{conn.SourceDeviceID, conn.DestDeviceID}).Limit(1).Count(&flowCount)
	result.HasFlowData = flowCount > 0

	return result, nil
}

// getConnectionTunnelNames returns matching tunnel names for a connection's source and dest devices.
func (d *Database) getConnectionTunnelNames(connID uint) (srcDeviceID, dstDeviceID uint, srcTunnelNames, dstTunnelNames []string, err error) {
	var conn models.DeviceConnection
	if err = d.db.Preload("SourceDevice").Preload("DestDevice").First(&conn, connID).Error; err != nil {
		return
	}
	srcDeviceID = conn.SourceDeviceID
	dstDeviceID = conn.DestDeviceID

	srcTunnels, _ := d.GetLatestVPNStatuses(conn.SourceDeviceID)
	dstTunnels, _ := d.GetLatestVPNStatuses(conn.DestDeviceID)

	// Collect IPs for both devices
	destIPs := d.collectDeviceIPs(conn.DestDeviceID, conn.DestDevice)
	srcIPs := d.collectDeviceIPs(conn.SourceDeviceID, conn.SourceDevice)

	// For indirectly matched connections (NAT'd hub-spoke), relax IP matching
	// by adding the peer's tunnel remote IPs — same logic as GetConnectionDetail
	if conn.MatchMethod == "tunnel_indirect" || conn.MatchMethod == "wan_inferred" {
		for _, t := range dstTunnels {
			if t.RemoteIP != "" {
				srcIPs[t.RemoteIP] = true
			}
		}
		for _, t := range srcTunnels {
			if t.RemoteIP != "" {
				destIPs[t.RemoteIP] = true
			}
		}
	}

	// Known tunnel names from auto-discovery
	knownTunnels := make(map[string]bool)
	if conn.TunnelNames != "" {
		for _, name := range strings.Split(conn.TunnelNames, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				knownTunnels[name] = true
			}
		}
	}

	for _, t := range srcTunnels {
		if destIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			srcTunnelNames = append(srcTunnelNames, t.TunnelName)
		}
	}
	for _, t := range dstTunnels {
		if srcIPs[t.RemoteIP] || knownTunnels[t.TunnelName] {
			dstTunnelNames = append(dstTunnelNames, t.TunnelName)
		}
	}
	return
}

// trafficWindow converts a connection-traffic lookback in hours to a bounded
// duration with the chart layer's adaptive bucket unit. The maxChartWindow
// clamp mirrors GetInterfaceChartWindow so a pathological hours value can't
// bucket unbounded history.
func trafficWindow(hours float64) (time.Duration, string) {
	dur := time.Duration(hours * float64(time.Hour))
	if dur <= 0 || dur > maxChartWindow {
		dur = maxChartWindow
	}
	return dur, bucketUnitForWindow(dur)
}

// interfaceTrafficWindow aggregates per-interface chart buckets (from
// GetInterfaceChartWindow) into a single series in the same shape the VPN
// traffic chart returns, so the frontend renders direct links identically.
// Buckets align across interfaces because they share one [from,to] window and
// adaptive bucket size; rows are merged by bucket string and returned sorted.
//
// H10 of the 2026-07-01 audit: interface_stats carries RAW CUMULATIVE SNMP
// counters, but the VPNChartBucket contract this endpoint shares with the
// tunnel path is PER-BUCKET DELTAS (the tunnel path computes them with LAG();
// both frontend consumers treat in_bytes as transfer-per-bucket and divide by
// the bucket interval for Mbps). The pre-fix code summed the cumulative
// averages straight through, so a direct link with, say, 2 TB lifetime
// InBytes rendered every hour bucket as ~2 TB transferred / a multi-Gbps flat
// line that grew monotonically. Convert to deltas PER INTERFACE before
// summing across interfaces: consecutive-bucket difference, clamped at 0 for
// counter resets/wraps, dropping each interface's first bucket (no baseline)
// — the same semantics as the tunnel path's LAG() query.
func (d *Database) interfaceTrafficWindow(refs []ConnInterfaceRef, hours float64) ([]VPNChartBucket, error) {
	if len(refs) == 0 {
		return []VPNChartBucket{}, nil
	}
	// Drop parent interfaces whose child (a VLAN sub-interface / bridge member) is
	// also in the set: on FortiGate the parent bridge counter aggregates its
	// children, so summing both double-counts the same octets. Genuine LAG members
	// (distinct physical ports with no parent/child link between them) survive and
	// still sum — that IS the bond's aggregate throughput.
	refs = dropOverlappingParents(refs)
	dur, _ := trafficWindow(hours)
	to := time.Now()
	from := to.Add(-dur)

	clamp := func(v float64) float64 {
		if v < 0 {
			return 0 // counter reset/wrap between buckets
		}
		return v
	}

	agg := make(map[string]*VPNChartBucket)
	for _, r := range refs {
		buckets, err := d.GetInterfaceChartWindow(r.DeviceID, r.IfIndex, from, to)
		if err != nil {
			return nil, err
		}
		// buckets are sorted ASC by bucket; delta each against its predecessor.
		for i := 1; i < len(buckets); i++ {
			cur, prev := buckets[i], buckets[i-1]
			e := agg[cur.Bucket]
			if e == nil {
				e = &VPNChartBucket{Bucket: cur.Bucket, BucketMs: cur.BucketMs}
				agg[cur.Bucket] = e
			}
			e.InBytes += clamp(cur.InBytes - prev.InBytes)
			e.OutBytes += clamp(cur.OutBytes - prev.OutBytes)
			e.InPackets += clamp(cur.InPackets - prev.InPackets)
			e.OutPackets += clamp(cur.OutPackets - prev.OutPackets)
		}
	}

	out := make([]VPNChartBucket, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BucketMs < out[j].BucketMs })
	return out, nil
}

// GetConnectionTraffic returns aggregated chart data for a connection. Tunnel,
// overlay and off-net connections aggregate vpn_status (overlays graph their
// carrier tunnel, matched by peer remote IP); direct links aggregate
// interface_stats for their member interfaces on one endpoint.
func (d *Database) GetConnectionTraffic(connID uint, hours float64) ([]VPNChartBucket, error) {
	// Direct links graph interface_stats, not vpn_status.
	var conn models.DeviceConnection
	if err := d.db.Preload("SourceDevice").Preload("DestDevice").First(&conn, connID).Error; err != nil {
		return nil, err
	}
	if connectionFamily(conn.ConnectionType) == "direct" {
		refs := d.resolveConnectionInterfaces(&conn)
		primary := interfacesForDevice(refs, conn.SourceDeviceID)
		if len(primary) == 0 {
			primary = interfacesForDevice(refs, conn.DestDeviceID)
		}
		return d.interfaceTrafficWindow(primary, hours)
	}

	srcDeviceID, dstDeviceID, srcTunnelNames, dstTunnelNames, err := d.getConnectionTunnelNames(connID)
	if err != nil {
		return nil, err
	}

	dur, bucketUnit := trafficWindow(hours)
	bucketExpr := d.dialect.TimeBucket(bucketUnit, "timestamp")
	cutoff := time.Now().Add(-dur)

	// Aggregate ONE endpoint only. A VPN tunnel is reported at BOTH ends (each
	// device counts the same bytes on its own tunnel interface), so summing
	// src+dst doubles the throughput — the ~2x inflation the direct path already
	// guards against (see interfacesForDevice's comment). Prefer the source
	// endpoint; fall back to the destination when the source has no matching
	// tunnels.
	var allNames []string
	var deviceIDs []uint
	if len(srcTunnelNames) > 0 {
		allNames = srcTunnelNames
		deviceIDs = []uint{srcDeviceID}
	} else if len(dstTunnelNames) > 0 {
		allNames = dstTunnelNames
		deviceIDs = []uint{dstDeviceID}
	}

	if len(allNames) == 0 {
		return []VPNChartBucket{}, nil
	}

	// Build explicit placeholders for IN clauses (GORM Raw doesn't reliably expand slices)
	var args []interface{}
	devPH := make([]string, len(deviceIDs))
	for i, id := range deviceIDs {
		devPH[i] = "?"
		args = append(args, id)
	}
	namePH := make([]string, len(allNames))
	for i, n := range allNames {
		namePH[i] = "?"
		args = append(args, n)
	}
	args = append(args, cutoff)

	// Use LAG() window function to compute per-sample deltas from cumulative SNMP counters.
	// First row per partition (LAG is NULL) returns NULL and is filtered by the outer WHERE.
	//
	// Two data pathologies are neutralized before the window runs:
	//  - Rows with BOTH byte counters zero are excluded: the collector's SSH
	//    phase1/phase2 poll writes status-only rows (no counters) into the same
	//    table as the SNMP counter rows. Left in the partition, each one reads
	//    as a counter reset and the next real sample contributes the tunnel's
	//    FULL lifetime bytes as one "delta" — the chart then dwarfs real
	//    traffic and climbs forever as the counter grows. Same rationale as
	//    vpnDeltaQuery's filter (charts.go).
	//  - Byte-identical counter streams are collapsed: FortiGate can surface
	//    ONE underlying counter under several tunnel names (observed live: 4
	//    phase names to the same gateway, byte-identical every sample), and
	//    summing those partitions multiplies real throughput by the duplicate
	//    count. Rows identical in (device, timestamp, all four counters) merge
	//    to one row keeping MIN(tunnel_name) as the partition key; tunnels with
	//    genuinely distinct counters keep their own partitions and still sum.
	query := fmt.Sprintf(`
		SELECT bucket, SUM(delta_in) as in_bytes, SUM(delta_out) as out_bytes,
		       SUM(delta_pin) as in_packets, SUM(delta_pout) as out_packets
		FROM (
			SELECT %s as bucket,
				CASE WHEN LAG(bytes_in) OVER w IS NULL THEN NULL
					WHEN bytes_in >= LAG(bytes_in) OVER w THEN bytes_in - LAG(bytes_in) OVER w
					ELSE bytes_in END as delta_in,
				CASE WHEN LAG(bytes_out) OVER w IS NULL THEN NULL
					WHEN bytes_out >= LAG(bytes_out) OVER w THEN bytes_out - LAG(bytes_out) OVER w
					ELSE bytes_out END as delta_out,
				CASE WHEN LAG(packets_in) OVER w IS NULL THEN NULL
					WHEN packets_in >= LAG(packets_in) OVER w THEN packets_in - LAG(packets_in) OVER w
					ELSE packets_in END as delta_pin,
				CASE WHEN LAG(packets_out) OVER w IS NULL THEN NULL
					WHEN packets_out >= LAG(packets_out) OVER w THEN packets_out - LAG(packets_out) OVER w
					ELSE packets_out END as delta_pout
			FROM (
				SELECT device_id, timestamp, bytes_in, bytes_out, packets_in, packets_out,
					MIN(tunnel_name) AS tunnel_name
				FROM vpn_status
				WHERE device_id IN (%s) AND tunnel_name IN (%s) AND timestamp > ?
					AND NOT (bytes_in = 0 AND bytes_out = 0)
				GROUP BY device_id, timestamp, bytes_in, bytes_out, packets_in, packets_out
			) AS samples
			WINDOW w AS (PARTITION BY device_id, tunnel_name ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`,
		bucketExpr, strings.Join(devPH, ","), strings.Join(namePH, ","))

	var rows []VPNChartBucket
	err = d.db.Raw(query, args...).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	// M12 of the 2026-07-01 audit: the SELECT list has no bucket_ms column, so
	// every row scanned with BucketMs=0 — the 3-mode charts' normalizeDeltas
	// then fell back to a hardcoded 60s interval, inflating Mbps 60x on the
	// hourly-bucketed 7d/30d ranges (and 5x on a 5-min poll cadence). Backfill
	// it from the bucket string exactly like GetInterfaceChartWindow does.
	for i := range rows {
		rows[i].BucketMs = parseBucketToMillis(rows[i].Bucket)
	}
	return rows, nil
}

// ConnectionFlowResult holds sFlow traffic analysis for a connection.
type ConnectionFlowResult struct {
	TotalBytes       uint64             `json:"total_bytes"`
	TotalPackets     uint64             `json:"total_packets"`
	TotalFlows       int64              `json:"total_flows"`
	ByProtocol       []KeyCount         `json:"by_protocol"`
	TopSources       []KeyCount         `json:"top_sources"`
	TopDests         []KeyCount         `json:"top_destinations"`
	TopConversations []FlowConversation `json:"top_conversations"`
	BytesOverTime    []TimeBucket       `json:"bytes_over_time"`
	BucketSeconds    int                `json:"bucket_seconds"` // width of each bytes_over_time bucket, so the UI can render a rate
}

// cidrToLikePattern converts a CIDR subnet to a SQL LIKE pattern.
// Works for /8, /16, /24 which cover ~99% of real VPN subnets.
// Returns empty string for invalid, too-broad (e.g. 0.0.0.0/0), or unsupported prefix lengths.
//
// AUDIT-148: the output of this function is fed verbatim into a SQL
// LIKE clause (with the `ESCAPE '\'` modifier at the call site).
// The patterns only ever contain digits, dots, and an intentional
// trailing `%` (the wildcard), so today's input set is safe by
// construction — `net.ParseIP` and `net.ParseCIDR` reject anything
// that isn't a valid IP literal. The defense-in-depth is the ESCAPE
// clause at the call site, not anything in this function.
func cidrToLikePattern(cidr string) string {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" || cidr == "0.0.0.0/0" {
		return ""
	}

	// Handle non-CIDR formats: "10.0.1.0 - 10.0.1.255" or bare IPs
	if !strings.Contains(cidr, "/") {
		// IP range format
		if strings.Contains(cidr, " - ") {
			parts := strings.SplitN(cidr, " - ", 2)
			beginIP := net.ParseIP(strings.TrimSpace(parts[0]))
			if beginIP == nil {
				return ""
			}
			b := beginIP.To4()
			if b == nil {
				return ""
			}
			return fmt.Sprintf("%d.%d.%d.%%", b[0], b[1], b[2])
		}
		// Single IP — exact match
		if net.ParseIP(cidr) != nil {
			return cidr
		}
		return ""
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return ""
	}
	ones, _ := ipNet.Mask.Size()
	switch {
	case ones == 32:
		return fmt.Sprintf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3])
	case ones >= 24:
		return fmt.Sprintf("%d.%d.%d.%%", ip4[0], ip4[1], ip4[2])
	case ones >= 16:
		return fmt.Sprintf("%d.%d.%%", ip4[0], ip4[1])
	case ones >= 8:
		return fmt.Sprintf("%d.%%", ip4[0])
	default:
		return ""
	}
}

// GetConnectionFlowStats returns sFlow traffic analysis for a connection.
// Primary strategy: filter flows by VPN subnet pairs (local/remote).
// Fallback: match tunnel interface indices by name (including Phase1Name).
func (d *Database) GetConnectionFlowStats(connID uint, hours int) (*ConnectionFlowResult, error) {
	srcDeviceID, dstDeviceID, srcTunnelNames, dstTunnelNames, err := d.getConnectionTunnelNames(connID)
	if err != nil {
		return nil, err
	}

	var tunnelNames []string
	tunnelNames = append(tunnelNames, srcTunnelNames...)
	tunnelNames = append(tunnelNames, dstTunnelNames...)
	if len(tunnelNames) == 0 {
		return &ConnectionFlowResult{}, nil
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	deviceIDs := []uint{srcDeviceID, dstDeviceID}

	// --- Strategy 1: Subnet-based filtering ---
	// Query VPN statuses for these tunnel names to get (local_subnet, remote_subnet) pairs
	type subnetPair struct {
		LocalSubnet  string
		RemoteSubnet string
	}
	var pairs []subnetPair
	d.db.Raw(`SELECT DISTINCT local_subnet, remote_subnet FROM vpn_status
		WHERE device_id IN ? AND tunnel_name IN ? AND local_subnet != '' AND remote_subnet != ''`,
		deviceIDs, tunnelNames).Scan(&pairs)

	// Convert subnet pairs to LIKE patterns
	var subnetConditions []string
	var subnetArgs []interface{}
	for _, p := range pairs {
		localPattern := cidrToLikePattern(p.LocalSubnet)
		remotePattern := cidrToLikePattern(p.RemoteSubnet)
		if localPattern == "" || remotePattern == "" {
			continue
		}
		// Bidirectional: src in local AND dst in remote, OR vice versa.
		// AUDIT-148: the `ESCAPE '\'` clause makes the LIKE evaluator
		// treat `\%` and `\_` as literal `%` / `_` rather than wildcards.
		// Today's patterns (built by cidrToLikePattern) never contain
		// literal `%` or `_` in user-controlled positions — only an
		// intentional trailing `%` as the "any" wildcard — so this is
		// defense-in-depth. The escape character `\` itself is never
		// emitted by cidrToLikePattern, so no double-escape is needed.
		subnetConditions = append(subnetConditions,
			"(src_addr LIKE ? ESCAPE '\\' AND dst_addr LIKE ? ESCAPE '\\')",
			"(src_addr LIKE ? ESCAPE '\\' AND dst_addr LIKE ? ESCAPE '\\')")
		subnetArgs = append(subnetArgs, localPattern, remotePattern, remotePattern, localPattern)
	}

	result := &ConnectionFlowResult{}

	var newBase func() *gorm.DB

	if len(subnetConditions) > 0 {
		// Use subnet-based filtering
		subnetWhere := strings.Join(subnetConditions, " OR ")
		newBase = func() *gorm.DB {
			return d.db.Model(&models.FlowSample{}).
				Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
				Where(subnetWhere, subnetArgs...)
		}
	} else {
		// --- Strategy 2 (fallback): Interface index matching with Phase1Names ---
		// Collect Phase1Names alongside tunnel names for better interface matching
		var phase1Names []string
		d.db.Raw(`SELECT DISTINCT phase1_name FROM vpn_status
			WHERE device_id IN ? AND tunnel_name IN ? AND phase1_name != ''`,
			deviceIDs, tunnelNames).Pluck("phase1_name", &phase1Names)

		allNames := make([]string, 0, len(tunnelNames)+len(phase1Names))
		allNames = append(allNames, tunnelNames...)
		allNames = append(allNames, phase1Names...)

		var tunnelIfIndices []int
		ifIndexSet := make(map[int]bool)
		var ifaces []models.InterfaceStats
		d.db.Raw(fmt.Sprintf("SELECT DISTINCT device_id, %s FROM interface_stats WHERE device_id IN ? AND (name IN ? OR description IN ? OR alias IN ?)", d.dialect.QuoteIdent("index")),
			deviceIDs, allNames, allNames, allNames).Scan(&ifaces)
		for _, iface := range ifaces {
			ifIndexSet[iface.Index] = true
		}
		for idx := range ifIndexSet {
			tunnelIfIndices = append(tunnelIfIndices, idx)
		}
		if len(tunnelIfIndices) == 0 {
			return &ConnectionFlowResult{}, nil
		}

		newBase = func() *gorm.DB {
			return d.db.Model(&models.FlowSample{}).
				Where("device_id IN ? AND timestamp > ?", deviceIDs, cutoff).
				Where("input_if_index IN ? OR output_if_index IN ?", tunnelIfIndices, tunnelIfIndices)
		}
	}

	// Total counts from raw samples
	newBase().Count(&result.TotalFlows)
	var totalBytes struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(bytes),0) as sum").Scan(&totalBytes)
	result.TotalBytes = totalBytes.Sum
	var totalPackets struct{ Sum uint64 }
	newBase().Select("COALESCE(SUM(packets),0) as sum").Scan(&totalPackets)
	result.TotalPackets = totalPackets.Sum

	// Supplement with rollup data for historical periods (subnet strategy only).
	// Every rollup tier whose age band intersects the window must be included —
	// the tiers are disjoint (promotion deletes the source rows), so a single
	// "best" interval left the younger bands out of long windows entirely. See
	// rollupIntervalsForWindow (flows.go).
	if hours > 1 && len(subnetConditions) > 0 {
		rollupIntervals := rollupIntervalsForWindow(hours)
		subnetWhere := strings.Join(subnetConditions, " OR ")
		rollupBase := func() *gorm.DB {
			return d.db.Model(&models.FlowRollup{}).
				Where("device_id IN ? AND timestamp > ? AND interval_type IN ?", deviceIDs, cutoff, rollupIntervals).
				Where(subnetWhere, subnetArgs...)
		}
		var rollupAgg struct {
			Flows int64
			Bytes uint64
			Pkts  uint64
		}
		rollupBase().Select("COALESCE(SUM(flow_count),0) as flows, COALESCE(SUM(bytes_sum),0) as bytes, COALESCE(SUM(packets_sum),0) as pkts").Scan(&rollupAgg)
		result.TotalFlows += rollupAgg.Flows
		result.TotalBytes += rollupAgg.Bytes
		result.TotalPackets += rollupAgg.Pkts
	}

	// Protocol distribution
	var protocols []struct {
		Protocol uint8
		Count    int64
	}
	newBase().Select("protocol, COUNT(*) as count").Group("protocol").Order("count DESC").Limit(10).Scan(&protocols)
	for _, p := range protocols {
		result.ByProtocol = append(result.ByProtocol, KeyCount{Key: protoName(p.Protocol), Count: p.Count})
	}

	// Top sources / destinations by bytes
	result.TopSources = topAddrsByBytes(newBase, "src_addr", 10)
	result.TopDests = topAddrsByBytes(newBase, "dst_addr", 10)

	// Top conversations
	var convos []struct {
		SrcAddr  string
		DstAddr  string
		SrcPort  uint16
		DstPort  uint16
		Protocol uint8
		Bytes    uint64
		Packets  uint64
	}
	newBase().Select("src_addr, dst_addr, src_port, dst_port, protocol, SUM(bytes) as bytes, SUM(packets) as packets").
		Group("src_addr, dst_addr, src_port, dst_port, protocol").Order("bytes DESC").Limit(10).Scan(&convos)
	for _, c := range convos {
		result.TopConversations = append(result.TopConversations, FlowConversation{
			SrcAddr: c.SrcAddr, DstAddr: c.DstAddr,
			SrcPort: c.SrcPort, DstPort: c.DstPort,
			Protocol: protoName(c.Protocol), Bytes: c.Bytes, Packets: c.Packets,
		})
	}

	// Bytes over time
	var timeSeries []struct {
		Bucket string `json:"bucket"`
		Total  int64  `json:"total"`
	}
	newBase().Select(d.dialect.TimeBucket("hour", "timestamp") + " as bucket, SUM(bytes) as total").
		Group("bucket").Order("bucket ASC").Scan(&timeSeries)
	result.BucketSeconds = 3600 // bytes_over_time is bucketed hourly above
	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}

// buildConnectionEvidence re-runs the L2 link inference over just the
// connection's two endpoint devices and returns the evidence rows of the link
// matching this connection's port attribution — the same ALGORITHM that drew
// the edge (internal/l2infer). Caveat: the poller runs it fleet-wide, so
// ambiguity handling can differ here — a MAC/sysname that is multi-owner
// across the fleet (dropped by the detector) resolves cleanly in this
// two-device universe; the view is explanatory, not authoritative.
// Returns nil for non-L2 match methods or when the evidence has aged past the
// grace window (the UI renders an explicit empty state).
func (d *Database) buildConnectionEvidence(conn *models.DeviceConnection) []L2EvidenceOut {
	switch conn.MatchMethod {
	case l2infer.MethodLLDP, l2infer.MethodFDB, l2infer.MethodARP:
	default:
		return nil
	}

	ids := []uint{conn.SourceDeviceID, conn.DestDeviceID}
	var devices []models.Device
	if err := d.db.Where("id IN ?", ids).Find(&devices).Error; err != nil || len(devices) < 2 {
		return nil
	}

	devs := make([]l2infer.DeviceMeta, 0, 2)
	for i := range devices {
		dev := &devices[i]
		ips := []string{dev.IPAddress}
		for ip := range d.collectDeviceIPs(dev.ID, dev) {
			ips = append(ips, ip)
		}
		devs = append(devs, l2infer.DeviceMeta{ID: dev.ID, Name: dev.Name, SiteID: dev.SiteID, IPs: ips})
	}

	var ifaces []l2infer.Iface
	deviceNames := map[uint]string{}
	for i := range devices {
		deviceNames[devices[i].ID] = devices[i].Name
		for _, st := range d.latestInterfacesForDevice(devices[i].ID) {
			ifaces = append(ifaces, l2infer.Iface{
				DeviceID: st.DeviceID, IfIndex: st.Index, Name: st.Name,
				MAC: st.MACAddress, Status: st.Status, TypeName: strings.ToLower(st.TypeName),
			})
		}
	}

	cutoff := time.Now().Add(-l2infer.GraceWindow)
	var entries []models.TopologyEntry
	d.db.Where("device_id IN ? AND timestamp >= ?", ids, cutoff).Find(&entries)
	var neighbors []models.TopologyNeighbor
	d.db.Where("device_id IN ? AND timestamp >= ?", ids, cutoff).Find(&neighbors)

	var fdb []l2infer.FDBRow
	var arp []l2infer.ARPRow
	for _, e := range entries {
		switch e.EntryType {
		case "fdb":
			fdb = append(fdb, l2infer.FDBRow{DeviceID: e.DeviceID, IfIndex: e.IfIndex, IfName: e.IfName, MAC: e.MACAddress, VLANID: e.VlanID, Ts: e.Timestamp})
		case "arp":
			arp = append(arp, l2infer.ARPRow{DeviceID: e.DeviceID, IfIndex: e.IfIndex, IfName: e.IfName, IP: e.IPAddress, MAC: e.MACAddress, Ts: e.Timestamp})
		}
	}
	var nbrs []l2infer.NeighborRow
	for _, n := range neighbors {
		nbrs = append(nbrs, l2infer.NeighborRow{
			DeviceID: n.DeviceID, LocalIfIndex: n.LocalIfIndex, LocalIfName: n.LocalPortName,
			ChassisID: n.RemoteChassisID, PortID: n.RemotePortID, PortDesc: n.RemotePortDesc,
			SysName: n.RemoteSysName, Ts: n.Timestamp,
		})
	}

	links := l2infer.InferLinks(devs, ifaces, fdb, arp, nbrs)
	if len(links) == 0 {
		return nil
	}

	// Pick the link matching this row's port attribution; with a single link
	// (the common case) fall back to it even if the ports have since moved.
	var match *l2infer.Link
	for i := range links {
		l := &links[i]
		if l.AIfIndex == conn.SourceIfIndex && l.BIfIndex == conn.DestIfIndex {
			match = l
			break
		}
	}
	if match == nil && len(links) == 1 {
		match = &links[0]
	}
	if match == nil {
		return nil
	}

	fresh := time.Now().Add(-l2infer.FreshWindow)
	out := make([]L2EvidenceOut, 0, len(match.Evidence))
	for _, ev := range match.Evidence {
		out = append(out, L2EvidenceOut{
			EvidenceRef: ev,
			DeviceName:  deviceNames[ev.DeviceID],
			Fresh:       !ev.Timestamp.Before(fresh),
		})
	}
	return out
}

// resolveL2EndpointInterfaces resolves a port-level connection's interfaces
// side-precisely: the source port on the SOURCE device and the dest port on
// the DEST device (ifIndex first, normalized name fallback). Returns nil for
// connections without port endpoints (legacy rows fall back to the
// TunnelNames name-list resolution).
func (d *Database) resolveL2EndpointInterfaces(conn *models.DeviceConnection) []ConnInterfaceRef {
	type side struct {
		deviceID uint
		device   *models.Device
		ifIndex  int
		ifName   string
	}
	sides := []side{
		{conn.SourceDeviceID, conn.SourceDevice, conn.SourceIfIndex, conn.SourceIfName},
		{conn.DestDeviceID, conn.DestDevice, conn.DestIfIndex, conn.DestIfName},
	}

	var refs []ConnInterfaceRef
	for _, s := range sides {
		if s.ifIndex == 0 && s.ifName == "" {
			continue // that end's port is unknown (one-sided evidence)
		}
		var match *models.InterfaceStats
		ifaces := d.latestInterfacesForDevice(s.deviceID)
		for i := range ifaces {
			if s.ifIndex > 0 && ifaces[i].Index == s.ifIndex {
				match = &ifaces[i]
				break
			}
		}
		if match == nil && s.ifName != "" {
			nn := normalizeIfName(s.ifName)
			for i := range ifaces {
				if normalizeIfName(ifaces[i].Name) == nn {
					match = &ifaces[i]
					break
				}
			}
		}
		if match == nil {
			continue
		}

		// Gate to the device's CURRENT poll — a stale address must never
		// surface on a live link (the 10.10.10.1-on-a-dmz-with-no-IP bug).
		addr := d.latestAddressForDeviceIf(s.deviceID, match.Index)

		deviceName := ""
		if s.device != nil {
			deviceName = s.device.Name
		}
		refs = append(refs, ConnInterfaceRef{
			DeviceID:   s.deviceID,
			DeviceName: deviceName,
			IfName:     match.Name,
			IfIndex:    match.Index,
			IPAddress:  addr.IPAddress,
			Subnet:     computeNetworkCIDR(addr.IPAddress, addr.NetMask),
			Kind:       match.TypeName,
			VlanID:     match.VLANID,
			Speed:      match.Speed,
			Status:     match.Status,
			InBytes:    match.InBytes,
			OutBytes:   match.OutBytes,
			InErrors:   match.InErrors,
			OutErrors:  match.OutErrors,
		})
	}
	// Only meaningful when at least one end resolved to a REAL interface;
	// otherwise let the legacy path try the name list.
	return refs
}

// windowedTraffic computes one side's reset-safe traffic over [from, to]: the
// side total, a per-tunnel-name breakdown, and how far that breakdown can be
// trusted to mean "per path".
//
// The side total goes through the GROUPED query on purpose — its collapse of
// identical-counter siblings is exactly what stops a FortiGate's replicated
// per-phase2 rows from multiplying the tunnel's traffic by its selector count.
// The per-path map deliberately skips that collapse, because attribution needs
// real names; the provenance flags are what tell the UI when that map is not
// safe to show per path.
func (d *Database) windowedTraffic(deviceID uint, rows []models.VPNStatus, from, to time.Time) (VPNWindowTotal, map[string]VPNWindowTotal, VPNCounterProvenance) {
	names := make([]string, 0, len(rows))
	seen := map[string]bool{}
	for _, r := range rows {
		if r.TunnelName == "" || seen[r.TunnelName] {
			continue
		}
		seen[r.TunnelName] = true
		names = append(names, r.TunnelName)
	}
	var side VPNWindowTotal
	if len(names) == 0 {
		return side, nil, VPNCounterProvenance{}
	}
	if buckets, err := d.GetVPNChartGroupWindow(deviceID, names, from, to); err == nil {
		for _, b := range buckets {
			side.InBytes += uint64(b.InBytes)
			side.OutBytes += uint64(b.OutBytes)
		}
	} else {
		log.Printf("windowedTraffic: side total for device %d failed: %v", deviceID, err)
	}
	perPath, err := d.GetVPNWindowTotalsByTunnel(deviceID, names, from, to)
	if err != nil {
		log.Printf("windowedTraffic: per-path totals for device %d failed: %v", deviceID, err)
	}
	prov, err := d.GetVPNCounterProvenance(deviceID, names, from, to)
	if err != nil {
		log.Printf("windowedTraffic: counter provenance for device %d failed: %v", deviceID, err)
	}
	return side, perPath, prov
}
