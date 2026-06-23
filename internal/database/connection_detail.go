package database

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/snmp"

	"gorm.io/gorm"
)

// Phase2Match represents a matched pair of Phase 2 selectors between two devices.
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
			// ends by the LAN segment that joins them (the detector's grouping key).
			var addr models.InterfaceAddress
			d.db.Where("device_id = ? AND if_index = ?", dv.id, st.Index).
				Order("timestamp DESC").Limit(1).First(&addr)

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
		result.Interfaces = d.resolveConnectionInterfaces(&conn)
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
						}
						if result.SourceTunnels[i].RemoteSubnet == "" {
							result.SourceTunnels[i].RemoteSubnet = dst.LocalSubnet
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
						}
						if result.DestTunnels[i].RemoteSubnet == "" {
							result.DestTunnels[i].RemoteSubnet = src.LocalSubnet
						}
						break
					}
				}
			}
		}
	}

	// Cross-fill tunnel uptime: if one side reports 0 uptime, use the paired tunnel's value.
	if len(result.SourceTunnels) > 0 && len(result.DestTunnels) > 0 {
		for i := range result.SourceTunnels {
			if result.SourceTunnels[i].TunnelUptime == 0 {
				for _, dst := range result.DestTunnels {
					if dst.TunnelUptime > 0 {
						result.SourceTunnels[i].TunnelUptime = dst.TunnelUptime
						break
					}
				}
			}
		}
		for i := range result.DestTunnels {
			if result.DestTunnels[i].TunnelUptime == 0 {
				for _, src := range result.SourceTunnels {
					if src.TunnelUptime > 0 {
						result.DestTunnels[i].TunnelUptime = src.TunnelUptime
						break
					}
				}
			}
		}
	}

	// Phase 2 inverse matching: source's local_subnet == dest's remote_subnet (and vice versa)
	for _, src := range result.SourceTunnels {
		if src.LocalSubnet == "" || src.RemoteSubnet == "" {
			continue
		}
		for _, dst := range result.DestTunnels {
			if dst.LocalSubnet == "" || dst.RemoteSubnet == "" {
				continue
			}
			if src.LocalSubnet == dst.RemoteSubnet && src.RemoteSubnet == dst.LocalSubnet {
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

// rangeToHours maps the connection-traffic range presets to a lookback in hours.
func rangeToHours(rangeStr string) int {
	switch rangeStr {
	case "1h":
		return 1
	case "7d":
		return 168
	case "30d":
		return 720
	default: // 24h
		return 24
	}
}

// interfaceTrafficWindow aggregates per-interface chart buckets (from
// GetInterfaceChartWindow) into a single series in the same shape the VPN
// traffic chart returns, so the frontend renders direct links identically.
// Buckets align across interfaces because they share one [from,to] window and
// adaptive bucket size; rows are merged by bucket string and returned sorted.
func (d *Database) interfaceTrafficWindow(refs []ConnInterfaceRef, rangeStr string) ([]VPNChartBucket, error) {
	if len(refs) == 0 {
		return []VPNChartBucket{}, nil
	}
	to := time.Now()
	from := to.Add(-time.Duration(rangeToHours(rangeStr)) * time.Hour)

	agg := make(map[string]*VPNChartBucket)
	for _, r := range refs {
		buckets, err := d.GetInterfaceChartWindow(r.DeviceID, r.IfIndex, from, to)
		if err != nil {
			return nil, err
		}
		for _, b := range buckets {
			e := agg[b.Bucket]
			if e == nil {
				e = &VPNChartBucket{Bucket: b.Bucket, BucketMs: b.BucketMs}
				agg[b.Bucket] = e
			}
			e.InBytes += b.InBytes
			e.OutBytes += b.OutBytes
			e.InPackets += b.InPackets
			e.OutPackets += b.OutPackets
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
func (d *Database) GetConnectionTraffic(connID uint, rangeStr string) ([]VPNChartBucket, error) {
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
		return d.interfaceTrafficWindow(primary, rangeStr)
	}

	srcDeviceID, dstDeviceID, srcTunnelNames, dstTunnelNames, err := d.getConnectionTunnelNames(connID)
	if err != nil {
		return nil, err
	}

	// Determine time params
	var hours int
	var bucketExpr string
	switch rangeStr {
	case "1h":
		hours = 1
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	case "7d":
		hours = 168
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	case "30d":
		hours = 720
		bucketExpr = d.dialect.TimeBucket("hour", "timestamp")
	default:
		hours = 24
		bucketExpr = d.dialect.TimeBucket("minute", "timestamp")
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Collect all tunnel conditions
	var allNames []string
	var deviceIDs []uint
	for _, n := range srcTunnelNames {
		allNames = append(allNames, n)
	}
	for _, n := range dstTunnelNames {
		allNames = append(allNames, n)
	}
	if len(srcTunnelNames) > 0 {
		deviceIDs = append(deviceIDs, srcDeviceID)
	}
	if len(dstTunnelNames) > 0 {
		deviceIDs = append(deviceIDs, dstDeviceID)
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
			FROM vpn_status
			WHERE device_id IN (%s) AND tunnel_name IN (%s) AND timestamp > ?
			WINDOW w AS (PARTITION BY device_id, tunnel_name ORDER BY timestamp)
		) AS deltas WHERE delta_in IS NOT NULL
		GROUP BY bucket ORDER BY bucket ASC`,
		bucketExpr, strings.Join(devPH, ","), strings.Join(namePH, ","))

	var rows []VPNChartBucket
	err = d.db.Raw(query, args...).Scan(&rows).Error
	if err != nil {
		return nil, err
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

	// Supplement with rollup data for historical periods (subnet strategy only)
	if hours > 1 && len(subnetConditions) > 0 {
		rollupInterval := "5m"
		if hours > 48 {
			rollupInterval = "1h"
		}
		if hours > 720 {
			rollupInterval = "1d"
		}
		subnetWhere := strings.Join(subnetConditions, " OR ")
		rollupBase := func() *gorm.DB {
			return d.db.Model(&models.FlowRollup{}).
				Where("device_id IN ? AND timestamp > ? AND interval_type = ?", deviceIDs, cutoff, rollupInterval).
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
	for _, t := range timeSeries {
		result.BytesOverTime = append(result.BytesOverTime, TimeBucket{Bucket: t.Bucket, Count: t.Total})
	}

	return result, nil
}
