package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/l2infer"
	"firewall-mon/internal/models"
)

// L2 evidence freshness windows. Evidence newer than l2EvidenceFresh yields a
// normal up/down link; between fresh and grace the link persists with status
// "stale" (amber in the NOC); past grace it is no longer upserted and the
// cycle's CleanupStaleAutoConnectionsBefore sweep deletes the row. The
// up → stale → deleted staircase means one missed topology snapshot (5-minute
// cadence) can't flap the map.
const (
	l2EvidenceFresh = l2infer.FreshWindow
	l2EvidenceGrace = l2infer.GraceWindow
)

// detectL2Links infers port-to-port links between same-site devices from the
// relayed L2 topology evidence (LLDP/CDP neighbors, FDB/MAC tables, ARP
// caches — internal/l2infer) and upserts them as auto-detected connections
// with port labels on both ends. This replaced detectPhysicalConnections'
// shared-subnet guess (v0.11.94): links are only drawn when layer-2 evidence
// backs them ("hide unconfirmed").
func (p *Poller) detectL2Links(devices []models.Device) int {
	if p.db == nil || len(devices) == 0 {
		return 0
	}

	ifaces, err := p.db.GetAllLatestInterfaces()
	if err != nil {
		log.Printf("L2 auto-detect: failed to get interfaces - %v", err)
		return 0
	}
	ifAddrs, err := p.db.GetLatestInterfaceAddresses()
	if err != nil {
		log.Printf("L2 auto-detect: failed to get interface addresses - %v", err)
		return 0
	}

	devs, infIfaces, ownedMACs := buildL2Inputs(devices, ifaces, ifAddrs)

	cutoff := time.Now().Add(-l2EvidenceGrace)
	// FDB is SQL-filtered to monitored interface MACs (multi-thousand-row
	// tables); ARP is read unfiltered — its IP-fallback match needs rows
	// whose MAC is NOT a monitored interface MAC.
	fdbRows, err := p.db.GetTopologyEntriesSince(cutoff, "fdb", ownedMACs)
	if err != nil {
		log.Printf("L2 auto-detect: failed to get FDB evidence - %v", err)
		return 0
	}
	arpRows, err := p.db.GetTopologyEntriesSince(cutoff, "arp", nil)
	if err != nil {
		log.Printf("L2 auto-detect: failed to get ARP evidence - %v", err)
		return 0
	}
	nbrRows, err := p.db.GetTopologyNeighborsSince(cutoff)
	if err != nil {
		log.Printf("L2 auto-detect: failed to get neighbor evidence - %v", err)
		return 0
	}

	links := l2infer.InferLinks(devs, infIfaces,
		toFDBRows(fdbRows), toARPRows(arpRows), toNeighborRows(nbrRows))
	if len(links) == 0 {
		return 0
	}

	deviceByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		deviceByID[devices[i].ID] = &devices[i]
	}

	now := time.Now()
	created := 0
	tierCounts := map[string]int{}
	staleCount := 0
	for _, link := range links {
		status := link.Status
		if link.LatestEvidence.Before(now.Add(-l2EvidenceFresh)) {
			status = "stale"
			staleCount++
		}

		connType := "ethernet"
		if l2infer.EndpointTypeName(infIfaces, link.A, link.AIfIndex, link.AIfName) == "lag" ||
			l2infer.EndpointTypeName(infIfaces, link.B, link.BIfIndex, link.BIfName) == "lag" {
			connType = "lag"
		}

		if err := p.db.UpsertAutoL2Connection(buildL2Upsert(link, deviceByID, status, connType)); err != nil {
			log.Printf("L2 auto-detect: failed to upsert link %d↔%d - %v", link.A, link.B, err)
			continue
		}
		created++
		tierCounts[link.Method]++
	}

	if created > 0 {
		log.Printf("L2 auto-detect: upserted %d link(s) (lldp=%d fdb=%d arp=%d stale=%d)",
			created, tierCounts[l2infer.MethodLLDP], tierCounts[l2infer.MethodFDB],
			tierCounts[l2infer.MethodARP], staleCount)
	}
	return created
}

// buildL2Inputs adapts the poller's device/interface rows into l2infer inputs
// and collects the (lowercased) monitored interface MACs for the FDB filter.
func buildL2Inputs(devices []models.Device, ifaces []models.InterfaceStats, ifAddrs []models.InterfaceAddress) ([]l2infer.DeviceMeta, []l2infer.Iface, []string) {
	ipsByDevice := map[uint][]string{}
	for _, a := range ifAddrs {
		if a.IPAddress != "" {
			ipsByDevice[a.DeviceID] = append(ipsByDevice[a.DeviceID], a.IPAddress)
		}
	}

	devs := make([]l2infer.DeviceMeta, 0, len(devices))
	for i := range devices {
		d := &devices[i]
		ips := append([]string(nil), ipsByDevice[d.ID]...)
		if d.IPAddress != "" {
			ips = append(ips, d.IPAddress)
		}
		devs = append(devs, l2infer.DeviceMeta{ID: d.ID, Name: d.Name, SiteID: d.SiteID, IPs: ips})
	}

	infIfaces := make([]l2infer.Iface, 0, len(ifaces))
	macSet := map[string]bool{}
	for _, f := range ifaces {
		infIfaces = append(infIfaces, l2infer.Iface{
			DeviceID: f.DeviceID,
			IfIndex:  f.Index,
			Name:     f.Name,
			MAC:      f.MACAddress,
			Status:   f.Status,
			TypeName: strings.ToLower(f.TypeName),
		})
		if mac := l2infer.NormalizeMAC(f.MACAddress); mac != "" && !l2infer.IsVirtualMAC(mac) {
			macSet[mac] = true
		}
	}
	ownedMACs := make([]string, 0, len(macSet))
	for mac := range macSet {
		ownedMACs = append(ownedMACs, mac)
	}
	sort.Strings(ownedMACs)
	return devs, infIfaces, ownedMACs
}

func toFDBRows(entries []models.TopologyEntry) []l2infer.FDBRow {
	out := make([]l2infer.FDBRow, 0, len(entries))
	for _, e := range entries {
		out = append(out, l2infer.FDBRow{
			DeviceID: e.DeviceID, IfIndex: e.IfIndex, MAC: e.MACAddress,
			VLANID: e.VlanID, Ts: e.Timestamp,
		})
	}
	return out
}

func toARPRows(entries []models.TopologyEntry) []l2infer.ARPRow {
	out := make([]l2infer.ARPRow, 0, len(entries))
	for _, e := range entries {
		out = append(out, l2infer.ARPRow{
			DeviceID: e.DeviceID, IfIndex: e.IfIndex, IfName: e.IfName,
			IP: e.IPAddress, MAC: e.MACAddress, Ts: e.Timestamp,
		})
	}
	return out
}

func toNeighborRows(rows []models.TopologyNeighbor) []l2infer.NeighborRow {
	out := make([]l2infer.NeighborRow, 0, len(rows))
	for _, n := range rows {
		out = append(out, l2infer.NeighborRow{
			DeviceID:     n.DeviceID,
			LocalIfIndex: n.LocalIfIndex,
			LocalIfName:  n.LocalPortName,
			ChassisID:    n.RemoteChassisID,
			PortID:       n.RemotePortID,
			PortDesc:     n.RemotePortDesc,
			SysName:      n.RemoteSysName,
			Ts:           n.Timestamp,
		})
	}
	return out
}

// buildL2Upsert builds the upsert payload: link name with port labels
// ("core:port2 ↔ branch:lan1"), TunnelNames carrying the port names so the
// existing direct-family interface resolution keeps working, VLANs as a
// comma list.
func buildL2Upsert(link l2infer.Link, deviceByID map[uint]*models.Device, status, connType string) database.L2LinkUpsert {
	nameFor := func(id uint) string {
		if d, ok := deviceByID[id]; ok {
			return d.Name
		}
		return fmt.Sprintf("device-%d", id)
	}
	portLabel := func(name string) string {
		if name == "" {
			return "?"
		}
		return name
	}

	var vlans []string
	for _, v := range link.VLANIDs {
		vlans = append(vlans, fmt.Sprintf("%d", v))
	}
	var tunnelNames []string
	if link.AIfName != "" {
		tunnelNames = append(tunnelNames, link.AIfName)
	}
	if link.BIfName != "" && !strings.EqualFold(link.BIfName, link.AIfName) {
		tunnelNames = append(tunnelNames, link.BIfName)
	}

	return database.L2LinkUpsert{
		SourceID:      link.A,
		DestID:        link.B,
		Status:        status,
		Name:          fmt.Sprintf("%s:%s ↔ %s:%s", nameFor(link.A), portLabel(link.AIfName), nameFor(link.B), portLabel(link.BIfName)),
		ConnType:      connType,
		MatchMethod:   link.Method,
		SourceIfIndex: link.AIfIndex,
		SourceIfName:  link.AIfName,
		DestIfIndex:   link.BIfIndex,
		DestIfName:    link.BIfName,
		VLANIDs:       strings.Join(vlans, ","),
		TunnelNames:   strings.Join(tunnelNames, ", "),
	}
}
