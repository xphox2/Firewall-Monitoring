package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
	"firewall-mon/internal/snmp"
)

type Poller struct {
	cfg          *config.Config
	db           *database.Database
	alertManager *alerts.AlertManager
	stopChan     chan struct{}
}

func NewPoller(cfg *config.Config, db *database.Database, am *alerts.AlertManager) *Poller {
	return &Poller{
		cfg:          cfg,
		db:           db,
		alertManager: am,
		stopChan:     make(chan struct{}),
	}
}

func (p *Poller) Start() error {
	if p.cfg.SNMP.PollInterval < 30*time.Second {
		p.cfg.SNMP.PollInterval = 30 * time.Second
	}

	log.Printf("Starting SNMP poller with interval: %v", p.cfg.SNMP.PollInterval)

	// Clean up stale auto-detected connections from generic interface names
	if p.db != nil {
		removed := p.db.CleanupStaleAutoConnections([]string{"ssl.root", "ssl.vdom", "naf.root", "l2t.root"})
		if removed > 0 {
			log.Printf("Cleaned up %d stale auto-detected connection(s) from generic tunnel names", removed)
		}
	}

	// Poll immediately on startup
	p.pollAllDevices()

	ticker := time.NewTicker(p.cfg.SNMP.PollInterval)
	defer ticker.Stop()

	// Cleanup old data daily
	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			p.pollAllDevices()
		case <-cleanupTicker.C:
			if p.db != nil {
				if err := p.db.CleanupOldData(90); err != nil {
					log.Printf("Data cleanup error: %v", err)
				} else {
					log.Println("Old data cleanup completed (>90 days)")
				}
			}
			if p.alertManager != nil {
				p.alertManager.PruneExpiredCooldowns()
			}
		case <-p.stopChan:
			log.Println("Poller stopped")
			return nil
		}
	}
}

func (p *Poller) pollAllDevices() {
	if p.db == nil {
		log.Println("Database not connected, skipping poll")
		return
	}

	// Refresh alert thresholds from DB so admin UI changes take effect
	if p.alertManager != nil {
		p.alertManager.RefreshThresholds(p.db.Gorm())
	}

	devices, err := p.db.GetAllDevices()
	if err != nil {
		log.Printf("Error getting devices: %v", err)
		return
	}

	if len(devices) == 0 {
		log.Println("No devices configured, skipping poll")
		return
	}

	log.Printf("Polling %d devices...", len(devices))

	// Poll devices concurrently with a semaphore to limit concurrent SNMP connections
	sem := make(chan struct{}, 5) // max 5 concurrent polls
	var wg sync.WaitGroup
	for i := range devices {
		if !devices[i].Enabled {
			continue
		}
		// Skip devices assigned to a remote probe — they are polled by the probe, not the server
		if devices[i].ProbeID != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore
		go func(device *models.Device) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore
			p.pollDevice(device)
		}(&devices[i])
	}
	wg.Wait()

	// Mark probe-assigned devices offline if their last_polled is stale.
	// Uses 3× poll interval as the threshold (minimum 5 minutes).
	staleAfter := 3 * p.cfg.SNMP.PollInterval
	if staleAfter < 5*time.Minute {
		staleAfter = 5 * time.Minute
	}
	threshold := time.Now().Add(-staleAfter)
	if count, err := p.db.MarkStaleProbeDevicesOffline(threshold); err != nil {
		log.Printf("Stale device check error: %v", err)
	} else if count > 0 {
		log.Printf("Marked %d probe-assigned device(s) offline (no data for >%v)", count, staleAfter)
	}

	// Auto-detect connections — record cycle start BEFORE both detectors
	// so the stale cleanup doesn't delete connections from the first detector.
	connCycleStart := time.Now()
	p.detectVPNConnections(devices)
	p.detectOverlayConnections(devices)

	// Clean up auto-detected connections not refreshed by either detector
	if p.db != nil {
		removed := p.db.CleanupStaleAutoConnectionsBefore(connCycleStart)
		if removed > 0 {
			log.Printf("Connection cleanup: removed %d stale auto-detected connection(s)", removed)
		}
	}
}

func (p *Poller) pollDevice(device *models.Device) {
	cfg := &config.Config{
		SNMP: config.SNMPConfig{
			SNMPHost:   device.IPAddress,
			SNMPPort:   device.SNMPPort,
			Community:  device.SNMPCommunity,
			Version:    device.SNMPVersion,
			V3Username: device.SNMPV3Username,
			V3AuthType: device.SNMPV3AuthType,
			V3AuthPass: device.SNMPV3AuthPass,
			V3PrivType: device.SNMPV3PrivType,
			V3PrivPass: device.SNMPV3PrivPass,
			Timeout:    5 * time.Second,
			Retries:    2,
		},
	}

	client, err := snmp.NewSNMPClient(cfg)
	if err != nil {
		log.Printf("Device %s (%s): failed to connect - %v", device.Name, device.IPAddress, err)
		p.updateDeviceStatus(device, "offline")
		return
	}
	defer client.Close()

	vendor := device.Vendor
	if vendor == "" {
		vendor = "fortigate"
	}

	status, err := client.GetSystemStatus(vendor)
	if err != nil {
		log.Printf("Device %s (%s): poll error - %v", device.Name, device.IPAddress, err)
		p.updateDeviceStatus(device, "offline")
		return
	}

	log.Printf("Device %s (%s): CPU=%.1f%% Memory=%.1f%% Sessions=%d",
		device.Name, device.IPAddress, status.CPUUsage, status.MemoryUsage, status.SessionCount)

	// Save system status to database
	if p.db != nil {
		status.DeviceID = device.ID
		status.Timestamp = time.Now()
		if err := p.db.SaveSystemStatus(status); err != nil {
			log.Printf("Device %s: failed to save status - %v", device.Name, err)
		}
	}

	// Check alert thresholds
	if p.alertManager != nil {
		if err := p.alertManager.CheckSystemStatus(status); err != nil {
			log.Printf("Device %s: alert check error - %v", device.Name, err)
		}
	}

	// Save interface stats to database
	interfaces, err := client.GetInterfaceStats()
	if err == nil && len(interfaces) > 0 {
		if p.db != nil {
			now := time.Now()
			for i := range interfaces {
				interfaces[i].DeviceID = device.ID
				interfaces[i].Timestamp = now
			}
			if err := p.db.SaveInterfaceStats(interfaces); err != nil {
				log.Printf("Device %s: failed to save interface stats - %v", device.Name, err)
			}
		}
		// Check interface alerts
		if p.alertManager != nil {
			if err := p.alertManager.CheckInterfaceStatus(interfaces); err != nil {
				log.Printf("Device %s: interface alert check error - %v", device.Name, err)
			}
		}
	}

	// Collect interface IP addresses (standard IP-MIB, vendor-neutral)
	ifAddrs, err := client.GetInterfaceAddresses()
	if err != nil {
		log.Printf("Device %s: interface address walk error - %v", device.Name, err)
	} else if len(ifAddrs) > 0 {
		now := time.Now()
		for i := range ifAddrs {
			ifAddrs[i].DeviceID = device.ID
			ifAddrs[i].Timestamp = now
		}
		if p.db != nil {
			if err := p.db.SaveInterfaceAddresses(ifAddrs); err != nil {
				log.Printf("Device %s: failed to save interface addresses - %v", device.Name, err)
			}
		}
		log.Printf("Device %s: %d interface addresses collected", device.Name, len(ifAddrs))
	}

	// Collect VPN tunnel status
	vpnStatuses, err := client.GetVPNStatus(vendor)
	if err != nil {
		log.Printf("Device %s: VPN walk error - %v", device.Name, err)
	} else if len(vpnStatuses) == 0 {
		log.Printf("Device %s: VPN: 0 tunnels (none configured or no IPsec active)", device.Name)
	} else {
		now := time.Now()
		for i := range vpnStatuses {
			vpnStatuses[i].DeviceID = device.ID
			vpnStatuses[i].Timestamp = now
		}
		if p.db != nil {
			if err := p.db.SaveVPNStatuses(vpnStatuses); err != nil {
				log.Printf("Device %s: failed to save VPN statuses - %v", device.Name, err)
			}
		}
		if p.alertManager != nil {
			p.alertManager.CheckVPNStatus(vpnStatuses)
		}
	}

	// Collect hardware sensors
	sensors, err := client.GetHardwareSensors(vendor)
	if err != nil {
		log.Printf("Device %s: hardware sensor poll error - %v", device.Name, err)
	} else if len(sensors) > 0 {
		now := time.Now()
		for i := range sensors {
			sensors[i].DeviceID = device.ID
			sensors[i].Timestamp = now
		}
		if p.db != nil {
			if err := p.db.SaveHardwareSensors(sensors); err != nil {
				log.Printf("Device %s: failed to save hardware sensors - %v", device.Name, err)
			}
		}
	}

	// Collect processor stats (CPU cores, NP/SPU ASICs)
	procStats, err := client.GetProcessorStats(vendor)
	if err != nil {
		log.Printf("Device %s: processor stats poll error - %v", device.Name, err)
	} else if len(procStats) > 0 {
		now := time.Now()
		for i := range procStats {
			procStats[i].DeviceID = device.ID
			procStats[i].Timestamp = now
		}
		if p.db != nil {
			if err := p.db.SaveProcessorStats(procStats); err != nil {
				log.Printf("Device %s: failed to save processor stats - %v", device.Name, err)
			}
		}
	}

	p.updateDeviceStatus(device, "online")
}

// detectVPNConnections matches VPN tunnel remote IPs to known device IPs
// (management IP + all interface addresses) and auto-creates/updates DeviceConnection records.
func (p *Poller) detectVPNConnections(devices []models.Device) {
	if p.db == nil || len(devices) == 0 {
		return
	}

	// Build IP → Device map from management IPs
	ipToDevice := make(map[string]*models.Device, len(devices)*2)
	ipSource := make(map[string]string) // IP → "mgmt" or "interface"
	deviceByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		ipToDevice[devices[i].IPAddress] = &devices[i]
		ipSource[devices[i].IPAddress] = "mgmt"
		deviceByID[devices[i].ID] = &devices[i]
	}

	// Extend IP map with all interface addresses from IP-MIB
	ifAddrs, err := p.db.GetLatestInterfaceAddresses()
	if err != nil {
		log.Printf("VPN auto-detect: failed to get interface addresses - %v", err)
	} else {
		for _, addr := range ifAddrs {
			if _, exists := ipToDevice[addr.IPAddress]; exists {
				continue // management IP already mapped, keep it
			}
			if dev, ok := deviceByID[addr.DeviceID]; ok {
				ipToDevice[addr.IPAddress] = dev
				ipSource[addr.IPAddress] = "interface"
			}
		}
	}

	vpnStatuses, err := p.db.GetAllLatestVPNStatuses()
	if err != nil {
		log.Printf("VPN auto-detect: failed to get VPN statuses - %v", err)
		return
	}
	if len(vpnStatuses) == 0 {
		return
	}

	// Index VPN tunnels by device ID for bidirectional checking
	vpnByDevice := make(map[uint][]models.VPNStatus)
	for _, vpn := range vpnStatuses {
		vpnByDevice[vpn.DeviceID] = append(vpnByDevice[vpn.DeviceID], vpn)
	}

	// pairKey returns a normalized key for a device pair (lower ID first)
	pairKey := func(a, b uint) string {
		if a > b {
			a, b = b, a
		}
		return fmt.Sprintf("%d:%d", a, b)
	}

	type pairInfo struct {
		sourceID    uint
		destID      uint
		tunnelNames map[string]bool
		anyUp       bool
		matchMethod string
		connType    string
		sides       int // how many sides have a matching tunnel (1=unidirectional, 2=bidirectional)
	}

	pairs := make(map[string]*pairInfo)

	for _, vpn := range vpnStatuses {
		remoteDevice, ok := ipToDevice[vpn.RemoteIP]
		if !ok {
			continue
		}
		if remoteDevice.ID == vpn.DeviceID {
			continue // skip self-referencing
		}

		key := pairKey(vpn.DeviceID, remoteDevice.ID)
		pi, exists := pairs[key]
		if !exists {
			srcID, dstID := vpn.DeviceID, remoteDevice.ID
			if srcID > dstID {
				srcID, dstID = dstID, srcID
			}
			// Determine match method based on how the IP was found
			method := "ip_match"
			if ipSource[vpn.RemoteIP] == "interface" {
				method = "interface_ip"
			}
			// Determine connection type from tunnel type
			ct := "ipsec"
			if vpn.TunnelType == "sslvpn" {
				ct = "ssl"
			}
			pi = &pairInfo{
				sourceID:    srcID,
				destID:      dstID,
				tunnelNames: make(map[string]bool),
				matchMethod: method,
				connType:    ct,
				sides:       0,
			}
			pairs[key] = pi
		}
		if vpn.TunnelName != "" {
			pi.tunnelNames[vpn.TunnelName] = true
		}
		if vpn.Status == "up" {
			pi.anyUp = true
		}
		// Upgrade connection type if we see SSL
		if vpn.TunnelType == "sslvpn" {
			pi.connType = "ssl"
		}
		// Upgrade match method if this side is via interface IP
		if ipSource[vpn.RemoteIP] == "interface" && pi.matchMethod == "ip_match" {
			pi.matchMethod = "interface_ip"
		}
	}

	// Phase 2: Indirect matching for NAT'd tunnels.
	// When a VPN tunnel's remote_ip doesn't resolve to any known device IP (common with
	// NAT'd IPSec), try matching the tunnel name against device names.
	// e.g., tunnel "NUDAY_LAN" on DC2-FW1 contains "nuday" → matches device "NUDAY-FW".
	deviceNameParts := make(map[uint][]string, len(devices))
	for i := range devices {
		name := strings.ToLower(devices[i].Name)
		parts := strings.FieldsFunc(name, func(r rune) bool {
			return r == '-' || r == '_' || r == '.' || r == ' '
		})
		for _, p := range parts {
			if len(p) >= 4 { // only meaningful parts (skip fw, gw, dc, etc.)
				deviceNameParts[devices[i].ID] = append(deviceNameParts[devices[i].ID], p)
			}
		}
	}

	for _, vpn := range vpnStatuses {
		if _, resolved := ipToDevice[vpn.RemoteIP]; resolved {
			continue // already matched in first pass
		}
		if vpn.DeviceID == 0 || vpn.TunnelName == "" {
			continue
		}
		tunnelNorm := strings.ToLower(strings.NewReplacer(" ", "", ".", "", "-", "", "_", "").Replace(vpn.TunnelName))

		for _, dev := range devices {
			if dev.ID == vpn.DeviceID {
				continue
			}
			matched := false
			for _, namePart := range deviceNameParts[dev.ID] {
				if strings.Contains(tunnelNorm, namePart) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			key := pairKey(vpn.DeviceID, dev.ID)
			pi, exists := pairs[key]
			if !exists {
				srcID, dstID := vpn.DeviceID, dev.ID
				if srcID > dstID {
					srcID, dstID = dstID, srcID
				}
				ct := "ipsec"
				if vpn.TunnelType == "sslvpn" {
					ct = "ssl"
				}
				pi = &pairInfo{
					sourceID:    srcID,
					destID:      dstID,
					tunnelNames: make(map[string]bool),
					matchMethod: "tunnel_indirect",
					connType:    ct,
				}
				pairs[key] = pi
			}
			pi.tunnelNames[vpn.TunnelName] = true
			if vpn.Status == "up" {
				pi.anyUp = true
			}
			break // found match for this tunnel, move on
		}
	}

	// Bidirectional check: for each pair, see if both sides have tunnels pointing at each other
	for _, pi := range pairs {
		srcTunnels := vpnByDevice[pi.sourceID]
		dstTunnels := vpnByDevice[pi.destID]
		srcPointsToDst := false
		dstPointsToSrc := false

		for _, t := range srcTunnels {
			if rd, ok := ipToDevice[t.RemoteIP]; ok && rd.ID == pi.destID {
				srcPointsToDst = true
				break
			}
		}
		for _, t := range dstTunnels {
			if rd, ok := ipToDevice[t.RemoteIP]; ok && rd.ID == pi.sourceID {
				dstPointsToSrc = true
				break
			}
		}

		if srcPointsToDst && dstPointsToSrc {
			pi.matchMethod = "bidirectional"
		}
	}

	for _, pi := range pairs {
		status := "down"
		if pi.anyUp {
			status = "up"
		}

		// Collect and sort tunnel names
		names := make([]string, 0, len(pi.tunnelNames))
		for n := range pi.tunnelNames {
			names = append(names, n)
		}
		sort.Strings(names)
		tunnelNames := strings.Join(names, ", ")

		// Build a descriptive connection name
		srcName, dstName := "?", "?"
		if d, ok := deviceByID[pi.sourceID]; ok {
			srcName = d.Name
		}
		if d, ok := deviceByID[pi.destID]; ok {
			dstName = d.Name
		}
		connName := fmt.Sprintf("%s ↔ %s", srcName, dstName)

		if err := p.db.UpsertAutoConnection(pi.sourceID, pi.destID, status, tunnelNames, connName, pi.connType, pi.matchMethod); err != nil {
			log.Printf("VPN auto-detect: failed to upsert connection %s - %v", connName, err)
		}
	}

	if len(pairs) > 0 {
		log.Printf("VPN auto-detect: processed %d connection(s) across %d devices", len(pairs), len(devices))
	}
}

// detectOverlayConnections finds matching overlay/local interfaces across devices and
// creates auto-detected connections. Only handles L2VLAN, L3IPVLAN, and VXLAN types.
// Tunnel/IPSec/GRE connections are handled exclusively by detectVPNConnections which
// uses actual VPN tunnel data (IPs, status) rather than name matching.
func (p *Poller) detectOverlayConnections(devices []models.Device) {
	if p.db == nil || len(devices) == 0 {
		return
	}

	ifaces, err := p.db.GetAllLatestInterfaces()
	if err != nil {
		log.Printf("Overlay auto-detect: failed to get interfaces - %v", err)
		return
	}

	deviceByID := make(map[uint]*models.Device, len(devices))
	for i := range devices {
		deviceByID[devices[i].ID] = &devices[i]
	}

	// Build IP → device ID map for direct-link verification
	ipToDeviceID := make(map[string]uint, len(devices)*4)
	for i := range devices {
		if devices[i].IPAddress != "" {
			ipToDeviceID[devices[i].IPAddress] = devices[i].ID
		}
	}
	ifAddrs, _ := p.db.GetLatestInterfaceAddresses()
	for _, addr := range ifAddrs {
		if _, exists := ipToDeviceID[addr.IPAddress]; !exists {
			ipToDeviceID[addr.IPAddress] = addr.DeviceID
		}
	}

	// Load VPN tunnel data to verify direct links
	vpnStatuses, _ := p.db.GetAllLatestVPNStatuses()
	// Build set of device pairs with verified direct VPN links (remote IP points to other device)
	vpnByDevice := make(map[uint][]models.VPNStatus)
	for _, vpn := range vpnStatuses {
		vpnByDevice[vpn.DeviceID] = append(vpnByDevice[vpn.DeviceID], vpn)
	}

	hasDirectLink := func(devA, devB uint) bool {
		// Check if device A has a VPN tunnel pointing to device B's IP
		for _, t := range vpnByDevice[devA] {
			if did, ok := ipToDeviceID[t.RemoteIP]; ok && did == devB {
				return true
			}
		}
		// Check if device B has a VPN tunnel pointing to device A's IP
		for _, t := range vpnByDevice[devB] {
			if did, ok := ipToDeviceID[t.RemoteIP]; ok && did == devA {
				return true
			}
		}
		// Fallback: check if detectVPNConnections already created a tunnel/ipsec connection
		// (handles NAT'd tunnels matched via tunnel_indirect method)
		if p.db != nil {
			for _, ct := range []string{"ipsec", "gre", "tunnel", "ssl"} {
				conn, _ := p.db.FindConnectionByDevicePairAndType(devA, devB, ct)
				if conn != nil {
					return true
				}
			}
		}
		return false
	}

	// Common names to skip (too generic — present on every device).
	// Values are normalized (lowercase, no separators) to match normalizeIfName output.
	skipNames := map[string]bool{
		"loopback0": true, "lo": true, "lo0": true,
		"mgmt": true, "mgmt0": true, "management": true,
		"null0": true, "": true,
	}
	// FortiGate system interfaces follow *.root / *.vdom pattern — skip all of them
	isSystemIface := func(normalized string) bool {
		return strings.HasSuffix(normalized, "root") || strings.HasSuffix(normalized, "vdom")
	}

	// Only overlay and local interface types — tunnel carriers (ipsec, gre, etc.)
	// are handled exclusively by detectVPNConnections using actual VPN data.
	overlayTypes := map[string]bool{
		"l2vlan": true, "l3ipvlan": true, "vxlan": true,
	}

	// Validation categories:
	// - l2vlan (local segment): requires same site
	// - l3ipvlan/vxlan (overlays): requires a direct VPN tunnel between endpoints
	localTypes := map[string]bool{"l2vlan": true}
	sameSite := func(devA, devB uint) bool {
		da, oa := deviceByID[devA]
		db, ob := deviceByID[devB]
		if !oa || !ob || da.SiteID == nil || db.SiteID == nil {
			return false
		}
		return *da.SiteID == *db.SiteID
	}
	// normalizeIfName strips formatting differences so vlan500, vlan 500,
	// vlan.500, vlan-500, vlan_500, VLAN500 all match as "vlan500".
	normalizeIfName := func(name string) string {
		n := strings.ToLower(strings.TrimSpace(name))
		return strings.NewReplacer(" ", "", ".", "", "-", "", "_", "").Replace(n)
	}

	// Type priority for per-pair type determination
	typePriority := map[string]int{"l2vlan": 0, "vxlan": 1, "l3ipvlan": 2}
	pairConnType := func(typeA, typeB string) string {
		a, b := strings.ToLower(typeA), strings.ToLower(typeB)
		priA, _ := typePriority[a]
		priB, _ := typePriority[b]
		if priA >= priB {
			return a
		}
		return b
	}

	type ifEntry struct {
		deviceID uint
		name     string
		typeName string
		status   string
	}
	nameGroups := make(map[string][]ifEntry)

	for _, iface := range ifaces {
		// Accept overlay/local interface types, or vxlan-prefixed names
		if !overlayTypes[strings.ToLower(iface.TypeName)] && !strings.HasPrefix(strings.ToLower(iface.Name), "vxlan") {
			continue
		}
		normalized := normalizeIfName(iface.Name)
		if skipNames[normalized] || isSystemIface(normalized) {
			continue
		}
		nameGroups[normalized] = append(nameGroups[normalized], ifEntry{
			deviceID: iface.DeviceID,
			name:     iface.Name,
			typeName: iface.TypeName,
			status:   iface.Status,
		})
	}

	pairKey := func(a, b uint) string {
		if a > b {
			a, b = b, a
		}
		return fmt.Sprintf("%d:%d", a, b)
	}
	// Dedup by pair + connection type — allows ipsec AND l2vlan between same pair
	processed := make(map[string]bool)
	created := 0

	for _, entries := range nameGroups {
		// Deduplicate by device
		seen := make(map[uint]*ifEntry)
		for i := range entries {
			if _, ok := seen[entries[i].deviceID]; !ok {
				seen[entries[i].deviceID] = &entries[i]
			}
		}
		if len(seen) < 2 {
			continue
		}

		// Create pairwise connections for hub-spoke
		deviceList := make([]*ifEntry, 0, len(seen))
		for _, e := range seen {
			deviceList = append(deviceList, e)
		}

		for i := 0; i < len(deviceList); i++ {
			for j := i + 1; j < len(deviceList); j++ {
				a, b := deviceList[i], deviceList[j]

				// Determine type from this specific pair's interface types
				connType := pairConnType(a.typeName, b.typeName)

				key := pairKey(a.deviceID, b.deviceID) + ":" + connType
				if processed[key] {
					continue
				}

				// Validation by category:
				// - l2vlan (local segment): requires same site
				// - l3ipvlan/vxlan (overlays): requires a direct VPN tunnel between endpoints
				if localTypes[connType] {
					if !sameSite(a.deviceID, b.deviceID) {
						continue
					}
				} else {
					if !hasDirectLink(a.deviceID, b.deviceID) {
						continue
					}
				}

				processed[key] = true

				srcID, dstID := a.deviceID, b.deviceID
				if srcID > dstID {
					srcID, dstID = dstID, srcID
				}

				status := "down"
				if a.status == "up" && b.status == "up" {
					status = "up"
				}

				srcName, dstName := "?", "?"
				if d, ok := deviceByID[srcID]; ok {
					srcName = d.Name
				}
				if d, ok := deviceByID[dstID]; ok {
					dstName = d.Name
				}
				connName := fmt.Sprintf("%s ↔ %s", srcName, dstName)

				matchMethod := "overlay_name"

				if err := p.db.UpsertAutoConnection(srcID, dstID, status, a.name, connName, connType, matchMethod); err != nil {
					log.Printf("Overlay auto-detect: failed to upsert connection %s - %v", connName, err)
				} else {
					created++
				}
			}
		}
	}

	if created > 0 {
		log.Printf("Overlay auto-detect: upserted %d connection(s)", created)
	}
}

func (p *Poller) updateDeviceStatus(device *models.Device, status string) {
	now := time.Now()
	device.Status = status
	device.LastPolled = now
	if p.db != nil {
		if err := p.db.UpdateDeviceStatus(device.ID, status, now); err != nil {
			log.Printf("Device %s: failed to update status - %v", device.Name, err)
		}
	}
	if status == "offline" && p.alertManager != nil {
		p.alertManager.CheckDeviceOffline(device)
	}
}

func (p *Poller) Stop() error {
	select {
	case <-p.stopChan:
		return nil
	default:
		close(p.stopChan)
	}
	return nil
}

func main() {
	cfg := config.Load()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting SNMP Poller...")

	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Database connected")
	defer db.Close()

	notif := notifier.NewNotifier(cfg)
	alertManager := alerts.NewAlertManager(cfg, notif, db)

	poller := NewPoller(cfg, db, alertManager)

	go func() {
		if err := poller.Start(); err != nil {
			log.Printf("Poller error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down poller...")
	poller.Stop()
	log.Println("Poller exited")
}
