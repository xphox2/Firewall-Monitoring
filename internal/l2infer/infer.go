// Package l2infer infers port-to-port links between monitored devices from
// layer-2 evidence: LLDP/CDP neighbor tables, MAC forwarding tables (FDB) and
// ARP caches, joined against the devices' own interface MACs. It is pure (no
// DB imports) and shared by the poller (which draws the links) and the
// connection-detail API (which explains them) — the "why" shown to users is
// the same logic that drew the edge.
//
// Universe: monitored same-site device pairs only. Unmanaged switches in the
// middle are invisible; an FDB-inferred link "A:port5 ↔ B:port3" may run
// through one, which is still the correct port attribution for the map.
//
// Evidence tiers (best wins as the link's match method):
//   - lldp_neighbor: the neighbor protocol names both endpoints' ports.
//   - fdb_match: A learned B's interface MAC on a port (and, when
//     bidirectional, vice versa).
//   - arp_match: A's ARP cache binds B's IP+MAC to a local interface.
package l2infer

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Evidence tiers / match methods (ordered weakest → strongest).
const (
	TierARP  = "arp"
	TierFDB  = "fdb"
	TierLLDP = "lldp"

	MethodARP  = "arp_match"
	MethodFDB  = "fdb_match"
	MethodLLDP = "lldp_neighbor"
)

// DeviceMeta is the monitored-device identity the inference matches against.
type DeviceMeta struct {
	ID     uint
	Name   string
	SiteID *uint
	IPs    []string // management IP + interface addresses
}

// Iface is one interface row (from the latest interface stats snapshot).
type Iface struct {
	DeviceID uint
	IfIndex  int
	Name     string
	MAC      string // any case; normalized internally
	Status   string // oper status "up"/"down"/…
	TypeName string // "ethernet"|"lag"|…
}

// FDBRow is one MAC-table entry reported by a device.
type FDBRow struct {
	DeviceID uint
	IfIndex  int
	MAC      string
	VLANID   int
	Ts       time.Time
}

// ARPRow is one ARP-cache entry reported by a device. SSH-sourced rows carry
// IfName instead of IfIndex.
type ARPRow struct {
	DeviceID uint
	IfIndex  int
	IfName   string
	IP       string
	MAC      string
	Ts       time.Time
}

// NeighborRow is one LLDP/CDP neighbor-table entry reported by a device.
type NeighborRow struct {
	DeviceID     uint
	LocalIfIndex int
	LocalIfName  string
	ChassisID    string // MAC form when the neighbor advertised subtype macAddress
	PortID       string
	PortDesc     string
	SysName      string
	Ts           time.Time
}

// EvidenceRef is one piece of evidence that contributed to a link, exposed on
// the connection-detail API so users can see WHY a link is drawn.
type EvidenceRef struct {
	Tier          string    `json:"tier"` // lldp | fdb | arp
	DeviceID      uint      `json:"device_id"`
	LocalIfIndex  int       `json:"local_if_index"`
	LocalIfName   string    `json:"local_if_name"`
	RemoteMAC     string    `json:"remote_mac,omitempty"`
	RemoteIP      string    `json:"remote_ip,omitempty"`
	RemotePort    string    `json:"remote_port,omitempty"` // lldp only
	RemoteSysName string    `json:"remote_sysname,omitempty"`
	VLANID        int       `json:"vlan_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Note          string    `json:"note,omitempty"` // e.g. port-conflict discrepancy
}

// Link is one inferred port-to-port link. A < B (normalized); an ifIndex of 0
// with an empty name means that end's port is unknown (one-sided evidence).
type Link struct {
	A, B               uint
	AIfIndex, BIfIndex int
	AIfName, BIfName   string
	VLANIDs            []int  // sorted, deduped; from FDB evidence
	Method             string // best tier present
	Sided              string // both | a_only | b_only
	Status             string // up | down (oper status of known endpoint ifaces)
	LatestEvidence     time.Time
	Evidence           []EvidenceRef
}

// evidence rows kept per link — enough to explain, bounded for the API.
const maxEvidencePerLink = 32

// Evidence freshness windows, shared by the poller (link status staircase:
// fresh → up/down, within grace → "stale", past grace → swept) and the
// connection-detail evidence view (Fresh flag).
const (
	FreshWindow = 30 * time.Minute
	GraceWindow = 3 * time.Hour
)

// NormalizeMAC canonicalizes a MAC to lowercase colon form; "" if unparseable.
func NormalizeMAC(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}

// IsVirtualMAC reports first-hop-redundancy virtual MACs: VRRP/CARP
// (00:00:5e:00:01:xx), VRRPv3 IPv6 (00:00:5e:00:02:xx) and HSRP
// (00:00:0c:07:ac:xx). These float between HA members and must never anchor
// MAC ownership. FortiGate FGCP virtual MACs (00:09:0f:09:xx:xx) are
// deliberately NOT here: on an FGCP cluster ifPhysAddress itself reports the
// virtual MAC, so excluding it would strip a monitored HA FortiGate of all
// MAC ownership — the multi-owner drop below handles dual-monitored clusters.
func IsVirtualMAC(mac string) bool {
	m := strings.ToLower(mac)
	return strings.HasPrefix(m, "00:00:5e:00:01:") ||
		strings.HasPrefix(m, "00:00:5e:00:02:") ||
		strings.HasPrefix(m, "00:00:0c:07:ac:")
}

type macOwner struct {
	deviceID uint
	ifIndex  int
	ifName   string
	// ambiguous: the same MAC appears on several interfaces of the SAME
	// device (FortiGate hardware-switch base MAC) — device match is valid,
	// interface attribution is not.
	ambiguousIface bool
}

type portRef struct {
	ifIndex int
	name    string
}

func (p portRef) known() bool { return p.ifIndex > 0 || p.name != "" }

// samePort: two refs denote the same port when a shared identity matches.
func samePort(a, b portRef) bool {
	if a.ifIndex > 0 && b.ifIndex > 0 {
		return a.ifIndex == b.ifIndex
	}
	if a.name != "" && b.name != "" {
		return strings.EqualFold(a.name, b.name)
	}
	return false
}

// candidate is one directional piece of link evidence: reporter's port toward
// target (and, for LLDP, the target's port too).
type candidate struct {
	reporter, target uint
	port             portRef // reporter side
	remotePort       portRef // target side (lldp only)
	tier             string
	vlans            []int
	ev               []EvidenceRef
	ts               time.Time
}

type indexes struct {
	devices  map[uint]*DeviceMeta
	byIndex  map[uint]map[int]*Iface
	byName   map[uint]map[string]*Iface
	owners   map[string]macOwner
	byDevMAC map[uint]map[string]bool // MAC ownership per device (ambiguity-proof)
	nameToID map[string]uint          // lowercased device name / short hostname → id (ambiguous removed)
	ipToID   map[uint]map[string]bool // deviceID → its IPs
	ipOwner  map[string]uint          // IP → deviceID (ambiguous removed)
}

func buildIndexes(devs []DeviceMeta, ifaces []Iface) *indexes {
	ix := &indexes{
		devices:  map[uint]*DeviceMeta{},
		byIndex:  map[uint]map[int]*Iface{},
		byName:   map[uint]map[string]*Iface{},
		owners:   map[string]macOwner{},
		byDevMAC: map[uint]map[string]bool{},
		nameToID: map[string]uint{},
		ipToID:   map[uint]map[string]bool{},
		ipOwner:  map[string]uint{},
	}
	nameAmbig := map[string]bool{}
	ipAmbig := map[string]bool{}
	for i := range devs {
		d := &devs[i]
		ix.devices[d.ID] = d
		for _, raw := range []string{d.Name, shortHostname(d.Name)} {
			n := strings.ToLower(strings.TrimSpace(raw))
			if n == "" {
				continue
			}
			if prev, ok := ix.nameToID[n]; ok && prev != d.ID {
				nameAmbig[n] = true
				continue
			}
			ix.nameToID[n] = d.ID
		}
		ix.ipToID[d.ID] = map[string]bool{}
		for _, ip := range d.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			ix.ipToID[d.ID][ip] = true
			if prev, ok := ix.ipOwner[ip]; ok && prev != d.ID {
				ipAmbig[ip] = true
				continue
			}
			ix.ipOwner[ip] = d.ID
		}
	}
	for n := range nameAmbig {
		delete(ix.nameToID, n)
	}
	for ip := range ipAmbig {
		delete(ix.ipOwner, ip)
	}

	macMultiOwner := map[string]bool{}
	for i := range ifaces {
		f := &ifaces[i]
		if ix.byIndex[f.DeviceID] == nil {
			ix.byIndex[f.DeviceID] = map[int]*Iface{}
			ix.byName[f.DeviceID] = map[string]*Iface{}
			ix.byDevMAC[f.DeviceID] = map[string]bool{}
		}
		if f.IfIndex > 0 {
			ix.byIndex[f.DeviceID][f.IfIndex] = f
		}
		if f.Name != "" {
			ix.byName[f.DeviceID][strings.ToLower(f.Name)] = f
		}
		mac := NormalizeMAC(f.MAC)
		if mac == "" || IsVirtualMAC(mac) {
			continue
		}
		ix.byDevMAC[f.DeviceID][mac] = true
		if owner, seen := ix.owners[mac]; seen {
			if owner.deviceID != f.DeviceID {
				macMultiOwner[mac] = true // claimed by >1 device — ambiguous, drop
			} else if owner.ifIndex != f.IfIndex {
				owner.ambiguousIface = true
				ix.owners[mac] = owner
			}
			continue
		}
		ix.owners[mac] = macOwner{deviceID: f.DeviceID, ifIndex: f.IfIndex, ifName: f.Name}
	}
	for mac := range macMultiOwner {
		delete(ix.owners, mac)
	}
	return ix
}

func shortHostname(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return ""
}

func (ix *indexes) sameSite(a, b uint) bool {
	da, oa := ix.devices[a]
	db, ob := ix.devices[b]
	if !oa || !ob || da.SiteID == nil || db.SiteID == nil {
		return false
	}
	return *da.SiteID == *db.SiteID
}

// resolvePort maps raw evidence (ifIndex and/or name) onto the device's real
// interface identity; unresolvable values pass through so the link still
// carries whatever the evidence said.
func (ix *indexes) resolvePort(dev uint, ifIndex int, name string) portRef {
	if name != "" {
		if f, ok := ix.byName[dev][strings.ToLower(name)]; ok {
			return portRef{f.IfIndex, f.Name}
		}
	}
	if ifIndex > 0 {
		if f, ok := ix.byIndex[dev][ifIndex]; ok {
			return portRef{f.IfIndex, f.Name}
		}
	}
	return portRef{ifIndex, name}
}

// resolveNeighborDevice matches an LLDP/CDP neighbor row to a monitored
// device: chassis MAC ownership first, then case-insensitive sysname (full
// then short hostname).
func (ix *indexes) resolveNeighborDevice(n NeighborRow) (uint, bool) {
	if mac := NormalizeMAC(n.ChassisID); mac != "" {
		if owner, ok := ix.owners[mac]; ok {
			return owner.deviceID, true
		}
	}
	for _, raw := range []string{n.SysName, shortHostname(n.SysName)} {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if id, ok := ix.nameToID[s]; ok {
			return id, true
		}
	}
	return 0, false
}

// resolveRemotePort maps an LLDP remote port identifier (ifName, ifDescr or
// MAC, depending on the advertised subtype) onto the target device's port.
func (ix *indexes) resolveRemotePort(target uint, n NeighborRow) portRef {
	for _, cand := range []string{n.PortID, n.PortDesc} {
		if cand == "" {
			continue
		}
		if f, ok := ix.byName[target][strings.ToLower(cand)]; ok {
			return portRef{f.IfIndex, f.Name}
		}
		if mac := NormalizeMAC(cand); mac != "" {
			if owner, ok := ix.owners[mac]; ok && owner.deviceID == target && !owner.ambiguousIface {
				return portRef{owner.ifIndex, owner.ifName}
			}
		}
	}
	if n.PortID != "" {
		return portRef{0, n.PortID}
	}
	return portRef{0, n.PortDesc}
}

func pairKey(a, b uint) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%d:%d", a, b)
}

// dirPortMap holds, per ORDERED (reporter, target) pair, the reporter's
// best-tier local port toward the target — the input to transitive
// suppression. First write wins, so filling in tier order (lldp local, fdb,
// arp, then lldp REMOTE ports as the lowest-priority fallback for the far
// side) keeps the strongest attribution.
type dirPortMap map[uint]map[uint]portRef

func (m dirPortMap) add(reporter, target uint, p portRef) {
	if !p.known() {
		return
	}
	if m[reporter] == nil {
		m[reporter] = map[uint]portRef{}
	}
	if _, exists := m[reporter][target]; !exists {
		m[reporter][target] = p
	}
}

// InferLinks derives port-to-port links between monitored same-site devices.
// Deterministic: identical inputs yield identically ordered output.
func InferLinks(devs []DeviceMeta, ifaces []Iface, fdb []FDBRow, arp []ARPRow, nbrs []NeighborRow) []Link {
	ix := buildIndexes(devs, ifaces)

	lldpC := ix.lldpCandidates(nbrs)
	fdbC := ix.fdbCandidates(fdb)
	arpC := ix.arpCandidates(arp)

	// Directional port attributions for transitive suppression.
	dir := dirPortMap{}
	for _, cands := range [][]candidate{lldpC, fdbC, arpC} {
		for i := range cands {
			dir.add(cands[i].reporter, cands[i].target, cands[i].port)
		}
	}
	for i := range lldpC {
		dir.add(lldpC[i].target, lldpC[i].reporter, lldpC[i].remotePort)
	}

	perPair := map[string][]*Link{}
	addCandidates := func(cands []candidate) {
		for i := range cands {
			c := &cands[i]
			key := pairKey(c.reporter, c.target)
			perPair[key] = mergeCandidate(perPair[key], c)
		}
	}

	addCandidates(lldpC)
	addCandidates(fdbC)
	addCandidates(arpC)

	keys := make([]string, 0, len(perPair))
	for k := range perPair {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []Link
	for _, k := range keys {
		links := perPair[k]
		sort.SliceStable(links, func(i, j int) bool {
			if links[i].AIfIndex != links[j].AIfIndex {
				return links[i].AIfIndex < links[j].AIfIndex
			}
			if links[i].BIfIndex != links[j].BIfIndex {
				return links[i].BIfIndex < links[j].BIfIndex
			}
			if links[i].AIfName != links[j].AIfName {
				return links[i].AIfName < links[j].AIfName
			}
			return links[i].BIfName < links[j].BIfName
		})
		for _, l := range links {
			// Transitive suppression: FDB/ARP "adjacency" through a
			// MONITORED middle device is not a cable — drop it. LLDP links
			// are protocol-confirmed direct adjacency and never suppressed.
			if l.Method != MethodLLDP && ix.isTransitive(l.A, l.B, dir) {
				continue
			}
			ix.finalize(l)
			out = append(out, *l)
		}
	}
	return out
}

// isTransitive reports whether the a—c attribution is explained by a
// monitored device b sitting BETWEEN them: one endpoint reaches both b and
// the far end through the SAME local port (they're down the same wire from
// its viewpoint), while b reaches the two endpoints through DIFFERENT ports
// (b genuinely forwards between them). This is the daisy-chain case —
// OPNsense → FW2 → FW1 on one broadcast domain puts OPNsense's MAC in FW1's
// FDB, but the OPNsense↔FW1 link is FW2's job to draw, twice. Links through
// UNMANAGED switches are unaffected (no monitored b exists), and partial
// data fails safe (missing port attributions → no suppression).
func (ix *indexes) isTransitive(a, c uint, dir dirPortMap) bool {
	behindVia := func(x, far uint) bool {
		px := dir[x]
		if px == nil {
			return false
		}
		pxFar, ok := px[far]
		if !ok {
			return false
		}
		for b, pxb := range px {
			if b == far {
				continue
			}
			if _, monitored := ix.devices[b]; !monitored {
				continue
			}
			if !samePort(pxFar, pxb) {
				continue // x distinguishes b from far — b isn't on that wire
			}
			pb := dir[b]
			if pb == nil {
				continue
			}
			pbx, okX := pb[x]
			pbFar, okFar := pb[far]
			if okX && okFar && !samePort(pbx, pbFar) {
				return true // b forwards between x and far on distinct ports
			}
		}
		return false
	}
	return behindVia(a, c) || behindVia(c, a)
}

// lldpCandidates converts neighbor rows into directional candidates.
func (ix *indexes) lldpCandidates(nbrs []NeighborRow) []candidate {
	var out []candidate
	for _, n := range nbrs {
		target, ok := ix.resolveNeighborDevice(n)
		if !ok || target == n.DeviceID || !ix.sameSite(n.DeviceID, target) {
			continue
		}
		local := ix.resolvePort(n.DeviceID, n.LocalIfIndex, n.LocalIfName)
		remote := ix.resolveRemotePort(target, n)
		out = append(out, candidate{
			reporter:   n.DeviceID,
			target:     target,
			port:       local,
			remotePort: remote,
			tier:       TierLLDP,
			ts:         n.Ts,
			ev: []EvidenceRef{{
				Tier:          TierLLDP,
				DeviceID:      n.DeviceID,
				LocalIfIndex:  local.ifIndex,
				LocalIfName:   local.name,
				RemoteMAC:     NormalizeMAC(n.ChassisID),
				RemotePort:    n.PortID,
				RemoteSysName: n.SysName,
				Timestamp:     n.Ts,
			}},
		})
	}
	return out
}

// fdbCandidates: per (reporter, target), attribute the reporter's port that
// most recently saw the target's MACs (newest snapshot wins, distinct-MAC
// count then lowest ifIndex as deterministic tiebreaks) — handles MAC moves.
func (ix *indexes) fdbCandidates(fdb []FDBRow) []candidate {
	type portStat struct {
		port   portRef
		ts     time.Time
		macs   map[string]bool
		vlans  map[int]bool
		refs   []EvidenceRef
		anyRow bool
	}
	acc := map[string]map[int]*portStat{} // "reporter:target" → ifIndex → stats
	for _, row := range fdb {
		mac := NormalizeMAC(row.MAC)
		if mac == "" {
			continue
		}
		owner, ok := ix.owners[mac]
		if !ok || owner.deviceID == row.DeviceID || !ix.sameSite(row.DeviceID, owner.deviceID) {
			continue
		}
		port := ix.resolvePort(row.DeviceID, row.IfIndex, "")
		key := fmt.Sprintf("%d:%d", row.DeviceID, owner.deviceID)
		if acc[key] == nil {
			acc[key] = map[int]*portStat{}
		}
		st := acc[key][port.ifIndex]
		if st == nil {
			st = &portStat{port: port, macs: map[string]bool{}, vlans: map[int]bool{}}
			acc[key][port.ifIndex] = st
		}
		st.anyRow = true
		st.macs[mac] = true
		if row.VLANID > 0 {
			st.vlans[row.VLANID] = true
		}
		if row.Ts.After(st.ts) {
			st.ts = row.Ts
		}
		if len(st.refs) < maxEvidencePerLink {
			st.refs = append(st.refs, EvidenceRef{
				Tier:         TierFDB,
				DeviceID:     row.DeviceID,
				LocalIfIndex: port.ifIndex,
				LocalIfName:  port.name,
				RemoteMAC:    mac,
				VLANID:       row.VLANID,
				Timestamp:    row.Ts,
			})
		}
	}

	keys := make([]string, 0, len(acc))
	for k := range acc {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []candidate
	for _, key := range keys {
		// Newest snapshot wins; ties break on distinct-MAC count, then
		// ifIndex, then port NAME — the name tiebreak matters for rows whose
		// port never resolved to an ifIndex (both 0), where iterating the
		// map would otherwise pick a nondeterministic winner and flap the
		// attribution every cycle.
		var best *portStat
		for _, st := range acc[key] {
			if best == nil ||
				st.ts.After(best.ts) ||
				(st.ts.Equal(best.ts) && len(st.macs) > len(best.macs)) ||
				(st.ts.Equal(best.ts) && len(st.macs) == len(best.macs) && st.port.ifIndex < best.port.ifIndex) ||
				(st.ts.Equal(best.ts) && len(st.macs) == len(best.macs) && st.port.ifIndex == best.port.ifIndex &&
					strings.Compare(st.port.name, best.port.name) < 0) {
				best = st
			}
		}
		if best == nil || !best.anyRow {
			continue
		}
		var reporter, target uint
		fmt.Sscanf(key, "%d:%d", &reporter, &target)
		vlans := make([]int, 0, len(best.vlans))
		for v := range best.vlans {
			vlans = append(vlans, v)
		}
		sort.Ints(vlans)
		out = append(out, candidate{
			reporter: reporter,
			target:   target,
			port:     best.port,
			tier:     TierFDB,
			vlans:    vlans,
			ev:       best.refs,
			ts:       best.ts,
		})
	}
	return out
}

// arpCandidates: MAC ownership is the primary match (NAT/proxy-ARP safe); IP
// membership is the fallback only when the MAC is not owned by a DIFFERENT
// device (covers targets whose interface MACs aren't reported).
func (ix *indexes) arpCandidates(arp []ARPRow) []candidate {
	type portStat struct {
		port portRef
		ts   time.Time
		rows int
		refs []EvidenceRef
	}
	acc := map[string]map[string]*portStat{} // "reporter:target" → portKey → stats
	for _, row := range arp {
		mac := NormalizeMAC(row.MAC)
		var target uint
		if mac != "" && !IsVirtualMAC(mac) {
			if owner, ok := ix.owners[mac]; ok {
				target = owner.deviceID
			}
		}
		if target == 0 {
			// IP fallback: only when the MAC isn't claimed by another device.
			if id, ok := ix.ipOwner[row.IP]; ok {
				if mac == "" || !ix.macOwnedByOther(mac, id) {
					target = id
				}
			}
		}
		if target == 0 || target == row.DeviceID || !ix.sameSite(row.DeviceID, target) {
			continue
		}
		port := ix.resolvePort(row.DeviceID, row.IfIndex, row.IfName)
		key := fmt.Sprintf("%d:%d", row.DeviceID, target)
		portKey := fmt.Sprintf("%d:%s", port.ifIndex, strings.ToLower(port.name))
		if acc[key] == nil {
			acc[key] = map[string]*portStat{}
		}
		st := acc[key][portKey]
		if st == nil {
			st = &portStat{port: port}
			acc[key][portKey] = st
		}
		st.rows++
		if row.Ts.After(st.ts) {
			st.ts = row.Ts
		}
		if len(st.refs) < maxEvidencePerLink {
			st.refs = append(st.refs, EvidenceRef{
				Tier:         TierARP,
				DeviceID:     row.DeviceID,
				LocalIfIndex: port.ifIndex,
				LocalIfName:  port.name,
				RemoteMAC:    mac,
				RemoteIP:     row.IP,
				Timestamp:    row.Ts,
			})
		}
	}

	keys := make([]string, 0, len(acc))
	for k := range acc {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []candidate
	for _, key := range keys {
		// Same deterministic comparator as the FDB tier. The port-NAME
		// tiebreak is load-bearing here: SSH-sourced ARP rows carry names
		// with ifIndex 0, and a collector snapshot stamps every row with one
		// timestamp — without the name ordering, two name-only ports tie all
		// the way down and the winner is map-iteration luck, flapping the
		// stored attribution every cycle.
		var best *portStat
		for _, st := range acc[key] {
			if best == nil ||
				st.ts.After(best.ts) ||
				(st.ts.Equal(best.ts) && st.rows > best.rows) ||
				(st.ts.Equal(best.ts) && st.rows == best.rows && st.port.ifIndex < best.port.ifIndex) ||
				(st.ts.Equal(best.ts) && st.rows == best.rows && st.port.ifIndex == best.port.ifIndex &&
					strings.Compare(st.port.name, best.port.name) < 0) {
				best = st
			}
		}
		if best == nil {
			continue
		}
		var reporter, target uint
		fmt.Sscanf(key, "%d:%d", &reporter, &target)
		out = append(out, candidate{
			reporter: reporter,
			target:   target,
			port:     best.port,
			tier:     TierARP,
			ev:       best.refs,
			ts:       best.ts,
		})
	}
	return out
}

func (ix *indexes) macOwnedByOther(mac string, deviceID uint) bool {
	owner, ok := ix.owners[mac]
	return ok && owner.deviceID != deviceID
}

// mergeCandidate folds one directional candidate into the pair's link set.
// LLDP forms/merges base links (mirrored rows collapse to one two-sided
// link); FDB merges onto a matching or unknown reporter-side port, wins the
// pair only when no LLDP link exists, and on a port CONFLICT with LLDP is
// attached as discrepancy evidence (LLDP wins, no second link); ARP merges
// like FDB but never creates a second link when the pair already has one.
func mergeCandidate(links []*Link, c *candidate) []*Link {
	// Orient the candidate onto normalized (A < B) sides.
	a, b := c.reporter, c.target
	aPort, bPort := c.port, c.remotePort
	if a > b {
		a, b = b, a
		aPort, bPort = bPort, aPort
	}
	reporterIsA := c.reporter == a

	sideMatches := func(l *Link) (exact bool, fillable bool) {
		lA := portRef{l.AIfIndex, l.AIfName}
		lB := portRef{l.BIfIndex, l.BIfName}
		if reporterIsA {
			if samePort(lA, aPort) {
				return true, false
			}
			return false, !lA.known()
		}
		if samePort(lB, bPort) {
			return true, false
		}
		return false, !lB.known()
	}

	apply := func(l *Link) {
		if aPort.known() && !(portRef{l.AIfIndex, l.AIfName}).known() {
			l.AIfIndex, l.AIfName = aPort.ifIndex, aPort.name
		}
		if bPort.known() && !(portRef{l.BIfIndex, l.BIfName}).known() {
			l.BIfIndex, l.BIfName = bPort.ifIndex, bPort.name
		}
		l.VLANIDs = append(l.VLANIDs, c.vlans...)
		if c.ts.After(l.LatestEvidence) {
			l.LatestEvidence = c.ts
		}
		if tierRank(c.tier) > tierRank(l.Method) {
			l.Method = methodForTier(c.tier)
		}
		room := maxEvidencePerLink - len(l.Evidence)
		if room > 0 {
			ev := c.ev
			if len(ev) > room {
				ev = ev[:room]
			}
			l.Evidence = append(l.Evidence, ev...)
		}
	}

	// 1) Exact reporter-side port match → merge.
	for _, l := range links {
		if exact, _ := sideMatches(l); exact {
			apply(l)
			return links
		}
	}
	// 2) Reporter-side unknown on an existing link → fill it.
	for _, l := range links {
		if _, fillable := sideMatches(l); fillable {
			apply(l)
			return links
		}
	}
	// 3) Port conflict handling per tier.
	if len(links) > 0 {
		hasLLDP := false
		for _, l := range links {
			if l.Method == MethodLLDP {
				hasLLDP = true
				break
			}
		}
		if (c.tier != TierLLDP && hasLLDP) || c.tier == TierARP {
			// Attach as discrepancy evidence to the first link — a weaker
			// tier must not spawn a parallel link the stronger tier (or an
			// existing attribution) contradicts.
			l := links[0]
			room := maxEvidencePerLink - len(l.Evidence)
			for i := range c.ev {
				if room <= 0 {
					break
				}
				ref := c.ev[i]
				ref.Note = "port disagrees with the link's attribution (" + methodForTier(c.tier) + ")"
				l.Evidence = append(l.Evidence, ref)
				room--
			}
			if c.ts.After(l.LatestEvidence) {
				l.LatestEvidence = c.ts
			}
			return links
		}
	}
	// 4) New (possibly parallel) link.
	nl := &Link{
		A: a, B: b,
		AIfIndex: aPort.ifIndex, AIfName: aPort.name,
		BIfIndex: bPort.ifIndex, BIfName: bPort.name,
		Method:         methodForTier(c.tier),
		LatestEvidence: c.ts,
		VLANIDs:        append([]int(nil), c.vlans...),
		Evidence:       append([]EvidenceRef(nil), c.ev...),
	}
	return append(links, nl)
}

func tierRank(s string) int {
	switch s {
	case TierLLDP, MethodLLDP:
		return 3
	case TierFDB, MethodFDB:
		return 2
	case TierARP, MethodARP:
		return 1
	}
	return 0
}

func methodForTier(tier string) string {
	switch tier {
	case TierLLDP:
		return MethodLLDP
	case TierFDB:
		return MethodFDB
	default:
		return MethodARP
	}
}

// finalize computes the derived fields (Sided, Status, VLAN dedup).
func (ix *indexes) finalize(l *Link) {
	aKnown := l.AIfIndex > 0 || l.AIfName != ""
	bKnown := l.BIfIndex > 0 || l.BIfName != ""
	switch {
	case aKnown && bKnown:
		l.Sided = "both"
	case aKnown:
		l.Sided = "a_only"
	default:
		l.Sided = "b_only"
	}

	// VLAN dedup + sort.
	if len(l.VLANIDs) > 0 {
		seen := map[int]bool{}
		uniq := l.VLANIDs[:0]
		for _, v := range l.VLANIDs {
			if v > 0 && !seen[v] {
				seen[v] = true
				uniq = append(uniq, v)
			}
		}
		sort.Ints(uniq)
		l.VLANIDs = uniq
	}

	// Status: down if any KNOWN endpoint interface is oper-down, else up.
	l.Status = "up"
	check := func(dev uint, ifIndex int, name string) {
		var f *Iface
		if ifIndex > 0 {
			f = ix.byIndex[dev][ifIndex]
		}
		if f == nil && name != "" {
			f = ix.byName[dev][strings.ToLower(name)]
		}
		if f != nil && f.Status == "down" {
			l.Status = "down"
		}
	}
	check(l.A, l.AIfIndex, l.AIfName)
	check(l.B, l.BIfIndex, l.BIfName)
}

// EndpointTypeName returns the TypeName of a link endpoint's interface, "" if
// unknown — the poller uses it to classify ethernet vs lag connections.
func EndpointTypeName(ifaces []Iface, dev uint, ifIndex int, name string) string {
	for i := range ifaces {
		f := &ifaces[i]
		if f.DeviceID != dev {
			continue
		}
		if (ifIndex > 0 && f.IfIndex == ifIndex) || (name != "" && strings.EqualFold(f.Name, name)) {
			return f.TypeName
		}
	}
	return ""
}
