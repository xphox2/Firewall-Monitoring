// Package vpnsession turns a firewall's live IPSec session documents into
// vpn_status telemetry rows.
//
// It exists because the vendor driver layer (internal/ipsec) answers a
// different question: driver.ParseStatus collapses a whole document into ONE
// TunnelStatus for ONE tunnel, keyed by peer IP, to decide whether a deploy
// succeeded. Telemetry needs the opposite — every child SA on the box, each as
// its own row with counters and selectors. Reusing ParseStatus would mean
// changing semantics the deploy-verification path depends on.
//
// This package deliberately does not import internal/ipsec: the driver packages
// are models-free by design and this one produces models.VPNStatus.
package vpnsession

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// ExpectedChild is one subnet pair a provisioned tunnel is supposed to carry.
//
// It is needed because a DOWN child produces no evidence at all: OPNsense
// children are configured with start_action start/none rather than trap or
// route, so when one is not established there is no SAD entry and no SPD
// policy to read. Without an expected list the rows would simply stop
// arriving, the edge would age out, and the alert path — which requires a
// literal status="down" row — would never fire. The tunnel would fail
// silently, which is the exact failure this telemetry exists to surface.
type ExpectedChild struct {
	TunnelName string // the provisioned name, e.g. "fwm-t11"
	Local      string // local selector CIDR from the intent
	Remote     string // remote selector CIDR from the intent
}

// opnDoc is the envelope every OPNsense search endpoint returns.
//
// Rows is a POINTER so its absence can be told apart from an empty result. A
// body that is valid JSON but not a result set — an auth failure rendered as
// 200, an error envelope — would otherwise unmarshal cleanly with a nil slice
// and read as "this box has no tunnels", synthesizing a down row for every
// expected child. That is a fleet-wide false outage manufactured out of a
// failed request, which is worse than reporting nothing.
type opnDoc struct {
	Rows *[]map[string]any `json:"rows"`
}

// rows returns the result set, or an error when the document carried none.
func (d opnDoc) rows(what string) ([]map[string]any, error) {
	if d.Rows == nil {
		return nil, fmt.Errorf("%s did not return a result set (no \"rows\" key) — "+
			"treating as an error rather than as zero tunnels", what)
	}
	return *d.Rows, nil
}

// ParseOPNsense builds one row per child SA from the three session documents.
//
// phase1Body/sadBody/spdBody are the raw bodies of sessions/searchPhase1,
// sad/search and spd/search respectively. expected lists the children the
// server knows this device should have, so absent ones can be reported down.
//
// A parse error on any document is fatal for the whole batch: a partial view
// would be indistinguishable from "these tunnels went away", and writing down
// rows from it would raise false outages.
func ParseOPNsense(deviceID uint, ts time.Time, phase1Body, sadBody, spdBody string, expected []ExpectedChild) ([]models.VPNStatus, error) {
	conns, err := parsePhase1(phase1Body)
	if err != nil {
		return nil, err
	}
	policies, err := parseSPD(spdBody)
	if err != nil {
		return nil, err
	}
	sas, err := parseSAD(sadBody)
	if err != nil {
		return nil, err
	}

	out := make([]models.VPNStatus, 0, len(policies)+len(expected))
	seen := make(map[string]bool, len(policies))

	for _, pol := range policies {
		c := conns.forPeer(pol.remoteHost)
		name, phase1 := childName(c, pol.localSel, pol.remoteSel)
		in, outb := sas.counters(pol.reqid, pol.localHost)

		row := models.VPNStatus{
			DeviceID:     deviceID,
			Timestamp:    ts,
			TunnelName:   name,
			Phase1Name:   phase1,
			TunnelType:   "ipsec",
			RemoteIP:     pol.remoteHost,
			LocalSubnet:  pol.localSel,
			RemoteSubnet: pol.remoteSel,
			Status:       "down",
			Mode:         "tunnel",
		}
		// An installed SA is the only thing that proves traffic can flow. The
		// phase1 being "connected" is not sufficient — the IKE SA can be up
		// with no child installed, which is precisely the state that moves no
		// packets and is worth alerting on.
		if in != nil || outb != nil {
			row.Status = "up"
			row.State = "installed"
		}
		if in != nil {
			row.BytesIn = in.bytes
			row.PacketsIn = 0 // SAD exposes bytes only; packets are not in the record
		}
		if outb != nil {
			row.BytesOut = outb.bytes
		}
		// TunnelUptime ONLY for a currently-installed SA. resolveVPNEverUp
		// treats a non-zero uptime on a down row as proof the tunnel once
		// worked and arms VPN_DOWN for it — permanently, since that decision
		// is latched per process. Reporting an age for a child that is not
		// installed would arm alerting on first sight.
		if outb != nil {
			row.TunnelUptime = outb.age
		} else if in != nil {
			row.TunnelUptime = in.age
		}

		out = append(out, row)
		seen[childKey(pol.localSel, pol.remoteSel)] = true
	}

	// Anything the server expects but the box is not carrying is DOWN, not
	// absent. Zero counters and zero uptime keep the ever-up gate honest: a
	// child that has never established must not be alertable.
	for _, e := range expected {
		if seen[childKey(e.Local, e.Remote)] {
			continue
		}
		out = append(out, models.VPNStatus{
			DeviceID:     deviceID,
			Timestamp:    ts,
			TunnelName:   tunnelChildName(e.TunnelName, e.Local, e.Remote),
			Phase1Name:   e.TunnelName,
			TunnelType:   "ipsec",
			LocalSubnet:  e.Local,
			RemoteSubnet: e.Remote,
			Status:       "down",
			Mode:         "tunnel",
		})
	}
	return out, nil
}

// ---- phase1 ------------------------------------------------------------

type conn struct {
	desc string
	uuid string
}

type connIndex struct {
	byPeer map[string][]conn
	total  int  // connections seen, for the unambiguous-by-elimination fallback
	only   conn // the sole connection when total == 1
}

// forPeer returns the connection terminating on that peer address, or a zero
// conn when there is none or the answer is ambiguous.
//
// Ambiguity is deliberately resolved by refusing to answer: two connections to
// the same peer address cannot be told apart from the session documents, and a
// child attributed to the wrong tunnel would be labelled with a name an
// operator trusts.
func (ci connIndex) forPeer(peer string) conn {
	if cs := ci.byPeer[peer]; len(cs) == 1 {
		return cs[0]
	} else if len(cs) > 1 {
		return conn{} // ambiguous — refuse rather than mislabel
	}
	// No address match. This is NOT exotic: when this box is the responder to a
	// dynamic peer the driver renders remote_addrs as "%any", so searchPhase1
	// reports no usable peer address while the kernel SPD holds the address the
	// peer was observed arriving from — the join fails for every child of that
	// tunnel. Leaving them unnamed would empty Phase1Name, which is the field
	// the connection map matches provisioned tunnels on, dropping the row back
	// to IP matching against a NAT address: exactly the misattribution that was
	// just fixed.
	//
	// When the box has exactly one connection, elimination is not a guess.
	if ci.total == 1 {
		return ci.only
	}
	return conn{}
}

func parsePhase1(body string) (connIndex, error) {
	ci := connIndex{byPeer: map[string][]conn{}}
	var doc opnDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return ci, fmt.Errorf("searchPhase1 unparseable: %w", err)
	}
	rows, rerr := doc.rows("searchPhase1")
	if rerr != nil {
		return ci, rerr
	}
	for _, r := range rows {
		// local-addrs is "%any" on a box behind NAT, so only the remote side
		// is usable as a join key.
		c := conn{
			desc: strings.TrimSpace(str(r, "phase1desc")),
			uuid: str(r, "name", "ikeid"),
		}
		ci.total++
		ci.only = c
		// "%any" is a wildcard, not an address — indexing it would make every
		// dynamic-peer tunnel collide under one key.
		peer := hostOf(str(r, "remote-addrs", "remote-host"))
		if peer == "" || peer == "%any" {
			continue
		}
		ci.byPeer[peer] = append(ci.byPeer[peer], c)
	}
	return ci, nil
}

// ---- SPD (selectors) ---------------------------------------------------

type policy struct {
	reqid                 string
	localSel, remoteSel   string
	localHost, remoteHost string
}

func parseSPD(body string) ([]policy, error) {
	var doc opnDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil, fmt.Errorf("spd/search unparseable: %w", err)
	}
	rows, rerr := doc.rows("spd/search")
	if rerr != nil {
		return nil, rerr
	}
	out := make([]policy, 0, len(rows)/2+1)
	for _, r := range rows {
		// Each child appears twice, once per direction. The outbound policy
		// alone gives local→remote in the orientation vpn_status wants.
		if !strings.EqualFold(str(r, "dir"), "out") {
			continue
		}
		id := reqidOf(r)
		if id == "" {
			continue
		}
		p := policy{reqid: id, localSel: str(r, "src"), remoteSel: str(r, "dst")}
		// src-dst is [local endpoint, remote endpoint] for the out direction.
		// Both sides are normalized the same way as the SAD's src, since either
		// may carry a "[port]" suffix and a raw comparison would silently never
		// match.
		if hosts, ok := r["src-dst"].([]any); ok && len(hosts) == 2 {
			lh, _ := hosts[0].(string)
			rh, _ := hosts[1].(string)
			p.localHost, p.remoteHost = hostOf(lh), hostOf(rh)
		}
		// Without the endpoint pair the SAs cannot be assigned a direction: an
		// empty localHost makes EVERY SA look inbound, so which one wins is map
		// iteration order. bytes_in would then alternate between two cumulative
		// counters poll-to-poll and the downstream reset-clamp would re-count
		// each downward swap as a full cumulative — a traffic spike from
		// nothing, with bytes_out flat at zero. Skipping is the honest answer.
		if p.localHost == "" || p.remoteHost == "" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// ---- SAD (counters) ----------------------------------------------------

type sa struct {
	bytes uint64
	age   uint64
}

type saIndex struct {
	// keyed reqid → direction → newest SA
	byReqid map[string]map[string]*sa
}

func parseSAD(body string) (saIndex, error) {
	idx := saIndex{byReqid: map[string]map[string]*sa{}}
	var doc opnDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return idx, fmt.Errorf("sad/search unparseable: %w", err)
	}
	rows, rerr := doc.rows("sad/search")
	if rerr != nil {
		return idx, rerr
	}
	// age is seconds since install, so the SMALLEST age is the newest SA.
	// During rekey two SAs share one reqid and direction; taking the newest
	// rather than summing avoids double-counting the overlap and the phantom
	// drop when the old one expires — a drop the downstream reset-clamp would
	// re-count as a full cumulative, spiking every chart once an hour.
	for _, r := range rows {
		id := reqidOf(r)
		if id == "" {
			continue
		}
		src := hostOf(str(r, "src"))
		cand := &sa{bytes: num(r, "bytes_current"), age: num(r, "addtime_diff")}
		if idx.byReqid[id] == nil {
			idx.byReqid[id] = map[string]*sa{}
		}
		cur := idx.byReqid[id][src]
		if cur == nil || cand.age < cur.age {
			idx.byReqid[id][src] = cand
		}
	}
	return idx, nil
}

// counters returns the inbound and outbound SA for a child. Outbound is the one
// whose source is this box.
func (idx saIndex) counters(reqid, localHost string) (in, out *sa) {
	for src, s := range idx.byReqid[reqid] {
		if src == localHost {
			out = s
		} else {
			in = s
		}
	}
	return in, out
}

// ---- naming ------------------------------------------------------------

// childName derives the per-child tunnel name and its parent phase1 name.
//
// The two identities are split across two fields on purpose. TunnelName must be
// unique per child, because GetAllLatestVPNStatuses keeps only the newest row
// per (device_id, tunnel_name) — every child sharing one name would collapse a
// multi-subnet tunnel to a single surviving row. Phase1Name carries the bare
// provisioned name so the connection map's provisioned-attribution matches it
// with no extra code.
func childName(c conn, localSel, remoteSel string) (name, phase1 string) {
	if c.desc != "" {
		return tunnelChildName(c.desc, localSel, remoteSel), c.desc
	}
	// No description: an unprovisioned / hand-built tunnel. The connection UUID
	// is the only stable-ish identity available. It changes if the connection
	// is recreated, which reads as a new tunnel — accepted, and it only affects
	// tunnels this system did not create.
	if c.uuid != "" {
		return tunnelChildName(c.uuid, localSel, remoteSel), c.uuid
	}
	return tunnelChildName("ipsec", localSel, remoteSel), ""
}

// tunnelChildName joins a tunnel name to the child's selector PAIR.
//
// Both selectors are required, not just the remote one. A tunnel fans out
// local×remote, so two children can share a remote selector while differing on
// the local side — e.g. 50.0/24→13.0/24 and 60.0/24→13.0/24. Naming on the
// remote alone gives them one name, and GetAllLatestVPNStatuses (newest row per
// device+tunnel_name) then discards one of them. That is the mirror image of
// the multi-subnet case this telemetry exists to make visible, so it must not
// be the thing that breaks it.
//
// The separator must not be "/" and network addresses are used WITHOUT their
// prefix length, because this value is passed in a URL PATH by every chart
// caller (…/vpn/:tunnel/chart) and gin routes on the decoded path — an escaped
// slash becomes a real separator and the request 404s. Dropping the prefix
// costs no uniqueness: two children of one tunnel differ in at least one
// network address.
func tunnelChildName(tunnel, localSel, remoteSel string) string {
	return tunnel + ":" + networkOf(localSel) + "-" + networkOf(remoteSel)
}

// childKey identifies a child by its SELECTOR PAIR, not by its name.
//
// Naming is best-effort — an unjoinable connection falls back to the UUID — but
// the expected-children list can only refer to the provisioned name. Keying on
// the name therefore fails to recognise an established-but-unnamed child, and
// the same child gets reported twice: up under the UUID and synthesized down
// under the provisioned name, i.e. a phantom outage beside a working tunnel.
//
// The selector pair is the child's real identity: the kernel will not install
// two policies for the same pair, so it is unique per box.
func childKey(localSel, remoteSel string) string {
	return networkOf(localSel) + "|" + networkOf(remoteSel)
}

// ---- small helpers -----------------------------------------------------

// networkOf strips a prefix length: "192.168.13.0/24" → "192.168.13.0".
func networkOf(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

// hostOf strips a port suffix strongSwan appends: "1.2.3.4[4500]" → "1.2.3.4".
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '['); i >= 0 {
		return s[:i]
	}
	return s
}

// reqidOf reads the join key, which the two endpoints type DIFFERENTLY: sad
// returns it as a JSON number and spd as a string. Verified on a live box — a
// single typed struct would silently fail on one of them.
func reqidOf(r map[string]any) string {
	switch v := r["reqid"].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprintf("%d", int64(v))
	}
	return ""
}

func str(r map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := r[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func num(r map[string]any, key string) uint64 {
	switch v := r[key].(type) {
	case float64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case string:
		var n uint64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}
