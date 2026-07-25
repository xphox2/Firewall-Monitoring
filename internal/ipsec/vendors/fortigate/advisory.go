package fortigate

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"firewall-mon/internal/ipsec"
)

// checkRouteTable is the AdvisoryProbe step that reads the device's static-route
// table so the server can spot a pre-existing route that competes with the one a
// deploy would install for a remote protected subnet.
const checkRouteTable = "route_table"

// advisoryRouteFormat restricts the cmdb response to the fields the analysis
// needs. Without it a busy edge device returns every attribute of every route,
// which risks blowing the collector's report size cap (the report is dropped
// whole if it exceeds it). Unsupported `format` is harmless — FortiOS then
// returns the full objects, which parse the same way.
const advisoryRouteFormat = "?format=seq-num|dst|dstaddr|gateway|device|distance|priority|blackhole|status|comment"

// fgTunnelRouteDistance is the administrative distance FortiOS gives the static
// routes Render installs for a STATIC peer. routeSteps deliberately omits
// `distance`, so the device applies its default of 10;
// TestRenderTunnelRouteOmitsDistance pins that omission so this constant cannot
// drift away from what Render actually does.
const fgTunnelRouteDistance = 10

// fgInjectedRouteDistance is the distance of the routes FortiOS injects itself
// for a DYNAMIC (dialup) peer via phase1 add-route — the FortiOS default for
// IKE-added routes. Render installs no per-subnet routes of its own in that case
// (see tunnelRoutesNeeded), so 15 — not 10 — is the bar a pre-existing route has
// to beat to divert the tunnel's traffic.
const fgInjectedRouteDistance = 15

// tunnelRouteDistance returns the distance of whichever route actually carries
// this tunnel's remote subnets, which depends on who installs it. Getting this
// wrong in either direction is a live defect: too high and a genuinely competing
// route is dismissed as harmless (a false all-clear on the exact "tunnel up,
// zero outbound" failure this advisory exists to catch), too low and a
// harmless route is reported with the wrong consequence.
func tunnelRouteDistance(remote *ipsec.EndpointSpec) int {
	if remote.Dynamic {
		return fgInjectedRouteDistance
	}
	return fgTunnelRouteDistance
}

// AdvisoryProbe reads the whole static-route table. This is a plain GET with no
// ExpectAbsent semantics: it lives outside PreflightProbe precisely so the deploy
// saga (which uses PreflightProbe as its collision precheck and ABORTS on a hit)
// can never see it, and so no finding derived from it can stop a deploy.
func (d driver) AdvisoryProbe(v ipsec.RenderView) []ipsec.PreflightStep {
	if len(v.Remote().ProtectedSubnets) == 0 {
		return nil
	}
	return []ipsec.PreflightStep{{
		Check:      checkRouteTable,
		Method:     "GET",
		Path:       cmdbRoute + advisoryRouteFormat,
		ReturnBody: true,
	}}
}

// Advisories reports pre-existing static routes that would steer a remote
// protected subnet away from this tunnel. Each remote subnet ends up with one
// route via the tunnel — installed by Render at distance 10 for a static peer,
// or injected by FortiOS at distance 15 for a dialup peer (see
// tunnelRouteDistance). An existing route for an overlapping prefix at a LOWER
// distance wins outright (traffic never enters the tunnel); one at an EQUAL
// distance is installed alongside it and ECMP-balanced. Both are silent at
// deploy time — the tunnel comes up and simply does not carry the traffic.
//
// Advisory-only by construction: an unreadable, absent, or unparseable body
// yields NO findings rather than a guessed warning.
func (d driver) Advisories(v ipsec.RenderView, bodies map[string]string) []ipsec.Advisory {
	rows, ok := parseFGRouteTable(bodies[checkRouteTable])
	if !ok {
		return nil
	}
	in := v.Intent
	local, remote := v.Local(), v.Remote()

	// Routes this tunnel owns are not conflicts. Exclude them by the deterministic
	// seq-nums Render uses, and belt-and-braces by the comment/device tag Render
	// stamps, so a re-run against a half-deployed device does not flag itself.
	ours := make(map[int]bool, routeCount(local, remote))
	for i := 0; i < routeCount(local, remote); i++ {
		ours[ipsec.FGRouteKey(in.ID, i)] = true
	}

	// Pre-parse our protected prefixes once; a malformed one is a validation
	// concern, not an advisory concern, so it is skipped silently here.
	type prefix struct {
		text string
		net  *net.IPNet
	}
	var wanted []prefix
	for _, s := range remote.ProtectedSubnets {
		if _, n, err := net.ParseCIDR(s); err == nil {
			wanted = append(wanted, prefix{text: s, net: n})
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	ourDist := tunnelRouteDistance(remote)
	seen := make(map[int]bool)
	var out []ipsec.Advisory
	for _, r := range rows {
		seq, hasSeq := fgInt(r, "seq-num")
		if hasSeq && (ours[seq] || seen[seq]) {
			continue
		}
		if strings.EqualFold(fgStr(r, "comment"), in.Name) || fgStr(r, "device") == in.Name {
			continue // ours by tag, or already pointing at this tunnel's VTI
		}
		if strings.EqualFold(fgStr(r, "status"), "disable") {
			continue // administratively down — not in the RIB
		}
		if strings.EqualFold(fgStr(r, "blackhole"), "enable") {
			continue // a discard route, not a competing forwarding path
		}
		dstText := fgStr(r, "dst")
		dst, dstOK := parseFGDst(dstText)
		if !dstOK {
			// dstaddr (an address-object reference) cannot be resolved from this
			// response, so the prefix is unknown — stay silent rather than guess.
			continue
		}
		// FortiOS omits `distance` only if the field was filtered out; the device
		// default is 10 and Render relies on that same default, so an absent value
		// is treated as the default rather than as "no opinion".
		dist, hasDist := fgInt(r, "distance")
		if !hasDist {
			dist = fgTunnelRouteDistance // FortiOS's default when the field is filtered out
		}
		if dist > ourDist {
			continue // the tunnel's route wins on distance — no advisory
		}
		for _, w := range wanted {
			if !prefixesOverlap(dst, w.net) {
				continue
			}
			if hasSeq {
				seen[seq] = true
			}
			out = append(out, fgRouteAdvisory(in.Name, w.text, dstText, dst, r, seq, hasSeq, dist, ourDist, remote.Dynamic))
			break
		}
	}
	// Deterministic order so the UI and the tests do not depend on FortiOS's
	// response ordering.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}

// fgRouteAdvisory renders one conflicting route into an operator-facing finding.
// The two cases read very differently on the device, so they get distinct copy:
// a lower distance defeats the tunnel outright, an equal distance ECMP-splits.
func fgRouteAdvisory(tunnel, wanted, dstText string, dst *net.IPNet, r map[string]any, seq int, hasSeq bool, dist, ourDist int, dynamic bool) ipsec.Advisory {
	via := fgStr(r, "gateway")
	dev := fgStr(r, "device")
	switch {
	case via != "" && dev != "":
		via = via + " on " + dev
	case via == "" && dev != "":
		via = "interface " + dev
	case via == "":
		via = "an unspecified next-hop"
	}
	id := "an existing static route"
	if hasSeq {
		id = "existing static route seq-num " + strconv.Itoa(seq)
	}

	// Name who owns the tunnel's route, because the remedy differs: for a dialup
	// peer the operator cannot simply lower "our" route — the device installs it.
	owner := fmt.Sprintf("the route %s installs for %s", tunnel, wanted)
	if dynamic {
		owner = fmt.Sprintf("the route the device injects for %s (dialup peer, phase1 add-route)", wanted)
	}

	a := ipsec.Advisory{Check: checkRouteTable, Subject: wanted}
	if dist < ourDist {
		a.Title = fmt.Sprintf("a pre-existing static route to %s outranks this tunnel's route", wanted)
		a.Detail = fmt.Sprintf(
			"%s covers %s (%s) via %s at distance %d. %s sits at distance %d, so the existing route stays preferred and traffic to %s will never enter the tunnel — the tunnel will come up but carry nothing for this prefix.",
			id, prefixText(dst, dstText), wanted, via, dist, owner, ourDist, wanted)
	} else {
		a.Title = fmt.Sprintf("a pre-existing static route to %s ties with this tunnel's route", wanted)
		a.Detail = fmt.Sprintf(
			"%s covers %s (%s) via %s at distance %d — the same distance as %s. FortiOS installs both and ECMP-balances between them, so traffic to %s can leave via %s instead of the tunnel.",
			id, prefixText(dst, dstText), wanted, via, dist, owner, wanted, via)
	}
	a.Remedy = fmt.Sprintf(
		"Raise the existing route's distance above %d so the tunnel route wins and the current path remains a fallback, or remove it if it is obsolete. On the device: config router static / edit %s / set distance %d / next / end.",
		ourDist, seqText(seq, hasSeq), ourDist+10)
	return a
}

func seqText(seq int, hasSeq bool) string {
	if hasSeq {
		return strconv.Itoa(seq)
	}
	return "<seq-num>"
}

// prefixText prefers the normalized CIDR but falls back to the device's own
// rendering when the two differ in a way worth showing verbatim.
func prefixText(n *net.IPNet, raw string) string {
	if n == nil {
		return raw
	}
	return n.String()
}

// prefixesOverlap reports whether two prefixes intersect. Two CIDR blocks
// intersect iff one contains the other's network address, so a /16 covering our
// /24 is caught as well as an exact match.
func prefixesOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// parseFGDst accepts FortiOS's "<ip> <mask>" static-route destination and, for
// robustness across builds, a plain CIDR. Returns ok=false for anything else
// (notably an empty dst, which means the route uses a dstaddr address object).
func parseFGDst(s string) (*net.IPNet, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, false
		}
		return n, true
	}
	f := strings.Fields(s)
	if len(f) != 2 {
		return nil, false
	}
	ip := net.ParseIP(f[0]).To4()
	mask := net.ParseIP(f[1]).To4()
	if ip == nil || mask == nil {
		return nil, false
	}
	m := net.IPMask(mask)
	if ones, bits := m.Size(); bits == 0 || ones > bits {
		return nil, false // non-contiguous mask — not a prefix we can reason about
	}
	return &net.IPNet{IP: ip.Mask(m), Mask: m}, true
}

// parseFGRouteTable decodes a cmdb list response into raw rows. ok is false when
// the body is absent or unparseable, which the caller turns into "no advisory"
// rather than a false all-clear.
func parseFGRouteTable(body string) ([]map[string]any, bool) {
	if strings.TrimSpace(body) == "" {
		return nil, false
	}
	var resp struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, false
	}
	return resp.Results, true
}

// fgStr reads a string-ish cmdb field. FortiOS is inconsistent about quoting
// numerics across builds, so a number is rendered rather than rejected.
func fgStr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return ""
	}
}

// fgInt reads an int-ish cmdb field, accepting both 10 and "10".
func fgInt(m map[string]any, k string) (int, bool) {
	switch v := m[k].(type) {
	case float64:
		return int(v), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}
