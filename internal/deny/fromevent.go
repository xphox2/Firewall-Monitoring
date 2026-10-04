package deny

import (
	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
	"firewall-mon/internal/threatintel"
)

// FromEvent derives a DeniedEvent from a normalized Event — the vendor-neutral
// successor of ProjectVendor's per-vendor scans. S-4 switches ingest to it
// once every line is normalized; until then it exists so TestDenyParity can
// prove, fixture by fixture, that the two produce the same row for the
// FortiGate and pf deny shapes ProjectVendor handles today.
//
// A denial is a network-class session or packet verdict (not an HTTP / DNS
// filter block, which is a UTM finding in deny_storm terms) whose action is
// deny or reject; or, when the operator configured a block-policy name
// pattern, a FortiGate session start (`action="start"`, Activity open) on a
// policy whose name matches (Signal 2). Everything else is not projected.
func FromEvent(ev *normalize.Event, tm *threatintel.Holder, cfg PatternConfig) (models.DeniedEvent, bool) {
	if ev == nil || ev.Class != normalize.ClassNetwork {
		return models.DeniedEvent{}, false
	}
	switch ev.Activity {
	case normalize.ActivityTraffic, normalize.ActivityPacket, normalize.ActivityOpen, normalize.ActivityClose:
	default:
		return models.DeniedEvent{}, false
	}
	var signal uint8
	switch {
	case ev.Action == normalize.ActionDeny || ev.Action == normalize.ActionReject:
		signal = models.DenySignalAction
	case ev.Activity == normalize.ActivityOpen && cfg.matches(ev.RuleName):
		signal = models.DenySignalPattern
	default:
		return models.DeniedEvent{}, false
	}
	if ev.SrcIP == nil || ev.DstIP == nil {
		return models.DeniedEvent{}, false
	}
	// Same scope-local drop as the projections (multicast / link-local /
	// limited broadcast would manufacture a fake victim).
	if classify.ScopeLocalIP(ev.SrcIP) || classify.ScopeLocalIP(ev.DstIP) {
		return models.DeniedEvent{}, false
	}
	out := models.DeniedEvent{
		Timestamp:  ev.Ts,
		DeviceID:   ev.DeviceID,
		ProbeID:    ev.ProbeID,
		SrcAddr:    ev.SrcIP.String(),
		DstAddr:    ev.DstIP.String(),
		SrcPort:    u16(ev.SrcPort),
		DstPort:    u16(ev.DstPort),
		Protocol:   u8(ev.Proto),
		SrcCountry: capStr(countryName(ev.SrcCountry, ev.Extra["src_country_name"]), 48),
		DstCountry: capStr(countryName(ev.DstCountry, ev.Extra["dst_country_name"]), 48),
		PolicyName: capStr(ev.RuleName, 64),
		Service:    capStr(ev.Extra["service"], 64),
		Subtype:    subtype(ev.Extra["subtype"]),
		Signal:     signal,
	}
	if ev.SrcRole != nil {
		out.SrcIntfRole = uint8(*ev.SrcRole)
	}
	// PolicyID is the FortiGate policy id. The filterlog projection has never
	// stored pf's rule NUMBER there (it is positional and changes on every
	// reorder; the stable tracker is Event.RuleUID, which the normalized
	// tables keep) — same row as ProjectVendor writes today.
	if ev.RuleID != nil && ev.VendorEventID != "filterlog" && *ev.RuleID >= 0 && *ev.RuleID <= 0xFFFFFFFF {
		out.PolicyID = uint32(*ev.RuleID)
	}
	if tm != nil {
		if _, ok := tm.Match(out.SrcAddr); ok {
			out.ThreatFlag |= 1
		}
		if _, ok := tm.Match(out.DstAddr); ok {
			out.ThreatFlag |= 2
		}
	}
	return out, true
}

// countryName restores the vendor's country NAME (what denied_events stores)
// from the Event's ISO code, or the unmapped raw name kept in Extra.
func countryName(cc, raw string) string {
	if raw != "" {
		return raw
	}
	return normalize.CountryName(cc)
}

func u16(p *int32) uint16 {
	if p == nil || *p < 0 || *p > 65535 {
		return 0
	}
	return uint16(*p)
}

func u8(p *int16) uint8 {
	if p == nil || *p < 0 || *p > 255 {
		return 0
	}
	return uint8(*p)
}
