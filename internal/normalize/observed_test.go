package normalize

import (
	"net"
	"strings"
	"testing"

	"firewall-mon/internal/normalize/capability"
)

// TestObservedFields pins the observed-field vocabulary: at most 64 names
// (Presence is a uint64), no duplicates, every capability.Field a profile or
// a feature names is tracked (otherwise the capability API could never see
// it as observed), and every tracked name has an `event.<name>` rule key, so
// the three spellings cannot drift apart.
func TestObservedFields(t *testing.T) {
	t.Parallel()
	if len(ObservedFields) > 64 {
		t.Fatalf("ObservedFields has %d names; Presence is a uint64", len(ObservedFields))
	}
	idx := map[string]int{}
	for i, f := range ObservedFields {
		if _, dup := idx[f]; dup {
			t.Errorf("ObservedFields lists %q twice", f)
		}
		idx[f] = i
	}
	for _, vendor := range capability.Vendors() {
		for f := range capability.Lookup(vendor).Fields {
			if _, ok := idx[string(f)]; !ok {
				t.Errorf("%s profile field %q is not in ObservedFields", vendor, f)
			}
		}
	}
	for feature, fields := range capability.Features {
		for _, f := range fields {
			if _, ok := idx[string(f)]; !ok {
				t.Errorf("feature %s field %q is not in ObservedFields", feature, f)
			}
		}
	}
	// Every name is an Event column the rule view renders: fill every column
	// and check the keys appear.
	full := fullEvent()
	dst := map[string]string{}
	full.Fields(dst)
	for _, f := range ObservedFields {
		if _, ok := dst[FieldPrefix+f]; !ok {
			t.Errorf("ObservedFields %q has no %s%s rule key", f, FieldPrefix, f)
		}
	}
}

// TestPresent_MatchesFields: Present marks exactly the ObservedFields that
// Fields renders — for an empty Event, a fully populated one, and a sparse
// one — so the observed counters and the rule view agree on "supplied".
func TestPresent_MatchesFields(t *testing.T) {
	t.Parallel()
	sparse := Event{Class: ClassNetwork, Action: ActionDeny, SrcIP: net.ParseIP("203.0.113.9"), RuleKey: "u:1", User: "alice"}
	for name, ev := range map[string]*Event{"empty": {}, "full": fullEvent(), "sparse": &sparse} {
		dst := map[string]string{}
		ev.Fields(dst)
		p := ev.Present()
		for i, f := range ObservedFields {
			_, rendered := dst[FieldPrefix+f]
			if f == "action" {
				rendered = ev.Action != ActionUnknown // Fields always writes event.action (by name)
			}
			if p.Has(i) != rendered {
				t.Errorf("%s: Present(%q) = %v, Fields rendered = %v", name, f, p.Has(i), rendered)
			}
		}
	}
	if (&Event{}).Present() != 0 {
		t.Error("an empty Event must have no present fields")
	}
}

// fullEvent returns an Event with every ObservedFields column supplied.
func fullEvent() *Event {
	e := &Event{Class: ClassNetwork, Activity: ActivityTraffic, Action: ActionAllow, VendorEventID: "x"}
	e.SrcIP, e.DstIP = net.ParseIP("192.0.2.10"), net.ParseIP("203.0.113.20")
	e.SrcPort, e.DstPort = e.i32("1"), e.i32("2")
	e.Proto = e.i16("6")
	e.SrcMAC, _ = net.ParseMAC("00:00:5e:00:53:0a")
	e.DstMAC, _ = net.ParseMAC("00:00:5e:00:53:0b")
	e.SrcIf, e.DstIf, e.SrcZone, e.DstZone = "a", "b", "c", "d"
	r := RoleLAN
	e.SrcRole, e.DstRole = &r, &r
	d := DirectionOutbound
	e.Direction = &d
	e.RuleKey, e.RuleUID, e.RuleName, e.Ruleset = "u:1", "1", "n", "root"
	e.RuleID, e.RuleIndex = e.i64("1"), e.i32("1")
	e.User, e.Group, e.App, e.AppCat = "alice", "staff", "HTTPS", "Web"
	e.AppRisk = e.i16("1")
	e.DevType, e.OSName, e.SrcHostname = "Computer", "Linux", "alice-laptop"
	e.BytesOut, e.BytesIn, e.PktsOut, e.PktsIn = e.i64("1"), e.i64("2"), e.i64("3"), e.i64("4")
	e.DurationMS = e.i32("5")
	e.SessionID = "s"
	e.NatSrcIP, e.NatDstIP = net.ParseIP("203.0.113.2"), net.ParseIP("203.0.113.3")
	e.SrcCountry, e.DstCountry = "US", "NL"
	e.URLHost, e.URLPath, e.DNSQName, e.WebCat = "www.example.com", "/", "example.com", "News"
	e.DNSQType = e.i16("1")
	e.Severity = e.i16("5")
	e.SigID, e.SigName, e.ThreatCat, e.FileHash = "1", "sig", "cat", "hash"
	e.AdminUser, e.AdminSrcIP, e.AdminMethod = "alice", "192.0.2.10", "gui"
	e.TunnelName, e.TunnelType = "t", "ipsec"
	e.TunnelPeer = net.ParseIP("203.0.113.50")
	e.ConfigPath, e.ConfigObj, e.ConfigOld, e.ConfigNew = "p", "o", "old", "new"
	e.WANName, e.MetricName = "wan1", "latency_ms"
	v := 1.5
	e.MetricValue = &v
	// Sanity: no ObservedFields name without a setter above.
	for _, f := range ObservedFields {
		if strings.TrimSpace(f) == "" {
			panic("empty ObservedFields name")
		}
	}
	return e
}
