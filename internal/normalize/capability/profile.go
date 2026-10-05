// Package capability is the static half of the per-device capability matrix
// (roadmap §1.4): what each vendor CAN supply for every normalized field,
// through which transport, and how completely. The observed half (what a
// device actually sent) lands with the typed tables in a later PR; the API
// that joins the two is S-4. Every page, widget and detector will declare
// its required fields through Features so the UI can say "not available for
// this device" instead of charting zeros.
//
// Written from vendors-web.md §4 (the per-vendor field mapping table). The
// UniFi and Meraki rows are built from vendor documentation and are untested
// on real hardware. TestCapabilityProfile_NoDrift in internal/normalize
// asserts that every syslog-sourced field a profile claims is produced by at
// least one fixture of that vendor, so a profile cannot promise what the
// mapper does not deliver.
package capability

import "sort"

// Field names a normalized column (normalize.Event field, snake_case as the
// `event.*` rule view spells it).
type Field string

// The fields a profile may claim. Only fields a feature or the UI needs are
// listed; a mapper may fill more.
const (
	Action      Field = "action"
	SrcIP       Field = "src_ip"
	DstIP       Field = "dst_ip"
	SrcPort     Field = "src_port"
	DstPort     Field = "dst_port"
	Proto       Field = "proto"
	SrcMAC      Field = "src_mac"
	SrcIf       Field = "src_if"
	SrcZone     Field = "src_zone"
	SrcRole     Field = "src_role"
	RuleKey     Field = "rule_key"
	RuleUID     Field = "rule_uid"
	RuleID      Field = "rule_id"
	RuleName    Field = "rule_name"
	RuleIndex   Field = "rule_index"
	Ruleset     Field = "ruleset"
	User        Field = "user"
	App         Field = "app"
	AppCat      Field = "app_cat"
	DevType     Field = "dev_type"
	OSName      Field = "os_name"
	SrcHostname Field = "src_hostname"
	BytesOut    Field = "bytes_out"
	BytesIn     Field = "bytes_in"
	DurationMS  Field = "duration_ms"
	SessionID   Field = "session_id"
	NatSrcIP    Field = "nat_src_ip"
	SrcCountry  Field = "src_country"
	URLHost     Field = "url_host"
	DNSQName    Field = "dns_qname"
	WebCat      Field = "web_cat"
	Severity    Field = "severity"
	SigID       Field = "sig_id"
	SigName     Field = "sig_name"
	FileHash    Field = "file_hash"
	AdminUser   Field = "admin_user"
	AdminSrcIP  Field = "admin_src_ip"
	AdminMethod Field = "admin_method"
	TunnelName  Field = "tunnel_name"
	TunnelPeer  Field = "tunnel_peer"
	ConfigPath  Field = "config_path"
	ConfigOld   Field = "config_old"
	WANName     Field = "wan_name"
	MetricValue Field = "metric_value"
)

// Source is the transport a field arrives on.
type Source string

const (
	SourceSyslog  Source = "syslog"
	SourceNetFlow Source = "netflow"
	SourceAPI     Source = "api"
	SourceNone    Source = "none" // the vendor cannot supply it
)

// Completeness says how much of the vendor's traffic carries the field.
type Completeness string

const (
	Full            Completeness = "full"             // every relevant event
	ConfigDependent Completeness = "config_dependent" // only when a vendor option is on (FortiGate logtraffic all, Meraki per-rule Syslog box)
	Partial         Completeness = "partial"          // a subset of events by nature (per-packet logs, flagged rules only)
)

// Spec is one (vendor, field) cell.
type Spec struct {
	Source       Source
	Completeness Completeness
	// Note names the caveat the UI shows for config_dependent / partial.
	Note string
}

// Profile is one vendor's static capability row.
type Profile struct {
	Vendor string
	// Hardware reports whether the profile was verified against a real device
	// ("" ) or built from documentation only ("untested on real hardware").
	Hardware string
	Fields   map[Field]Spec
}

// Spec returns the cell for f; a field a profile does not list cannot be
// supplied (SourceNone).
func (p Profile) Spec(f Field) Spec {
	if s, ok := p.Fields[f]; ok {
		return s
	}
	return Spec{Source: SourceNone}
}

// Can reports whether the vendor supplies f at all.
func (p Profile) Can(f Field) bool { return p.Spec(f).Source != SourceNone }

var profiles = map[string]Profile{}

func register(p Profile) { profiles[p.Vendor] = p }

// Lookup returns vendor's profile, or the generic one for an unknown vendor.
func Lookup(vendor string) Profile {
	if p, ok := profiles[vendor]; ok {
		return p
	}
	return profiles["generic"]
}

// Vendors lists the profiled vendors, sorted.
func Vendors() []string {
	out := make([]string, 0, len(profiles))
	for v := range profiles {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Features maps a feature (a page, report section or detector) to the
// fields it needs. A device whose profile cannot supply one of them is
// "unsupported" for the feature; one whose profile can but that has not been
// observed sending it is "inactive" (the observed half, S-4).
var Features = map[string][]Field{
	"deny_analytics":     {Action, SrcIP, DstIP},
	"policy_hits":        {RuleKey, Action},
	"policy_bytes":       {RuleKey, BytesOut, BytesIn},
	"identity_inventory": {SrcIP, SrcMAC},
	"user_attribution":   {User},
	"app_visibility":     {App},
	"utm_trends":         {SigID, SigName, Severity},
	"web_categories":     {URLHost, WebCat},
	"dns_visibility":     {DNSQName},
	"vpn_sessions":       {TunnelName, TunnelPeer},
	"config_audit":       {ConfigPath, AdminUser},
	"admin_login_audit":  {AdminUser, AdminSrcIP},
	"wan_health":         {WANName, MetricValue},
	"nat_forensics":      {NatSrcIP},
	"geo":                {SrcCountry},
}

// FeatureState is the static verdict for a (feature, vendor) pair.
type FeatureState string

const (
	Supported   FeatureState = "supported"
	Degraded    FeatureState = "degraded"    // every field present, at least one config_dependent / partial
	Unsupported FeatureState = "unsupported" // at least one field the vendor cannot supply
	// Inactive is the observed half's verdict (the capability API, S-4): the
	// profile can supply every field but the device has not sent at least
	// one of them within the observation window. Feature never returns it.
	Inactive FeatureState = "inactive"
)

// FieldState is the effective per-(device, field) verdict the capability
// API reports: the profile's static cell joined with what the device was
// observed sending within the window.
type FieldState string

const (
	// FieldNative: the profile sources the field with Full completeness and
	// the device sent it within the window.
	FieldNative FieldState = "native"
	// FieldPartial: observed, but the profile says only a subset of events
	// carry it by nature.
	FieldPartial FieldState = "partial"
	// FieldConfigDependent: observed, and the profile says a vendor option
	// governs it — the device evidently has the option on today.
	FieldConfigDependent FieldState = "config_dependent"
	// FieldInactive: the profile can supply it but nothing was observed
	// within the window (option off, feature unused, or no traffic yet).
	FieldInactive FieldState = "inactive"
	// FieldUnsupported: the vendor cannot supply it (SourceNone).
	FieldUnsupported FieldState = "unsupported"
)

// EffectiveState joins one profile cell with the observation fact. Only a
// syslog-sourced cell can be observed by the syslog ingest; a NetFlow- or
// API-sourced cell reports its static completeness (the observed half of
// those transports is outside this matrix), and a cell with no source is
// unsupported whatever was observed.
func EffectiveState(spec Spec, observed bool) FieldState {
	switch {
	case spec.Source == SourceNone:
		return FieldUnsupported
	case spec.Source == SourceSyslog && !observed:
		return FieldInactive
	case spec.Completeness == Partial:
		return FieldPartial
	case spec.Completeness == ConfigDependent:
		return FieldConfigDependent
	default:
		return FieldNative
	}
}

// FeatureNames lists the Features keys, sorted (for API error messages and
// the all-features listing).
func FeatureNames() []string {
	out := make([]string, 0, len(Features))
	for f := range Features {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Feature evaluates feature for vendor and returns the state with the
// fields that caused a degradation or exclusion.
func Feature(feature, vendor string) (FeatureState, []Field) {
	p := Lookup(vendor)
	state := Supported
	var why []Field
	for _, f := range Features[feature] {
		s := p.Spec(f)
		switch {
		case s.Source == SourceNone:
			if state != Unsupported {
				why = why[:0]
			}
			state = Unsupported
			why = append(why, f)
		case s.Completeness != Full && state == Supported:
			state = Degraded
			why = append(why, f)
		case s.Completeness != Full && state == Degraded:
			why = append(why, f)
		}
	}
	return state, why
}

// s is a short constructor for the tables below.
func s(src Source, c Completeness, note string) Spec { return Spec{src, c, note} }

var (
	syslogFull = s(SourceSyslog, Full, "")
)

func init() {
	logtraffic := "needs `logtraffic all` on the policy; the default logs UTM-inspected sessions only"
	register(Profile{Vendor: "fortigate", Fields: map[Field]Spec{
		Action: syslogFull, SrcIP: syslogFull, DstIP: syslogFull, SrcPort: syslogFull, DstPort: syslogFull,
		Proto: syslogFull, SrcMAC: syslogFull, SrcIf: syslogFull, SrcRole: syslogFull, Ruleset: syslogFull,
		RuleKey: s(SourceSyslog, ConfigDependent, logtraffic), RuleUID: s(SourceSyslog, ConfigDependent, logtraffic),
		RuleID: s(SourceSyslog, ConfigDependent, logtraffic), RuleName: s(SourceSyslog, ConfigDependent, logtraffic),
		User: s(SourceSyslog, ConfigDependent, "FSSO / firewall authentication"), App: s(SourceSyslog, ConfigDependent, "application-control profile on the policy"),
		AppCat:  s(SourceSyslog, ConfigDependent, "application-control profile on the policy"),
		DevType: s(SourceSyslog, ConfigDependent, "device detection on the interface"), OSName: s(SourceSyslog, ConfigDependent, "device detection on the interface"),
		SrcHostname: s(SourceSyslog, ConfigDependent, "device detection on the interface"),
		BytesOut:    s(SourceSyslog, ConfigDependent, logtraffic), BytesIn: s(SourceSyslog, ConfigDependent, logtraffic),
		DurationMS: s(SourceSyslog, ConfigDependent, logtraffic), SessionID: syslogFull, NatSrcIP: syslogFull, SrcCountry: syslogFull,
		URLHost: s(SourceSyslog, ConfigDependent, "web-filter profile"), WebCat: s(SourceSyslog, ConfigDependent, "web-filter profile"),
		DNSQName: s(SourceSyslog, ConfigDependent, "DNS-filter profile"),
		Severity: syslogFull, SigID: s(SourceSyslog, ConfigDependent, "IPS sensor"), SigName: s(SourceSyslog, ConfigDependent, "IPS / AV profile"),
		FileHash:  s(SourceSyslog, ConfigDependent, "AV profile"),
		AdminUser: syslogFull, AdminSrcIP: syslogFull, AdminMethod: syslogFull,
		TunnelName: syslogFull, TunnelPeer: syslogFull, ConfigPath: syslogFull, ConfigOld: syslogFull,
		WANName: s(SourceSyslog, ConfigDependent, "SD-WAN health-check logging"), MetricValue: s(SourceSyslog, ConfigDependent, "SD-WAN health-check logging"),
	}})

	perPacket := "pf filterlog is per packet: no session bytes, duration, user or application"
	logged := "only rules with logging enabled"
	for _, v := range []string{"opnsense", "pfsense"} {
		register(Profile{Vendor: v, Fields: map[Field]Spec{
			Action: s(SourceSyslog, ConfigDependent, logged), SrcIP: syslogFull, DstIP: syslogFull, SrcPort: syslogFull, DstPort: syslogFull,
			Proto: syslogFull, SrcIf: syslogFull,
			RuleKey: s(SourceSyslog, ConfigDependent, logged), RuleUID: s(SourceSyslog, ConfigDependent, logged), RuleID: s(SourceSyslog, ConfigDependent, logged),
			RuleName: s(SourceAPI, ConfigDependent, "name resolved from the rule tracker via config.xml, not in the log"),
			BytesOut: s(SourceNetFlow, Full, perPacket), BytesIn: s(SourceNetFlow, Full, perPacket),
			AdminUser: s(SourceSyslog, Partial, "sshd / web GUI authentication lines"), AdminSrcIP: s(SourceSyslog, Partial, "sshd lines"), AdminMethod: s(SourceSyslog, Partial, "sshd lines"),
			TunnelName: s(SourceSyslog, Partial, "strongSwan charon text"), TunnelPeer: s(SourceSyslog, Partial, "strongSwan / OpenVPN daemon text"),
			User: s(SourceSyslog, Partial, "OpenVPN client connects only"),
		}})
	}

	untested := "untested on real hardware — built from vendor documentation"
	nfLogged := "netfilter LOG prefix: only rules with the Syslog toggle; per packet"
	// Every CEF-sourced cell is config_dependent: the SIEM integration
	// (Settings > Control Plane > Integrations, Network 8.5+) must be enabled.
	siem := "SIEM integration (CEF) must be enabled; "
	register(Profile{Vendor: "unifi", Hardware: untested, Fields: map[Field]Spec{
		Action: s(SourceSyslog, ConfigDependent, nfLogged), SrcIP: syslogFull, DstIP: syslogFull, SrcPort: syslogFull, DstPort: syslogFull,
		Proto: syslogFull, SrcMAC: s(SourceSyslog, Partial, "netfilter MAC= field and CEF client events"), SrcIf: s(SourceSyslog, ConfigDependent, nfLogged),
		SrcZone: s(SourceSyslog, ConfigDependent, siem+"CEF 201 only"),
		RuleKey: s(SourceSyslog, ConfigDependent, nfLogged), RuleIndex: s(SourceSyslog, ConfigDependent, nfLogged), RuleName: s(SourceSyslog, Partial, "netfilter DESCR (truncated) and CEF 201 policy name"),
		Ruleset: s(SourceSyslog, ConfigDependent, nfLogged),
		App:     s(SourceSyslog, ConfigDependent, siem+"CEF 201 only"), SrcHostname: s(SourceSyslog, Partial, "CEF client events and DHCP leases"),
		BytesOut: s(SourceNetFlow, Partial, "IPFIX on supported gateways (sampled); CEF 201 per IPS flow"), BytesIn: s(SourceNetFlow, Partial, "IPFIX on supported gateways (sampled); CEF 201 per IPS flow"),
		SessionID: s(SourceSyslog, ConfigDependent, siem+"CEF 201 only"),
		DNSQName:  s(SourceSyslog, ConfigDependent, "dnsmasq query logging"),
		Severity:  s(SourceSyslog, ConfigDependent, siem+"CEF header"),
		SigID:     s(SourceSyslog, Partial, siem+"CEF 201 IPS/IDS hits carry a signature id; blocklist and honeypot hits do not"),
		SigName:   s(SourceSyslog, Partial, siem+"CEF 201 IPS/IDS signature, else the CEF event name"),
		AdminUser: s(SourceSyslog, ConfigDependent, siem+"CEF 544 successes; failures unverified"), AdminSrcIP: s(SourceSyslog, ConfigDependent, siem+"CEF 544"), AdminMethod: s(SourceSyslog, ConfigDependent, siem+"CEF 544"),
		ConfigPath: s(SourceSyslog, ConfigDependent, siem+"UniFi OS CEF 1005 free text"), ConfigOld: s(SourceSyslog, ConfigDependent, siem+"UniFi OS CEF 1005 free text"),
		WANName: s(SourceSyslog, ConfigDependent, siem+"CEF 100/112/113"), MetricValue: s(SourceSyslog, Partial, siem+"CEF 112 (latency) only; 113 carries no loss figure"),
	}})

	flagged := "only L3 rules with the Syslog box checked; per flow, no bytes"
	register(Profile{Vendor: "meraki", Hardware: untested, Fields: map[Field]Spec{
		Action: s(SourceSyslog, ConfigDependent, flagged), SrcIP: syslogFull, DstIP: syslogFull, SrcPort: syslogFull, DstPort: syslogFull,
		Proto: syslogFull, SrcMAC: s(SourceSyslog, Partial, "LAN-side client only"),
		RuleKey: s(SourceSyslog, ConfigDependent, flagged), RuleName: s(SourceSyslog, ConfigDependent, "rule text (`pattern:`), no id"),
		Ruleset: s(SourceSyslog, Partial, "vpn_firewall / cellular_firewall roles only"),
		User:    s(SourceAPI, Partial, "clients API (802.1X / splash)"), App: s(SourceAPI, Partial, "traffic API aggregates only"),
		SrcHostname: s(SourceAPI, Full, "clients API"), OSName: s(SourceAPI, Full, "clients API"),
		BytesOut: s(SourceNetFlow, Full, "NetFlow v9 (reverse counters)"), BytesIn: s(SourceNetFlow, Full, "NetFlow v9 (reverse counters)"),
		URLHost:  s(SourceSyslog, ConfigDependent, "urls role"),
		Severity: syslogFull, SigID: s(SourceSyslog, Full, "ids-alerts / security_event"), SigName: s(SourceSyslog, Full, "ids-alerts / security_event"),
		FileHash:  s(SourceSyslog, Full, "security_event file scanned"),
		AdminUser: s(SourceAPI, Full, "configurationChanges API; not in syslog"), ConfigPath: s(SourceAPI, Full, "configurationChanges API"), ConfigOld: s(SourceAPI, Full, "configurationChanges API"),
		TunnelName: s(SourceSyslog, Full, "events vpn_connectivity_change"), TunnelPeer: s(SourceSyslog, Full, "events vpn_connectivity_change / client VPN"),
		WANName: s(SourceSyslog, Partial, "events failover text; uplink metrics are API"), MetricValue: s(SourceAPI, Full, "uplink loss / latency API"),
	}})

	register(Profile{Vendor: "generic", Fields: map[Field]Spec{
		Action: s(SourceSyslog, Partial, "CEF act= / filterlog / k=v action="), SrcIP: s(SourceSyslog, Partial, "CEF / filterlog / k=v"), DstIP: s(SourceSyslog, Partial, "CEF / filterlog / k=v"),
		SrcPort: s(SourceSyslog, Partial, ""), DstPort: s(SourceSyslog, Partial, ""), Proto: s(SourceSyslog, Partial, ""),
		RuleKey: s(SourceSyslog, Partial, "filterlog tracker / k=v rule id"), RuleID: s(SourceSyslog, Partial, "filterlog / k=v"), RuleUID: s(SourceSyslog, Partial, "filterlog tracker"),
		SigID: s(SourceSyslog, Partial, "CEF header"), SigName: s(SourceSyslog, Partial, "CEF header"), Severity: s(SourceSyslog, Partial, "CEF header"),
		User: s(SourceSyslog, Partial, "CEF suser / k=v user"), App: s(SourceSyslog, Partial, "CEF app"), URLHost: s(SourceSyslog, Partial, "CEF request"),
	}})
}
