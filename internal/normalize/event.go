package normalize

import (
	"net"
	"net/netip"
	"time"
)

// Event is the one vendor-neutral record every syslog line normalizes into
// (roadmap §1.1-1.2). Column semantics:
//
//   - a pointer field is NULL when nil ("the vendor did not supply it") and a
//     supplied zero otherwise; a string field is NULL when empty; a net.IP /
//     net.HardwareAddr is NULL when nil;
//   - Class decides which table the row lands in later (network → net_events,
//     everything else → sec_events) — S-2 stores nothing, it only produces
//     the struct and the `event.*` rule view;
//   - Native is the vendor's own key→value tokens exactly as logfields has
//     always exposed them to rules (FortiOS kv pairs, filterlog columns, CEF
//     extension keys …); Extra holds the few vendor leftovers the typed
//     columns cannot carry (country names that did not map, FortiGate
//     service/subtype) and is what S-3 persists as `extra jsonb`.
//
// Pointer and address fields are carved out of small per-Event slabs (arena)
// rather than boxed one by one: a FortiOS traffic line fills ~15 of them, and
// the rule engine calls Normalize for every message a rule set is loaded
// for, so each box would be one garbage object per message. The slabs are
// append-only and never mutated after mapping, so copying an Event (it is
// returned by value) keeps every pointer valid.
type Event struct {
	Class         Class
	Activity      Activity
	Action        Action
	VendorEventID string // FortiOS logid / UniFi CEF id or chain / Meraki category / pf "filterlog"
	Ts            time.Time
	DeviceID      uint
	ProbeID       uint

	// endpoints
	SrcIP, DstIP     net.IP
	SrcPort, DstPort *int32
	Proto            *int16
	SrcMAC, DstMAC   net.HardwareAddr
	SrcIf, DstIf     string
	SrcZone, DstZone string
	SrcRole, DstRole *Role
	Direction        *Direction

	// rule (roadmap §1.3)
	RuleKey   string
	RuleUID   string
	RuleID    *int64
	RuleName  string
	RuleIndex *int32
	Ruleset   string // FortiGate vd= (VDOM), UniFi chain, Meraki firewall ruleset

	// identity & app
	User, Group        string
	App, AppCat        string
	AppRisk            *int16
	DevType, OSName    string
	SrcHostname        string
	BytesOut, BytesIn  *int64
	PktsOut, PktsIn    *int64
	DurationMS         *int32
	SessionID          string
	NatSrcIP, NatDstIP net.IP
	NatSrcPort         *int32
	NatDstPort         *int32

	// geo / threat
	SrcCountry, DstCountry string // ISO 3166-1 alpha-2
	ThreatFlag             int16

	// web / dns
	URLHost, URLPath string
	DNSQName         string
	DNSQType         *int16
	WebCat           string

	// sec_events columns
	Severity               *int16 // 0-10, CEF scale
	SigID, SigName         string
	ThreatCat, FileHash    string
	AdminUser, AdminSrcIP  string
	AdminMethod            string // gui / ssh / api / console / cloud
	TunnelName, TunnelType string
	TunnelPeer             net.IP
	ConfigPath, ConfigObj  string
	ConfigOld, ConfigNew   string
	WANName, MetricName    string
	MetricValue            *float64
	Message                string

	Extra  map[string]string
	Native map[string]string

	arena
}

// arena is the Event's slab storage for pointer-typed columns and
// addresses: one heap object per Event, lazily allocated, holding every
// *int64 / *int32 / *int16 and net.IP the mappers fill. When a slab is
// exhausted (no vendor line comes close) the constructors fall back to
// boxing the value individually.
type arena struct {
	slab *slab
}

type slab struct {
	n64                [10]int64
	n32                [12]int32
	n16                [8]int16
	ips                [6][16]byte
	c64, c32, c16, cip int
}

func (e *Event) s() *slab {
	if e.slab == nil {
		e.slab = new(slab)
	}
	return e.slab
}

// OutcomeKind says what Normalize made of a line.
type OutcomeKind uint8

const (
	// OutcomeOK: a family tokenized the line and the vendor mapper produced an
	// Event.
	OutcomeOK OutcomeKind = iota
	// OutcomeUnparsed: a family tokenized the line (Native is populated) but
	// the mapper has no mapping for it; Reason names the gap, e.g.
	// "fortigate: event/router not mapped".
	OutcomeUnparsed
	// OutcomeNoFamily: none of the vendor's families recognised the line
	// (Native is nil).
	OutcomeNoFamily
)

func (k OutcomeKind) String() string {
	switch k {
	case OutcomeOK:
		return "ok"
	case OutcomeUnparsed:
		return "unparsed"
	default:
		return "no_family"
	}
}

// Outcome is Normalize's verdict on one line.
type Outcome struct {
	Kind   OutcomeKind
	Reason string
}

func ok() Outcome { return Outcome{Kind: OutcomeOK} }

func unparsed(reason string) Outcome { return Outcome{Kind: OutcomeUnparsed, Reason: reason} }

// extra records a vendor leftover; nil-safe.
func (e *Event) extra(k, v string) {
	if v == "" {
		return
	}
	if e.Extra == nil {
		e.Extra = make(map[string]string, 4)
	}
	e.Extra[k] = v
}

// Slab constructors. Each returns a pointer into the Event's arena; a value
// parsed from an empty or non-numeric string stays nil so an absent vendor
// field is NULL rather than a supplied zero.

func (e *Event) p64(v int64) *int64 {
	s := e.s()
	if s.c64 == len(s.n64) {
		p := new(int64) // explicit box: a `return &v` here would heap-allocate v on EVERY call
		*p = v
		return p
	}
	s.n64[s.c64] = v
	s.c64++
	return &s.n64[s.c64-1]
}

func (e *Event) p32(v int32) *int32 {
	s := e.s()
	if s.c32 == len(s.n32) {
		p := new(int32) // explicit box: a `return &v` here would heap-allocate v on EVERY call
		*p = v
		return p
	}
	s.n32[s.c32] = v
	s.c32++
	return &s.n32[s.c32-1]
}

func (e *Event) p16(v int16) *int16 {
	s := e.s()
	if s.c16 == len(s.n16) {
		p := new(int16) // explicit box: a `return &v` here would heap-allocate v on EVERY call
		*p = v
		return p
	}
	s.n16[s.c16] = v
	s.c16++
	return &s.n16[s.c16-1]
}

func (e *Event) i64(s string) *int64 {
	n, ok := atoi(s)
	if !ok {
		return nil
	}
	return e.p64(n)
}

func (e *Event) i32(s string) *int32 {
	n, ok := atoi(s)
	if !ok || n < -2147483648 || n > 2147483647 {
		return nil
	}
	return e.p32(int32(n))
}

func (e *Event) i16(s string) *int16 {
	n, ok := atoi(s)
	if !ok || n < -32768 || n > 32767 {
		return nil
	}
	return e.p16(int16(n))
}

func (e *Event) port(s string) *int32 {
	n, ok := atoi(s)
	if !ok || n < 0 || n > 65535 {
		return nil
	}
	return e.p32(int32(n))
}

// ip parses an address into the arena; the result is in net.IP's 16-byte
// form for v4 and v6 alike, as net.ParseIP returns.
func (e *Event) ip(s string) net.IP {
	if s == "" {
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	if a.Zone() != "" {
		a = a.WithZone("")
	}
	sl := e.s()
	if sl.cip == len(sl.ips) {
		b := a.As16()
		return net.IP(b[:])
	}
	sl.ips[sl.cip] = a.As16()
	sl.cip++
	return net.IP(sl.ips[sl.cip-1][:])
}

func (e *Event) f64(s string) *float64 {
	if s == "" {
		return nil
	}
	var v, frac, scale float64 = 0, 0, 1
	neg, seenDot, digits := false, false, 0
	i := 0
	if s[0] == '-' {
		neg = true
		i++
	}
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			if seenDot {
				scale *= 10
				frac = frac*10 + float64(c-'0')
			} else {
				v = v*10 + float64(c-'0')
			}
		case c == '.' && !seenDot:
			seenDot = true
		default:
			return nil
		}
	}
	if digits == 0 {
		return nil
	}
	v += frac / scale
	if neg {
		v = -v
	}
	return &v
}

// atoi is a no-allocation decimal parser (strconv.Atoi's error path allocates
// on every non-numeric vendor value, and most vendor fields are not numeric).
func atoi(s string) (int64, bool) {
	if s == "" || len(s) > 19 {
		return 0, false
	}
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i++
		if len(s) == 1 {
			return 0, false
		}
	}
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}

func ptrRole(r Role) *Role          { return &r }
func ptrDir(d Direction) *Direction { return &d }

func parseMAC(s string) net.HardwareAddr {
	if s == "" {
		return nil
	}
	m, err := net.ParseMAC(s)
	if err != nil {
		return nil
	}
	return m
}

// splitHostPort splits "ip:port" (also "[v6]:port"); a bare address comes
// back with an empty port.
func splitHostPort(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	if s[0] == '[' {
		if end := indexByte(s, ']'); end > 0 {
			host := s[1:end]
			if end+1 < len(s) && s[end+1] == ':' {
				return host, s[end+2:]
			}
			return host, ""
		}
		return s, ""
	}
	// IPv6 without brackets has more than one ':' — treat as bare address.
	first := indexByte(s, ':')
	if first < 0 {
		return s, ""
	}
	if indexByte(s[first+1:], ':') >= 0 {
		return s, ""
	}
	return s[:first], s[first+1:]
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
