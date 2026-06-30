// Package threatintel provides an in-memory matcher for the known-bad address
// feed (models.ThreatIntel). It is consulted at ingest to flag flows whose
// source or destination falls inside a threat CIDR, without a per-row DB query.
//
// The matcher is immutable once built; refreshes construct a new matcher and the
// holder swaps it atomically, so lookups never lock. A nil *Matcher is safe and
// matches nothing, so callers don't branch on whether a feed is loaded.
package threatintel

import (
	"net/netip"
	"sync/atomic"
	"time"

	"firewall-mon/internal/models"
)

// Hit is what a successful match returns: the category and severity of the
// threat-intel entry that contained the address.
type Hit struct {
	Category string
	Severity string
}

// entry is a parsed prefix plus its metadata.
type entry struct {
	prefix netip.Prefix
	hit    Hit
}

// Matcher holds the parsed threat-intel prefixes. Build one with New and look up
// with Match. It is read-only; refresh by building a new Matcher.
type Matcher struct {
	entries []entry
}

// New builds a Matcher from threat-intel rows, skipping expired entries (as of
// `now`) and rows whose CIDR doesn't parse (a bare IP is accepted as /32 or
// /128). A nil/empty input yields an empty matcher that matches nothing.
func New(rows []models.ThreatIntel, now time.Time) *Matcher {
	m := &Matcher{entries: make([]entry, 0, len(rows))}
	for _, r := range rows {
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue // expired
		}
		p, ok := parsePrefix(r.CIDR)
		if !ok {
			continue
		}
		m.entries = append(m.entries, entry{
			prefix: p,
			hit:    Hit{Category: r.Category, Severity: r.Severity},
		})
	}
	return m
}

// parsePrefix accepts "10.0.0.0/8" or a bare "10.0.0.1" (treated as a host
// prefix). Returns ok=false on anything unparseable.
func parsePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// Match reports whether ip falls inside any threat prefix, returning the first
// matching entry's metadata. Nil-safe and allocation-free on the lookup path.
func (m *Matcher) Match(ip string) (Hit, bool) {
	if m == nil || len(m.entries) == 0 {
		return Hit{}, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Hit{}, false
	}
	for _, e := range m.entries {
		if e.prefix.Contains(addr) {
			return e.hit, true
		}
	}
	return Hit{}, false
}

// Len returns the number of active prefixes (for status reporting).
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.entries)
}

// Holder is a goroutine-safe container for the current Matcher, swapped
// atomically on refresh. The zero value holds a nil matcher (matches nothing).
type Holder struct {
	ptr atomic.Pointer[Matcher]
}

// Store atomically replaces the current matcher.
func (h *Holder) Store(m *Matcher) { h.ptr.Store(m) }

// Load returns the current matcher (may be nil; Match is nil-safe).
func (h *Holder) Load() *Matcher { return h.ptr.Load() }

// Match is a convenience that loads the current matcher and matches against it.
func (h *Holder) Match(ip string) (Hit, bool) { return h.Load().Match(ip) }

// Len returns the active prefix count of the current matcher.
func (h *Holder) Len() int { return h.Load().Len() }
