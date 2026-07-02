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
	"sort"
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

// Matcher holds the parsed threat-intel prefixes. Build one with New and look up
// with Match. It is read-only; refresh by building a new Matcher.
//
// M4 of the 2026-07-01 audit: the pre-fix Matcher was a flat slice scanned to
// the end on every miss (the overwhelmingly common case) — with the default
// feed bundle's tens of thousands of prefixes, and Match called twice per flow
// sample synchronously in the ingest handler, that burned a full CPU core at a
// few thousand samples/sec. Prefixes are now bucketed by bit length into maps
// keyed on the masked prefix: a lookup masks the address to each distinct
// length present in the feed and does one map probe per length — O(#distinct
// lengths), a handful in practice, independent of feed size. Lengths are
// probed longest-first, so the MOST SPECIFIC prefix wins (the old slice
// returned insertion order).
type Matcher struct {
	by4   map[int]map[netip.Prefix]Hit // IPv4 prefixes, bucketed by prefix length
	lens4 []int                        // distinct IPv4 lengths, descending
	by6   map[int]map[netip.Prefix]Hit
	lens6 []int
	count int
}

// New builds a Matcher from threat-intel rows, skipping expired entries (as of
// `now`) and rows whose CIDR doesn't parse (a bare IP is accepted as /32 or
// /128). A nil/empty input yields an empty matcher that matches nothing.
// Duplicate prefixes keep the first occurrence's metadata.
func New(rows []models.ThreatIntel, now time.Time) *Matcher {
	m := &Matcher{
		by4: make(map[int]map[netip.Prefix]Hit),
		by6: make(map[int]map[netip.Prefix]Hit),
	}
	for _, r := range rows {
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue // expired
		}
		p, ok := parsePrefix(r.CIDR)
		if !ok {
			continue
		}
		buckets := m.by4
		if p.Addr().Is6() {
			buckets = m.by6
		}
		bl := p.Bits()
		bucket := buckets[bl]
		if bucket == nil {
			bucket = make(map[netip.Prefix]Hit)
			buckets[bl] = bucket
		}
		if _, dup := bucket[p]; dup {
			continue // first occurrence wins (matches the old scan order)
		}
		bucket[p] = Hit{Category: r.Category, Severity: r.Severity}
		m.count++
	}
	m.lens4 = sortedLensDesc(m.by4)
	m.lens6 = sortedLensDesc(m.by6)
	return m
}

// sortedLensDesc returns the bucket map's keys sorted descending, so lookups
// probe the most specific prefix length first.
func sortedLensDesc(buckets map[int]map[netip.Prefix]Hit) []int {
	lens := make([]int, 0, len(buckets))
	for l := range buckets {
		lens = append(lens, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(lens)))
	return lens
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

// Match reports whether ip falls inside any threat prefix, returning the most
// specific matching entry's metadata. Nil-safe and allocation-free on the
// lookup path: one map probe per distinct prefix length in the feed (M4).
func (m *Matcher) Match(ip string) (Hit, bool) {
	if m == nil || m.count == 0 {
		return Hit{}, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Hit{}, false
	}
	addr = addr.Unmap() // 4-in-6 forms match the IPv4 buckets
	buckets, lens := m.by4, m.lens4
	if addr.Is6() {
		buckets, lens = m.by6, m.lens6
	}
	for _, bl := range lens {
		p, err := addr.Prefix(bl) // addr masked to bl bits
		if err != nil {
			continue
		}
		if hit, ok := buckets[bl][p]; ok {
			return hit, true
		}
	}
	return Hit{}, false
}

// Len returns the number of active prefixes (for status reporting).
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return m.count
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
