package handlers

import (
	"container/list"
	"context"
	"log"
	"net/netip"
	"sync"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/deny"
	"firewall-mon/internal/metrics"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
	"firewall-mon/internal/relay"
)

// Syslog normalization on the ingest path (Phase 1, S-4).
//
// ReceiveSyslogMessages saves the raw rows FIRST (SaveSyslogMessages fills
// each row's ID, which becomes raw_id) and only then calls normalizeIngest,
// so nothing in here can lose a raw syslog row: every failure below is logged
// and counted, never returned to the collector. One normalize.Normalize per
// message feeds four consumers from the same Event — the rule engine
// (ProcessSyslogEvent, no second parse), the deny projection
// (deny.FromEvent; denied_events keeps being written through Phase 1, an
// operator decision), the typed tables (net_events by COPY, sec_events) and
// the two catalog tables (fw_rules through a per-key window so a hot rule is
// upserted once per fwRuleSeenTTL, device_field_observed through an
// in-memory counter buffer flushed every observedFlushInterval).
//
// NORMALIZE_ENABLED=false (config.Normalize.Disabled) takes the pre-0.11.296
// path instead — the rule engine parses for itself and deny.ProjectVendor
// scans per vendor — which is the rollback-by-config the plan asks for.

const (
	// observedFlushInterval is how often the in-memory observed-field
	// counters reach device_field_observed (RunObservedFlusher).
	observedFlushInterval = 5 * time.Minute
	// observedMaxKeys bounds the counter buffer at (device, class) pairs —
	// six classes per device, so this covers ~700 devices between flushes.
	// Past the cap new pairs are not recorded until the next flush (logged
	// once); existing pairs keep counting.
	observedMaxKeys = 4096
	// fwRuleSeenTTL is how long a (device, rule_key) counts as recently
	// upserted: fw_rules.last_seen is therefore at most this stale.
	fwRuleSeenTTL = 5 * time.Minute
	// fwRuleSeenMax bounds the fw_rules window; the least recently seen key
	// is evicted (and simply upserted again on its next event).
	fwRuleSeenMax = 16384
	// denyCollapseWindow: a per-PACKET deny log (UniFi netfilter) writes one
	// line per packet, so one blocked TCP connect is 3-5 lines of SYN retries
	// over ~2 s. deny_victim / deny_storm count denied_events rows, and a
	// FortiGate or pf session log would have contributed ONE row for the same
	// attempt, so identical netfilter 5-tuples within this window project
	// once. net_events keeps every packet row (nothing is dropped from
	// storage); only the detector projection is collapsed.
	denyCollapseWindow = 2 * time.Second
	// denyCollapseMax bounds the collapse window's key set.
	denyCollapseMax = 65536
	// normalizeIngestStartedSetting is written once, on the first batch that
	// landed normalized rows: the S-5 backfill's default upper bound, so the
	// backfill and live ingest never cover the same raw rows. Insert-only —
	// it is never overwritten (InsertSettingIfAbsent).
	normalizeIngestStartedSetting = "normalize_ingest_started_at"
)

// normalizeIngest derives every normalized consumer's input from one saved
// batch (see the file comment). probe carries the negotiated schema version:
// a framing-contract (v6) probe's rows skip the re-framing join.
func (h *Handler) normalizeIngest(msgs []models.SyslogMessage, probe *models.Probe) {
	framed := probe != nil && probe.SchemaVersion >= relay.SchemaVersionFramed
	cfg := deny.PatternConfig{Pattern: h.denyPolicyPattern()}
	now := time.Now()
	var (
		// Sized for the dominant shape: a FortiGate `logtraffic all` batch is
		// all network class; the other slices stay small.
		nets       = make([]models.NetEvent, 0, len(msgs))
		secs       []models.SecEvent
		denied     []models.DeniedEvent
		rules      []models.FwRule
		batchRules map[fwRuleKey]struct{}
		nOK        int
		nUnp       int
		nNoFam     int
		nUnsaved   int
	)
	for i := range msgs {
		msg := &msgs[i]
		vendor := h.deviceVendor(msg.DeviceID)
		var (
			ev  normalize.Event
			out normalize.Outcome
		)
		if framed {
			ev, out = normalize.NormalizeFramed(vendor, msg)
		} else {
			ev, out = normalize.Normalize(vendor, msg)
		}
		// The rule engine sees every message (an Unparsed line still exposes
		// its native tokens through FieldsFromEvent). Its chain fast path
		// makes this free when no rule is loaded.
		if h.alertManager != nil {
			if err := h.alertManager.ProcessSyslogEvent(msg, nil, &ev, out); err != nil {
				log.Printf("Failed to process syslog alert: %v", err)
			}
		}
		switch out.Kind {
		case normalize.OutcomeOK:
			nOK++
		case normalize.OutcomeUnparsed:
			nUnp++
			continue
		default:
			nNoFam++
			continue
		}
		// A row the raw save's per-row fallback dropped has no ID: nothing
		// derived from it may be stored (raw_id would be NULL and the backfill
		// could not reconcile it), so it stops here.
		if msg.ID == 0 {
			nUnsaved++
			continue
		}
		if de, ok := deny.FromEvent(&ev, &h.threatMatch, cfg); ok && !h.collapsePacketDeny(&ev, out.Family) {
			denied = append(denied, de)
		}
		rawID := int64(msg.ID)
		if ev.Class == normalize.ClassNetwork {
			nets = append(nets, database.NetEventFromEvent(&ev, rawID, msg.Timestamp))
		} else {
			secs = append(secs, database.SecEventFromEvent(&ev, rawID, msg.Timestamp))
		}
		if msg.DeviceID == 0 {
			continue // no device, no capability row and no rule catalog entry
		}
		h.observed.record(msg.DeviceID, ev.Class, ev.Present(), now)
		if r, ok := database.FwRuleFromEvent(&ev, ev.Ts); ok {
			k := fwRuleKey{dev: msg.DeviceID, rk: ev.RuleKey}
			if _, dup := batchRules[k]; !dup && !h.fwRuleSeen.recent(k, now) {
				if batchRules == nil {
					batchRules = make(map[fwRuleKey]struct{})
				}
				batchRules[k] = struct{}{}
				rules = append(rules, r)
			}
		}
	}
	metrics.AddNormalizeOutcome("ok", nOK)
	metrics.AddNormalizeOutcome("unparsed", nUnp)
	metrics.AddNormalizeOutcome("no_family", nNoFam)
	metrics.AddNormalizeOutcome("unsaved", nUnsaved)
	if h.db == nil {
		return
	}
	if len(denied) > 0 {
		if err := h.db.SaveDeniedEvents(denied); err != nil {
			log.Printf("normalizeIngest: save %d denied event(s): %v", len(denied), err)
		}
	}
	landed := false
	if len(nets) > 0 {
		if err := h.db.SaveNetEvents(nets); err != nil {
			metrics.IncNormalizeWriteError("net_events")
			log.Printf("normalizeIngest: save %d net_events row(s): %v", len(nets), err)
		} else {
			metrics.AddNormalizeRows("net_events", len(nets))
			landed = true
		}
	}
	if len(secs) > 0 {
		if err := h.db.SaveSecEvents(secs); err != nil {
			metrics.IncNormalizeWriteError("sec_events")
			log.Printf("normalizeIngest: save %d sec_events row(s): %v", len(secs), err)
		} else {
			metrics.AddNormalizeRows("sec_events", len(secs))
			landed = true
		}
	}
	if len(rules) > 0 {
		if err := h.db.UpsertFwRules(rules); err != nil {
			// Not marked as seen: the next batch retries these keys.
			metrics.IncNormalizeWriteError("fw_rules")
			log.Printf("normalizeIngest: upsert %d fw_rules row(s): %v", len(rules), err)
		} else {
			metrics.AddNormalizeRows("fw_rules", len(rules))
			for k := range batchRules {
				h.fwRuleSeen.mark(k, now)
			}
		}
	}
	if landed {
		h.markNormalizeIngestStarted(now)
	}
}

// denyTuple is the collapse key for per-packet deny logs: one blocked
// connection attempt is one (device, 5-tuple).
type denyTuple struct {
	dev          uint
	src, dst     netip.Addr
	sport, dport int32
	proto        int16
}

// collapsePacketDeny reports whether this deny is a repeat of an identical
// per-packet deny seen within denyCollapseWindow (see the constant). Only
// the netfilter family logs per packet without a session abstraction;
// filterlog rows are per packet too but ProjectVendor always projected them
// one-to-one and the deny parity with it is kept.
func (h *Handler) collapsePacketDeny(ev *normalize.Event, fam normalize.Family) bool {
	if fam != normalize.FamilyNetfilter || ev.Activity != normalize.ActivityPacket {
		return false
	}
	k := denyTuple{dev: ev.DeviceID}
	k.src, _ = netip.AddrFromSlice(ev.SrcIP)
	k.dst, _ = netip.AddrFromSlice(ev.DstIP)
	if ev.SrcPort != nil {
		k.sport = *ev.SrcPort
	}
	if ev.DstPort != nil {
		k.dport = *ev.DstPort
	}
	if ev.Proto != nil {
		k.proto = *ev.Proto
	}
	if h.denyCollapse.recent(k, ev.Ts) {
		return true
	}
	h.denyCollapse.mark(k, ev.Ts)
	return false
}

// markNormalizeIngestStarted records normalizeIngestStartedSetting once per
// database. The write is insert-only (ON CONFLICT DO NOTHING), so neither a
// restart nor a transient read failure can move the watermark off the FIRST
// normalized batch — the S-5 backfill's upper bound. The in-process flag is
// set only after the insert statement succeeded (inserted, or found the row
// already there), so a failed write is retried on the next batch.
func (h *Handler) markNormalizeIngestStarted(now time.Time) {
	if h.normalizeStarted.Load() {
		return
	}
	_, err := h.db.InsertSettingIfAbsent(&models.SystemSetting{
		Key:      normalizeIngestStartedSetting,
		Value:    now.UTC().Format(time.RFC3339),
		Type:     "string",
		Label:    "Normalized ingest started at",
		Category: "normalize",
	})
	if err != nil {
		log.Printf("normalizeIngest: record %s: %v", normalizeIngestStartedSetting, err)
		return
	}
	h.normalizeStarted.Store(true)
}

// FlushFieldObserved drains the observed-field counters into
// device_field_observed. Called by RunObservedFlusher, by main after the HTTP
// server has drained at shutdown, and by tests; safe to call any time (a
// failed flush puts the rows back so they are retried).
func (h *Handler) FlushFieldObserved() {
	rows := h.observed.drain()
	if len(rows) == 0 || h.db == nil {
		return
	}
	if err := h.db.FlushFieldObserved(rows); err != nil {
		metrics.IncNormalizeWriteError("device_field_observed")
		log.Printf("normalizeIngest: flush %d device_field_observed row(s): %v", len(rows), err)
		h.observed.restore(rows)
		return
	}
	metrics.AddNormalizeRows("device_field_observed", len(rows))
}

// RunObservedFlusher flushes every observedFlushInterval until ctx is done,
// flushes once more and returns. The caller (cmd/api) waits for it to return
// and flushes again after the HTTP server has drained, since requests still
// in flight at cancellation record after this loop's last pass.
func (h *Handler) RunObservedFlusher(ctx context.Context) {
	ticker := time.NewTicker(observedFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.FlushFieldObserved()
		case <-ctx.Done():
			h.FlushFieldObserved()
			return
		}
	}
}

// ── observed-field counter buffer ─────────────────────────────────────────────

type observedKey struct {
	dev   uint
	class normalize.Class
}

type observedEntry struct {
	counts [len(normalize.ObservedFields)]int64
	last   time.Time
}

// observedBuffer accumulates per-(device, class) field counts between
// flushes: one fixed-size array per pair (no per-message allocation) and a
// hard cap on pairs, so a batch from an unknown number of devices cannot
// grow it without bound.
type observedBuffer struct {
	mu        sync.Mutex
	m         map[observedKey]*observedEntry
	capLogged bool
}

func (b *observedBuffer) record(dev uint, class normalize.Class, p normalize.Presence, at time.Time) {
	if p == 0 {
		return
	}
	k := observedKey{dev: dev, class: class}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[k]
	if e == nil {
		if len(b.m) >= observedMaxKeys {
			if !b.capLogged {
				b.capLogged = true
				log.Printf("normalizeIngest: observed-field buffer at its %d-pair cap; new (device, class) pairs are not counted until the next flush", observedMaxKeys)
			}
			return
		}
		if b.m == nil {
			b.m = make(map[observedKey]*observedEntry)
		}
		e = &observedEntry{}
		b.m[k] = e
	}
	for i := range normalize.ObservedFields {
		if p.Has(i) {
			e.counts[i]++
		}
	}
	if at.After(e.last) {
		e.last = at
	}
}

// drain swaps the buffer out and returns its contents as upsert rows.
func (b *observedBuffer) drain() []models.DeviceFieldObserved {
	b.mu.Lock()
	m := b.m
	b.m = nil
	b.capLogged = false
	b.mu.Unlock()
	if len(m) == 0 {
		return nil
	}
	rows := make([]models.DeviceFieldObserved, 0, len(m)*8)
	for k, e := range m {
		for i, n := range e.counts {
			if n == 0 {
				continue
			}
			rows = append(rows, models.DeviceFieldObserved{
				DeviceID: k.dev,
				Class:    int16(k.class),
				Field:    normalize.ObservedFields[i],
				Count:    n,
				LastSeen: e.last,
			})
		}
	}
	return rows
}

// restore puts drained rows back after a failed flush (bounded by the same
// cap; rows for pairs past it are dropped — the next events recreate them).
func (b *observedBuffer) restore(rows []models.DeviceFieldObserved) {
	idx := make(map[string]int, len(normalize.ObservedFields))
	for i, f := range normalize.ObservedFields {
		idx[f] = i
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = make(map[observedKey]*observedEntry)
	}
	for _, r := range rows {
		i, ok := idx[r.Field]
		if !ok {
			continue
		}
		k := observedKey{dev: r.DeviceID, class: normalize.Class(r.Class)}
		e := b.m[k]
		if e == nil {
			if len(b.m) >= observedMaxKeys {
				continue
			}
			e = &observedEntry{}
			b.m[k] = e
		}
		e.counts[i] += r.Count
		if r.LastSeen.After(e.last) {
			e.last = r.LastSeen
		}
	}
}

// ── recently-seen key window (fw_rules dedup, per-packet deny collapse) ───────

type fwRuleKey struct {
	dev uint
	rk  string
}

type recentEntry[K comparable] struct {
	key    K
	expiry time.Time
}

// recentKeys remembers keys for a fixed window (ttl) and holds at most max
// of them, evicting the least recently touched. Two-phase on purpose: recent
// asks, mark records — so a caller can mark only after the write the key
// stands for succeeded (fw_rules), and a repeat inside the window does not
// extend it (a steady SYN-retry stream still projects once per window).
// Zero value ready except for ttl / max, which NewHandler sets.
type recentKeys[K comparable] struct {
	ttl time.Duration
	max int

	mu sync.Mutex
	ll *list.List
	m  map[K]*list.Element
}

// recent reports whether key was marked less than ttl ago. Touching it keeps
// it from eviction; it does not insert or extend.
func (r *recentKeys[K]) recent(key K, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.m[key]
	if !ok {
		return false
	}
	r.ll.MoveToFront(el)
	return now.Before(el.Value.(*recentEntry[K]).expiry)
}

// mark records key as seen at now (window restarts), evicting the least
// recently touched keys past max.
func (r *recentKeys[K]) mark(key K, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = make(map[K]*list.Element)
		r.ll = list.New()
	}
	if el, ok := r.m[key]; ok {
		el.Value.(*recentEntry[K]).expiry = now.Add(r.ttl)
		r.ll.MoveToFront(el)
		return
	}
	for r.max > 0 && r.ll.Len() >= r.max {
		back := r.ll.Back()
		delete(r.m, back.Value.(*recentEntry[K]).key)
		r.ll.Remove(back)
	}
	r.m[key] = r.ll.PushFront(&recentEntry[K]{key: key, expiry: now.Add(r.ttl)})
}

// size is the number of keys held (tests).
func (r *recentKeys[K]) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}
