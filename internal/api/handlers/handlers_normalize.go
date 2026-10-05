package handlers

import (
	"container/list"
	"context"
	"log"
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
// the two catalog tables (fw_rules through a per-key LRU so a hot rule is
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
	// fwRuleSeenTTL is how long a (device, rule_key) stays in the LRU after
	// an upsert: fw_rules.last_seen is therefore at most this stale.
	fwRuleSeenTTL = 5 * time.Minute
	// fwRuleSeenMax bounds the LRU; the least recently seen key is evicted
	// (and simply upserted again on its next event).
	fwRuleSeenMax = 16384
	// normalizeIngestStartedSetting is written once, on the first batch that
	// landed normalized rows: the S-5 backfill's default upper bound, so the
	// backfill and live ingest never cover the same raw rows.
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
		nets   []models.NetEvent
		secs   []models.SecEvent
		denied []models.DeniedEvent
		rules  []models.FwRule
		nOK    int
		nUnp   int
		nNoFam int
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
		if de, ok := deny.FromEvent(&ev, &h.threatMatch, cfg); ok {
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
		if r, ok := database.FwRuleFromEvent(&ev, ev.Ts); ok && h.fwRuleSeen.allow(fwRuleKey{dev: msg.DeviceID, rk: ev.RuleKey}, now) {
			rules = append(rules, r)
		}
	}
	metrics.AddNormalizeOutcome("ok", nOK)
	metrics.AddNormalizeOutcome("unparsed", nUnp)
	metrics.AddNormalizeOutcome("no_family", nNoFam)
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
			metrics.IncNormalizeWriteError("fw_rules")
			log.Printf("normalizeIngest: upsert %d fw_rules row(s): %v", len(rules), err)
		} else {
			metrics.AddNormalizeRows("fw_rules", len(rules))
		}
	}
	if landed {
		h.markNormalizeIngestStarted(now)
	}
}

// markNormalizeIngestStarted writes normalizeIngestStartedSetting once per
// database (never overwritten: the watermark must stay at the FIRST normalized
// batch, or a restart would open a gap the backfill does not cover). The
// in-process flag is set only after the row is known to exist, so a failed
// write is retried on the next batch.
func (h *Handler) markNormalizeIngestStarted(now time.Time) {
	if h.normalizeStarted.Load() {
		return
	}
	if _, ok := h.db.GetSettingValue(normalizeIngestStartedSetting); ok {
		h.normalizeStarted.Store(true)
		return
	}
	err := h.db.UpsertSetting(&models.SystemSetting{
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
// device_field_observed. Called by RunObservedFlusher and at shutdown; safe
// to call any time (a failed flush puts the rows back so they are retried).
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
// then once more so a clean shutdown loses nothing.
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

// ── fw_rules per-key LRU ──────────────────────────────────────────────────────

type fwRuleKey struct {
	dev uint
	rk  string
}

type fwRuleSeenEntry struct {
	key    fwRuleKey
	expiry time.Time
}

// fwRuleLRU remembers which (device, rule_key) pairs were upserted into
// fw_rules within fwRuleSeenTTL so the catalog is not rewritten for every
// hit of a hot rule (a `logtraffic all` FortiGate hits its top policies
// thousands of times a minute). Bounded at fwRuleSeenMax entries by
// least-recent eviction; an evicted or expired key is simply allowed again.
// Zero value ready.
type fwRuleLRU struct {
	mu sync.Mutex
	ll *list.List
	m  map[fwRuleKey]*list.Element
}

// allow reports whether key should be upserted now (not seen, or seen longer
// than fwRuleSeenTTL ago) and records it as seen when so.
func (l *fwRuleLRU) allow(key fwRuleKey, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = make(map[fwRuleKey]*list.Element)
		l.ll = list.New()
	}
	if el, ok := l.m[key]; ok {
		e := el.Value.(*fwRuleSeenEntry)
		l.ll.MoveToFront(el)
		if now.Before(e.expiry) {
			return false
		}
		e.expiry = now.Add(fwRuleSeenTTL)
		return true
	}
	for l.ll.Len() >= fwRuleSeenMax {
		back := l.ll.Back()
		delete(l.m, back.Value.(*fwRuleSeenEntry).key)
		l.ll.Remove(back)
	}
	l.m[key] = l.ll.PushFront(&fwRuleSeenEntry{key: key, expiry: now.Add(fwRuleSeenTTL)})
	return true
}

// size is the number of keys held (tests).
func (l *fwRuleLRU) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
