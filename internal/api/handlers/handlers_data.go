package handlers

import (
	"crypto/md5" // (gosec G501 excluded in CI: non-crypto config-change checksum)
	"encoding/hex"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/api/response"
	"firewall-mon/internal/classify"
	"firewall-mon/internal/configdiff"
	"firewall-mon/internal/deny"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/snmp"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// batchDedupCheck implements the AUDIT-042 idempotency check for probe batch
// endpoints. If the request carries an `X-Probe-Batch-ID` already recorded for
// this probe, it writes a 200 "deduped" response and returns dup=true (the
// caller must return immediately). Otherwise it returns the batch id (possibly
// "") for the caller to pass to markBatchIfOK via defer.
func (h *Handler) batchDedupCheck(c *gin.Context, probeID uint) (batchID string, dup bool) {
	batchID = c.GetHeader("X-Probe-Batch-ID")
	if batchID == "" || h.db == nil {
		return "", false
	}
	if h.db.BatchAlreadyProcessed(probeID, batchID) {
		c.JSON(http.StatusOK, response.Success(gin.H{"deduped": true, "saved": 0}))
		return "", true
	}
	return batchID, false
}

// markBatchIfOK records the idempotency key, but ONLY if the response was a 2xx
// (i.e. the batch actually saved). Recording on failure would dedupe-drop the
// collector's legitimate retry of a batch that never persisted. Call via defer.
func (h *Handler) markBatchIfOK(c *gin.Context, probeID uint, batchID string) {
	if batchID == "" || h.db == nil {
		return
	}
	if s := c.Writer.Status(); s >= 200 && s < 300 {
		if err := h.db.MarkBatchProcessed(probeID, batchID); err != nil {
			log.Printf("markBatchIfOK: probe %d batch %s: %v", probeID, batchID, err)
		}
	}
}

// truncateProbeBatch enforces a per-request item cap on an ingestion batch.
//
// M1 of the 2026-07-01 audit: the flows/counters/pings/interface paths
// truncated silently — `items = items[:1000]` with no log or alert — then
// returned 200 and marked the idempotency batch ID processed, so the
// collector's retry machinery could never resend the tail. Any operator who
// raised PROBE_MAX_BATCH_SIZE above the server cap lost every batch's tail
// permanently and invisibly. Every truncation is now logged, and (matching the
// pre-existing traps/syslog behavior) an operator-visible probe alert is
// recorded when the overshoot exceeds 20%. The collector additionally clamps
// PROBE_MAX_BATCH_SIZE to 1000 as of v1.2.155 so updated deployments never
// truncate at all.
func truncateProbeBatch[T any](h *Handler, probe *models.Probe, kind string, capN int, items []T) []T {
	if len(items) <= capN {
		return items
	}
	orig := len(items)
	items = items[:capN]
	log.Printf("%s: probe %d (%s) sent %d items; truncated to %d — the tail is DROPPED. Clamp PROBE_MAX_BATCH_SIZE <= %d on the collector.",
		kind, probe.ID, probe.Name, orig, capN, capN)
	if h.alertManager != nil && orig > capN+capN/5 {
		h.alertManager.RecordProbeDataTruncation(probe.ID, probe.Name, orig, capN)
	}
	return items
}

// bumpOnlineFreshness is how recent a device's freshest row must be for the
// bump to also mark it online. Mirrors the offline sweep's threshold floor
// (cmd/poller/main.go: max(3× poll interval, 5 min)); live rows arrive seconds
// after collection regardless of poll cadence, so this never blocks a
// legitimate re-online.
const bumpOnlineFreshness = 5 * time.Minute

// bumpDevicesOnline advances each device's last_polled to its freshest
// qualifying row timestamp (clamped to now: zero/future → now) and marks the
// device online ONLY when that evidence is fresh. Every relay handler that
// receives device-attributed telemetry the collector actively POLLED
// (SNMP/SSH/API) must call this after a successful save — the poller's
// DEVICE_OFFLINE sweep fires on a stale last_polled, so a handler that saves
// polled data without bumping makes a healthy device flap offline whenever the
// bumping data types happen to fail while others still deliver. Passive,
// device-pushed sources (syslog, traps, flow samples) intentionally do NOT
// bump: they prove the device is emitting, not that the collector can poll it.
//
// Timestamps are per device and the update is monotonic (the WHERE guard):
// after a server outage the collector drains hours of spooled batches while
// live traffic interleaves, and one drained ping batch can span hours and many
// devices — bumping with `now` (the pre-fix behavior) held a device that died
// mid-outage "online" for the whole drain window, and a batch-wide timestamp
// would let one device's fresh rows extend a dead sibling's evidence. Stale
// evidence advances the clock but never revives a device: without the
// freshness gate a drain batch would re-online a device the sweep already
// flipped offline, and every re-flip sends a dedup-free critical email.
// (The sweep's SELECT-then-UPDATE race can transiently leave a device offline
// WITH fresh last_polled; the next fresh batch heals it.)
func (h *Handler) bumpDevicesOnline(deviceTimes map[uint]time.Time, now time.Time) {
	for id, ts := range deviceTimes {
		if ts.IsZero() || ts.After(now) {
			ts = now
		}
		updates := map[string]interface{}{"last_polled": ts}
		if now.Sub(ts) < bumpOnlineFreshness {
			updates["status"] = "online"
		}
		// A silently failing bump reproduces the exact DEVICE_OFFLINE flap this
		// helper exists to prevent — log it so the failure is diagnosable.
		if err := h.db.Gorm().Model(&models.Device{}).
			Where("id = ? AND (last_polled IS NULL OR last_polled < ?)", id, ts).
			Updates(updates).Error; err != nil {
			log.Printf("bumpDevicesOnline: failed to update device %d: %v", id, err)
		}
	}
}

// trackDeviceTime folds one qualifying row's (device, timestamp) into the
// per-device freshest-evidence map bumpDevicesOnline consumes.
func trackDeviceTime(deviceTimes map[uint]time.Time, deviceID uint, ts time.Time) {
	if ts.After(deviceTimes[deviceID]) {
		deviceTimes[deviceID] = ts
	}
}

func (h *Handler) ReceiveSyslogMessages(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var messages []models.SyslogMessage
	if err := c.ShouldBindJSON(&messages); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	messages = truncateProbeBatch(h, probe, "syslog", 1000, messages)
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	// Pre-resolve the source IPs of device-less messages in one batch query
	// rather than a lookup per message (an N+1 at high syslog volume). Indexing
	// a nil map returns 0, so the per-message assignment below stays simple.
	var ipToDevice map[string]uint
	if h.db != nil {
		ipSet := make(map[string]struct{})
		for i := range messages {
			if messages[i].DeviceID == 0 && messages[i].SourceIP != "" {
				ipSet[messages[i].SourceIP] = struct{}{}
			}
		}
		if len(ipSet) > 0 {
			ips := make([]string, 0, len(ipSet))
			for ip := range ipSet {
				ips = append(ips, ip)
			}
			ipToDevice = h.db.ResolveDevicesByIPs(ips)
		}
	}
	filtered := messages[:0]
	for i := range messages {
		messages[i].ProbeID = probe.ID
		if messages[i].Timestamp.IsZero() {
			messages[i].Timestamp = now
		}
		if messages[i].DeviceID == 0 && messages[i].SourceIP != "" {
			if devID := ipToDevice[messages[i].SourceIP]; devID > 0 {
				messages[i].DeviceID = devID
			}
		}
		// Reject any DeviceID (body-supplied or IP-resolved) the probe doesn't
		// own — the global ResolveDevicesByIPs lookup can map a source IP to a
		// device assigned to a different probe, and a crafted body can spoof one
		// outright. Without this, a probe could inject SYSLOG_CRITICAL alerts and
		// forge config-change attribution against another site's device. Mirrors
		// the allow-list enforcement every sibling ingestion handler already does.
		if messages[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[messages[i].DeviceID] {
			continue
		}
		filtered = append(filtered, messages[i])
	}
	if err := h.db.SaveSyslogMessages(filtered); err != nil {
		log.Printf("Failed to batch save syslog messages: %v", err)
		httputil.InternalError(c, "Failed to save syslog messages", err)
		return
	}
	// Evaluate every message against the event-rule engine (v35). The old outer
	// `severity <= 2` gate is gone — content-matching rules must see all
	// severities (e.g. sev-3/4 FortiGate VPN errors). The engine fast-paths when
	// no rules are loaded, so this stays cheap on the syslog hot path.
	if h.alertManager != nil {
		for i := range filtered {
			if err := h.alertManager.ProcessSyslog(&filtered[i], nil); err != nil {
				log.Printf("Failed to process syslog alert: %v", err)
			}
		}
	}
	// Tranche 4 Phase 2: project FortiGate action="deny" lines into denied_events
	// for the deny detectors. deny.Project cheap-gates non-deny messages before
	// any KV parse, so the majority stream is untouched on this hot path.
	h.projectDeniedEvents(filtered)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

// denyPatternCacheTTL bounds how stale the block-policy pattern setting may be
// on the ingest path (the setting is read from the DB, not this process's env).
const denyPatternCacheTTL = 60 * time.Second

// projectDeniedEvents derives DeniedEvent rows from a saved syslog batch and
// bulk-inserts them. Only FortiGate deny lines project (deny.Project returns
// false otherwise). Best-effort: a projection/insert failure is logged, never
// fatal to syslog ingest.
func (h *Handler) projectDeniedEvents(msgs []models.SyslogMessage) {
	if len(msgs) == 0 || h.db == nil {
		return
	}
	cfg := deny.PatternConfig{Pattern: h.denyPolicyPattern()}
	events := make([]models.DeniedEvent, 0, len(msgs))
	for i := range msgs {
		if ev, ok := deny.Project(&msgs[i], &h.threatMatch, cfg); ok {
			events = append(events, ev)
		}
	}
	if len(events) == 0 {
		return
	}
	if err := h.db.SaveDeniedEvents(events); err != nil {
		log.Printf("projectDeniedEvents: save %d event(s): %v", len(events), err)
	}
}

// denyPolicyPattern returns the block-policy-name glob, from the
// detect_deny_policy_pattern admin setting when set, else the env/built-in
// default. TTL-cached so the hot path doesn't hit the DB per batch.
func (h *Handler) denyPolicyPattern() string {
	now := time.Now()
	h.mu.RLock()
	if now.Before(h.denyPatternExpiry) {
		p := h.denyPatternCached
		h.mu.RUnlock()
		return p
	}
	h.mu.RUnlock()

	pattern := h.config.Detect.DenyPolicyPattern
	if v, ok := h.db.GetSettingValue("detect_deny_policy_pattern"); ok {
		pattern = strings.TrimSpace(v)
	}
	h.mu.Lock()
	h.denyPatternCached = pattern
	h.denyPatternExpiry = now.Add(denyPatternCacheTTL)
	h.mu.Unlock()
	return pattern
}

func (h *Handler) ReceiveTrapEvents(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var traps []models.TrapEvent
	if err := c.ShouldBindJSON(&traps); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	traps = truncateProbeBatch(h, probe, "traps", 1000, traps)
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := traps[:0]
	for i := range traps {
		if traps[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[traps[i].DeviceID] {
			continue
		}
		traps[i].ProbeID = probe.ID
		if traps[i].Timestamp.IsZero() {
			traps[i].Timestamp = now
		}
		filtered = append(filtered, traps[i])
	}
	if err := h.db.SaveTrapEvents(filtered); err != nil {
		log.Printf("Failed to batch save trap events: %v", err)
		httputil.InternalError(c, "Failed to save trap events", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveFlowSamples(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var samples []models.FlowSample
	if err := c.ShouldBindJSON(&samples); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	samples = truncateProbeBatch(h, probe, "flows", 1000, samples)
	allowedDevices := h.probeDeviceIDs(probe.ID)
	// Server-side device-resolution fallback for unresolved samples, batched into
	// one query for the whole payload instead of a lookup per sample.
	var ipToDevice map[string]uint
	if h.db != nil {
		ipSet := make(map[string]struct{})
		for i := range samples {
			if samples[i].DeviceID == 0 && samples[i].SamplerAddress != "" {
				ipSet[samples[i].SamplerAddress] = struct{}{}
			}
		}
		if len(ipSet) > 0 {
			ips := make([]string, 0, len(ipSet))
			for ip := range ipSet {
				ips = append(ips, ip)
			}
			ipToDevice = h.db.ResolveDevicesByIPs(ips)
		}
	}
	now := time.Now()
	filtered := samples[:0]
	for i := range samples {
		samples[i].ProbeID = probe.ID
		if samples[i].Timestamp.IsZero() {
			samples[i].Timestamp = now
		}
		if samples[i].DeviceID == 0 && samples[i].SamplerAddress != "" {
			if devID := ipToDevice[samples[i].SamplerAddress]; devID > 0 {
				samples[i].DeviceID = devID
			}
		}
		if samples[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[samples[i].DeviceID] {
			continue
		}
		// Tranche 3: clamp the exporting-protocol label. Clamp, don't reject —
		// a 400 would bounce an entire batch over one field from a future
		// collector (violating the additive-wire rule), and pass-through of
		// junk values would fragment rollup groups (flow_source is a GROUP BY
		// key). Bump FlowSourceMax when a new source ships.
		if samples[i].FlowSource > models.FlowSourceMax {
			samples[i].FlowSource = models.FlowSourceSFlow
		}
		// NOTE: zero-byte rows are deliberately legal — NSEL create/denied
		// records and NAT-event records carry no byte counters, and denied-
		// flow visibility (firewall_event=3) is the headline NetFlow feature.
		// Ingest-time classification: stamp the app/L7 category and direction
		// (internal/classify) so the Flows page can GROUP BY them. Pure
		// (proto, ports, flags / addr-scope) functions — cheap per sample.
		// Exporter app identification (PAN App-ID PEN 25461 / FortiGate app
		// options, decoded by the collector into AppName) outranks the port
		// heuristic — the firewall did real L7 inspection, so "ssl" on a
		// non-standard port classifies as Web instead of Unknown. Unknown app
		// names fall through to the port heuristic (conservative mapping).
		// app_category is a rollup group key, so this is also how vendor app
		// analytics survive past the raw retention window.
		if cat, ok := classify.FromAppName(samples[i].AppName); ok {
			samples[i].AppCategory = uint8(cat)
		} else {
			samples[i].AppCategory = uint8(classify.Classify(samples[i].Protocol, samples[i].SrcPort, samples[i].DstPort, samples[i].TCPFlags))
		}
		samples[i].Direction = classify.Direction(samples[i].SrcAddr, samples[i].DstAddr, samples[i].InputIfIndex, samples[i].OutputIfIndex)
		samples[i].ScopeLocal = classify.ScopeLocal(samples[i].SrcAddr, samples[i].DstAddr)
		// Geo/ASN enrichment (GEOIP_ENABLED). Nil-safe: when geo is off these are
		// no-ops returning empty/0. GeoLite2 maps only public IPs, so internal
		// src/dst simply stay empty.
		// BGP (sFlow extended_gateway) AS numbers take precedence over GeoLite2
		// — they reflect the actual routing path, not a static IP→ASN database.
		// GeoLite2 then fills any AS still unknown.
		if samples[i].BGPSrcAS > 0 {
			samples[i].SrcASN = samples[i].BGPSrcAS
		}
		if samples[i].BGPDstAS > 0 {
			samples[i].DstASN = samples[i].BGPDstAS
		}
		if h.geoResolver.Enabled() {
			samples[i].SrcCountry = h.geoResolver.Country(samples[i].SrcAddr)
			samples[i].DstCountry = h.geoResolver.Country(samples[i].DstAddr)
			// ASN + org together, but ONLY when the number itself comes from the
			// geo DB. When a BGP AS won above we leave the org empty rather than
			// risk pairing the geo DB's org with a different BGP AS number.
			if samples[i].SrcASN == 0 {
				samples[i].SrcASN, samples[i].SrcASNOrg = h.geoResolver.ASNInfo(samples[i].SrcAddr)
			}
			if samples[i].DstASN == 0 {
				samples[i].DstASN, samples[i].DstASNOrg = h.geoResolver.ASNInfo(samples[i].DstAddr)
			}
		}
		// Threat-intel bitfield: bit 0 = src known-bad IP, bit 1 = dst known-bad
		// IP, bit 2 = src ASN on the bad-ASN reputation set, bit 3 = dst ASN bad.
		// Nil-safe + in-memory lookups — no-op when no feed is loaded. ASN checks
		// use the AS numbers resolved just above (BGP or GeoIP).
		var tf uint8
		if _, ok := h.threatMatch.Match(samples[i].SrcAddr); ok {
			tf |= 1
		}
		if _, ok := h.threatMatch.Match(samples[i].DstAddr); ok {
			tf |= 2
		}
		if _, ok := h.threatMatch.MatchASN(samples[i].SrcASN); ok {
			tf |= 4
		}
		if _, ok := h.threatMatch.MatchASN(samples[i].DstASN); ok {
			tf |= 8
		}
		samples[i].ThreatFlag = tf
		filtered = append(filtered, samples[i])
	}
	// M2 of the 2026-07-01 audit: fold the batch's cumulative drops counters
	// into flow_agent_drops so the sampling_backoff detector has data.
	h.recordAgentDrops(filtered)

	if err := h.db.SaveFlowSamples(filtered); err != nil {
		log.Printf("ReceiveFlowSamples: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save flow samples", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

// ReceiveFlowCounterSamples ingests sFlow interface counter samples (schema v2).
// Mirrors ReceiveFlowSamples: validate probe, dedup batch, resolve device by
// sampler IP, drop samples for devices the probe doesn't own, persist. Only
// collectors that negotiated schema_version 2 POST here.
func (h *Handler) ReceiveFlowCounterSamples(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var counters []models.FlowInterfaceCounter
	if err := c.ShouldBindJSON(&counters); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	counters = truncateProbeBatch(h, probe, "flow-counters", 1000, counters)
	allowedDevices := h.probeDeviceIDs(probe.ID)
	var ipToDevice map[string]uint
	if h.db != nil {
		ipSet := make(map[string]struct{})
		for i := range counters {
			if counters[i].DeviceID == 0 && counters[i].SamplerAddress != "" {
				ipSet[counters[i].SamplerAddress] = struct{}{}
			}
		}
		if len(ipSet) > 0 {
			ips := make([]string, 0, len(ipSet))
			for ip := range ipSet {
				ips = append(ips, ip)
			}
			ipToDevice = h.db.ResolveDevicesByIPs(ips)
		}
	}
	now := time.Now()
	filtered := counters[:0]
	for i := range counters {
		counters[i].ProbeID = probe.ID
		if counters[i].Timestamp.IsZero() {
			counters[i].Timestamp = now
		}
		if counters[i].DeviceID == 0 && counters[i].SamplerAddress != "" {
			if devID := ipToDevice[counters[i].SamplerAddress]; devID > 0 {
				counters[i].DeviceID = devID
			}
		}
		if counters[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[counters[i].DeviceID] {
			continue
		}
		filtered = append(filtered, counters[i])
	}
	if err := h.db.SaveFlowInterfaceCounters(filtered); err != nil {
		log.Printf("ReceiveFlowCounterSamples: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save interface counters", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceivePingResults(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var results []models.PingResult
	if err := c.ShouldBindJSON(&results); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	results = truncateProbeBatch(h, probe, "pings", 1000, results)
	log.Printf("ReceivePingResults: probe %d received %d results", probe.ID, len(results))
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := results[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range results {
		if results[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[results[i].DeviceID] {
			log.Printf("ReceivePingResults: device %d not allowed for probe %d", results[i].DeviceID, probe.ID)
			continue
		}
		results[i].ProbeID = probe.ID
		if results[i].Timestamp.IsZero() {
			results[i].Timestamp = now
		}
		filtered = append(filtered, results[i])
		// Only a SUCCESSFUL ping proves reachability — a saved failure row
		// must not keep an unreachable device "online", and a spooled failure
		// newer than the last success must not extend its evidence either.
		if results[i].DeviceID > 0 && results[i].Success {
			trackDeviceTime(deviceTimes, results[i].DeviceID, results[i].Timestamp)
		}
	}
	if err := h.db.SavePingResults(filtered); err != nil {
		log.Printf("Failed to batch save ping results: %v", err)
		httputil.InternalError(c, "Failed to save ping results", err)
		return
	}
	// Aggregate into PingStats — fold the whole batch per target (M4).
	h.updatePingStatsBatch(probe.ID, filtered)
	h.bumpDevicesOnline(deviceTimes, now)
	log.Printf("ReceivePingResults: probe %d saved %d results", probe.ID, len(filtered))
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

// pingAgg folds a batch's samples for one (device, target) before touching the DB.
type pingAgg struct {
	min, max, sum float64
	count         int
	lastLoss      float64
}

// updatePingStatsBatch folds a batch of ping results into the per-(device,target)
// running PingStats series with ONE read + ONE write per distinct target, instead
// of a serial read-modify-write per result (M4 of the 2026-06-23 audit; up to
// ~2N DB round-trips for N results). The folded min/max/avg/sample-count is
// mathematically identical to applying the samples one at a time, since the
// running average ((A·S + Σ) / (S + K)) is associative. PacketLoss/ProbeID keep
// the original last-writer semantics (the last sample for that target in the
// batch). Ping stats are a single series per (device, target) regardless of which
// probe sent the sample, so replacing a probe keeps one continuous series.
func (h *Handler) updatePingStatsBatch(probeID uint, results []models.PingResult) {
	groups := make(map[uint]map[string]*pingAgg)
	for i := range results {
		r := &results[i]
		byTarget := groups[r.DeviceID]
		if byTarget == nil {
			byTarget = make(map[string]*pingAgg)
			groups[r.DeviceID] = byTarget
		}
		a := byTarget[r.TargetIP]
		if a == nil {
			a = &pingAgg{min: r.Latency, max: r.Latency}
			byTarget[r.TargetIP] = a
		}
		a.min = math.Min(a.min, r.Latency)
		a.max = math.Max(a.max, r.Latency)
		a.sum += r.Latency
		a.count++
		a.lastLoss = r.PacketLoss // last-writer provenance, batch order preserved
	}

	now := time.Now()
	for deviceID, byTarget := range groups {
		for targetIP, a := range byTarget {
			// Fold atomically in the DB (INSERT … ON CONFLICT DO UPDATE) rather than
			// read-modify-writing here: two batches folding the same (device,target)
			// concurrently would otherwise both read the same base row and the last
			// writer would erase the other's whole batch (audit L16).
			if err := h.db.FoldPingStats(deviceID, probeID, targetIP, a.min, a.max, a.sum, a.count, a.lastLoss, now); err != nil {
				log.Printf("updatePingStatsBatch: fold (device %d target %s): %v", deviceID, targetIP, err)
			}
		}
	}
}

func (h *Handler) ReceiveInterfaceAddresses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var addrs []models.InterfaceAddress
	if err := c.ShouldBindJSON(&addrs); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	addrs = truncateProbeBatch(h, probe, "interface-addresses", 1000, addrs)
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := addrs[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range addrs {
		if addrs[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[addrs[i].DeviceID] {
			continue
		}
		if addrs[i].Timestamp.IsZero() {
			addrs[i].Timestamp = now
		}
		filtered = append(filtered, addrs[i])
		if addrs[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, addrs[i].DeviceID, addrs[i].Timestamp)
		}
	}
	if err := h.db.SaveInterfaceAddresses(filtered); err != nil {
		log.Printf("ReceiveInterfaceAddresses: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save interface addresses", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveProcessorStats(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	// L17 of the 2026-07-01 audit: the direct-send metric endpoints had no
	// batch idempotency, so a timeout-after-commit replay from the collector's
	// spillover queue inserted every row twice (duplicate timestamps skew
	// per-device history charts). Same AUDIT-042 pair the event endpoints use;
	// a no-op when the collector (pre-v1.2.156) sends no X-Probe-Batch-ID.
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var stats []models.ProcessorStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(stats) > 500 {
		stats = stats[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := stats[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range stats {
		if stats[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[stats[i].DeviceID] {
			continue
		}
		if stats[i].Timestamp.IsZero() {
			stats[i].Timestamp = now
		}
		filtered = append(filtered, stats[i])
		if stats[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, stats[i].DeviceID, stats[i].Timestamp)
		}
	}
	if err := h.db.SaveProcessorStats(filtered); err != nil {
		log.Printf("ReceiveProcessorStats: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save processor stats", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveDiskUsage(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var rows []models.DiskUsage
	if err := c.ShouldBindJSON(&rows); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(rows) > 500 {
		rows = rows[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := rows[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range rows {
		if rows[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[rows[i].DeviceID] {
			continue
		}
		if rows[i].Timestamp.IsZero() {
			rows[i].Timestamp = now
		}
		filtered = append(filtered, rows[i])
		if rows[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, rows[i].DeviceID, rows[i].Timestamp)
		}
	}
	if err := h.db.SaveDiskUsage(filtered); err != nil {
		log.Printf("ReceiveDiskUsage: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save disk usage", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveLoadAverage(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var rows []models.LoadAverage
	if err := c.ShouldBindJSON(&rows); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(rows) > 500 {
		rows = rows[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := rows[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range rows {
		if rows[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[rows[i].DeviceID] {
			continue
		}
		if rows[i].Timestamp.IsZero() {
			rows[i].Timestamp = now
		}
		filtered = append(filtered, rows[i])
		if rows[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, rows[i].DeviceID, rows[i].Timestamp)
		}
	}
	if err := h.db.SaveLoadAverage(filtered); err != nil {
		log.Printf("ReceiveLoadAverage: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save load average", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveHardwareSensors(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID) // L17: see ReceiveProcessorStats
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var sensors []models.HardwareSensor
	if err := c.ShouldBindJSON(&sensors); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(sensors) > 500 {
		sensors = sensors[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := sensors[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range sensors {
		if sensors[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[sensors[i].DeviceID] {
			continue
		}
		if sensors[i].Timestamp.IsZero() {
			sensors[i].Timestamp = now
		}
		filtered = append(filtered, sensors[i])
		if sensors[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, sensors[i].DeviceID, sensors[i].Timestamp)
		}
	}
	if len(filtered) == 0 {
		c.JSON(http.StatusOK, response.Success(gin.H{"saved": 0}))
		return
	}
	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveHardwareSensors: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save hardware sensors", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSystemStatuses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID) // L17: see ReceiveProcessorStats
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var statuses []models.SystemStatus
	if err := c.ShouldBindJSON(&statuses); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	statuses = truncateProbeBatch(h, probe, "system-status", 100, statuses)

	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := statuses[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range statuses {
		if statuses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[statuses[i].DeviceID] {
			continue // skip data for devices not assigned to this probe
		}
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = now
		}
		filtered = append(filtered, statuses[i])
		if statuses[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, statuses[i].DeviceID, statuses[i].Timestamp)
		}
	}

	// One batch insert instead of a Create per row (M4).
	if err := h.db.SaveSystemStatuses(filtered); err != nil {
		log.Printf("Probe %d: failed to batch save system statuses: %v", probe.ID, err)
		httputil.InternalError(c, "Failed to save system statuses", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)

	log.Printf("Probe %d: saved %d/%d system status records", probe.ID, len(filtered), len(statuses))
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveInterfaceStats(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	// L17: duplicated cumulative interface counters at near-identical
	// timestamps are the worst replay case — they skew every delta-based
	// bandwidth calculation.
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var stats []models.InterfaceStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	stats = truncateProbeBatch(h, probe, "interface-stats", 1000, stats)
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	deviceTimes := make(map[uint]time.Time)
	filtered := stats[:0]
	for i := range stats {
		if stats[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[stats[i].DeviceID] {
			continue
		}
		if stats[i].Timestamp.IsZero() {
			stats[i].Timestamp = now
		}
		if stats[i].TypeName == "" && stats[i].Type > 0 {
			if name, ok := snmp.IfTypeNames[stats[i].Type]; ok {
				stats[i].TypeName = name
			}
		}
		if stats[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, stats[i].DeviceID, stats[i].Timestamp)
		}
		filtered = append(filtered, stats[i])
	}
	if err := h.db.SaveInterfaceStats(filtered); err != nil {
		log.Printf("ReceiveInterfaceStats: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save interface stats", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)

	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveVPNStatuses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID) // L17: see ReceiveProcessorStats
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var statuses []models.VPNStatus
	if err := c.ShouldBindJSON(&statuses); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(statuses) > 500 {
		statuses = statuses[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	deviceTimes := make(map[uint]time.Time)
	filtered := statuses[:0]
	for i := range statuses {
		if statuses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[statuses[i].DeviceID] {
			continue
		}
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = now
		}
		if statuses[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, statuses[i].DeviceID, statuses[i].Timestamp)
		}
		filtered = append(filtered, statuses[i])
	}
	if err := h.db.SaveVPNStatuses(filtered); err != nil {
		log.Printf("ReceiveVPNStatuses: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save VPN statuses", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)

	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveHAStatuses(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID) // L17: see ReceiveProcessorStats
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var statuses []models.HAStatus
	if err := c.ShouldBindJSON(&statuses); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(statuses) > 500 {
		statuses = statuses[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := statuses[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range statuses {
		if statuses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[statuses[i].DeviceID] {
			continue
		}
		if statuses[i].Timestamp.IsZero() {
			statuses[i].Timestamp = now
		}
		filtered = append(filtered, statuses[i])
		if statuses[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, statuses[i].DeviceID, statuses[i].Timestamp)
		}
	}
	if err := h.db.SaveHAStatuses(filtered); err != nil {
		log.Printf("ReceiveHAStatuses: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save HA statuses", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSecurityStats(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID) // L17: see ReceiveProcessorStats
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var stats []models.SecurityStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(stats) > 500 {
		stats = stats[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := stats[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range stats {
		if stats[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[stats[i].DeviceID] {
			continue
		}
		if stats[i].Timestamp.IsZero() {
			stats[i].Timestamp = now
		}
		filtered = append(filtered, stats[i])
		if stats[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, stats[i].DeviceID, stats[i].Timestamp)
		}
	}
	if err := h.db.SaveSecurityStats(filtered); err != nil {
		log.Printf("ReceiveSecurityStats: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save security stats", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSDWANHealth(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID) // L17: see ReceiveProcessorStats
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	var health []models.SDWANHealth
	if err := c.ShouldBindJSON(&health); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(health) > 500 {
		health = health[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := health[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range health {
		if health[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[health[i].DeviceID] {
			continue
		}
		if health[i].Timestamp.IsZero() {
			health[i].Timestamp = now
		}
		filtered = append(filtered, health[i])
		if health[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, health[i].DeviceID, health[i].Timestamp)
		}
	}
	if err := h.db.SaveSDWANHealth(filtered); err != nil {
		log.Printf("ReceiveSDWANHealth: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save SD-WAN health", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveLicenseInfo(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var licenses []models.LicenseInfo
	if err := c.ShouldBindJSON(&licenses); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(licenses) > 500 {
		licenses = licenses[:500]
	}
	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := licenses[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range licenses {
		if licenses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[licenses[i].DeviceID] {
			continue
		}
		if licenses[i].Timestamp.IsZero() {
			licenses[i].Timestamp = now
		}
		filtered = append(filtered, licenses[i])
		if licenses[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, licenses[i].DeviceID, licenses[i].Timestamp)
		}
	}
	if err := h.db.SaveLicenseInfo(filtered); err != nil {
		log.Printf("ReceiveLicenseInfo: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save license info", err)
		return
	}
	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

const (
	maxConfigTextSize = 50 * 1024 * 1024 // 50MB max config size to prevent DoS
)

func (h *Handler) ReceiveConfigRevision(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		log.Printf("ReceiveConfigRevision: validateProbe failed")
		return
	}
	log.Printf("ReceiveConfigRevision: probe %d (%s) receiving config", probe.ID, probe.Name)

	var rev models.DeviceConfigRevision
	if err := c.ShouldBindJSON(&rev); err != nil {
		log.Printf("ReceiveConfigRevision: Invalid JSON: %v", err)
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	log.Printf("ReceiveConfigRevision: received DeviceID=%d, Length=%d, ConfigText len=%d", rev.DeviceID, rev.Length, len(rev.ConfigText))

	allowedDevices := h.probeDeviceIDs(probe.ID)
	log.Printf("ReceiveConfigRevision: probe %d has %d devices assigned", probe.ID, len(allowedDevices))

	if allowedDevices != nil && !allowedDevices[rev.DeviceID] {
		log.Printf("ReceiveConfigRevision: REJECTED - device %d not in probe %d's device list (probe name: %s)", rev.DeviceID, probe.ID, probe.Name)
		c.JSON(http.StatusForbidden, response.Error("Device not assigned to probe"))
		return
	}

	// Validate ConfigText size to prevent DoS
	if len(rev.ConfigText) > maxConfigTextSize {
		log.Printf("ReceiveConfigRevision: Rejected config for device %d - size %d exceeds limit %d", rev.DeviceID, len(rev.ConfigText), maxConfigTextSize)
		c.JSON(http.StatusBadRequest, response.Error("Config too large"))
		return
	}

	if rev.Timestamp.IsZero() {
		rev.Timestamp = time.Now()
	}

	// Compute the vendor-aware normalized checksum. This is what change-detection
	// alerts compare against — raw checksums drift on every backup for FortiOS
	// devices because of random-IV ENC ciphertext, so they're useless for "did
	// the operator actually change something?".
	vendor := ""
	if dev, err := h.db.GetDevice(rev.DeviceID); err == nil && dev != nil {
		vendor = dev.Vendor
	}
	normalized, quality := configdiff.Normalize(vendor, []byte(rev.ConfigText))
	normalizedSum := md5.Sum(normalized) // (gosec G401 excluded in CI: non-crypto config-change checksum)
	rev.NormalizedChecksum = hex.EncodeToString(normalizedSum[:])

	// Honor a TriggerSource the collector explicitly set (e.g. "syslog"). If it
	// didn't, default to "poll" — this is the safety-net floor cadence.
	if rev.TriggerSource == "" {
		rev.TriggerSource = "poll"
	}

	// Honor a BackupQuality the collector explicitly set; otherwise use what the
	// normalizer detected (e.g. FortiOS 7.2.1+ password masking).
	if rev.BackupQuality == "" {
		rev.BackupQuality = quality
	}

	// Validate the bytes look like a real FortiOS backup BEFORE we consider
	// merging into the prior row. If validation fails we will still INSERT
	// (so we don't lose the data), but we won't OVERWRITE good prior bytes
	// with bad ones — the row will be tagged "suspect" and treated as a new
	// state so it gets visibility instead of silently replacing good data.
	suspect := false
	if vendor == "fortigate" {
		if err := configdiff.ValidateFortiGateBackup([]byte(rev.ConfigText)); err != nil {
			log.Printf("ReceiveConfigRevision: validation failed for device %d, treating as suspect: %v",
				rev.DeviceID, err)
			suspect = true
			rev.BackupQuality = "suspect"
		}
	}

	// Merge-into-latest model (v0.10.198+):
	//   - Same NormalizedChecksum as prior revision → UPDATE in place,
	//     refresh ConfigText (latest ENC ciphertext for restore), bump
	//     LastVerifiedAt, increment VerifyCount. No alert.
	//   - Different NormalizedChecksum, OR no prior revision, OR suspect →
	//     INSERT a new row, alert if a prior row existed.
	//
	// All wrapped in a transaction with a SELECT ... FOR UPDATE to serialize
	// concurrent backups for the same device.
	now := time.Now()
	var (
		mergedID       uint
		mergedAction   string // "merge" | "insert-first" | "insert-change" | "insert-suspect"
		prevNormalized string
		prevConfigText string
	)

	txErr := h.db.Gorm().Transaction(func(tx *gorm.DB) error {
		var prevRev models.DeviceConfigRevision
		// Lock the latest row for this device. On Postgres this is a real row
		// lock; on SQLite the entire DB is serialized under transactions, so
		// the same correctness property holds.
		err := tx.Set("gorm:query_option", "FOR UPDATE").
			Where("device_id = ?", rev.DeviceID).
			Order("id DESC").Limit(1).
			First(&prevRev).Error

		hasPrev := err == nil
		if hasPrev {
			prevNormalized = prevRev.NormalizedChecksum
			prevConfigText = prevRev.ConfigText
		}

		// MERGE path: same vendor-normalized state, validation OK.
		if hasPrev && !suspect && prevRev.NormalizedChecksum == rev.NormalizedChecksum && rev.NormalizedChecksum != "" {
			updates := map[string]interface{}{
				"checksum":         rev.Checksum,
				"config_text":      rev.ConfigText,
				"length":           len(rev.ConfigText),
				"last_verified_at": now,
				"verify_count":     prevRev.VerifyCount + 1,
				"trigger_source":   rev.TriggerSource,
			}
			// Backup quality can shift (e.g. FortiOS 7.2.1+ password masking
			// was just enabled). Keep the latest value.
			if rev.BackupQuality != "" {
				updates["backup_quality"] = rev.BackupQuality
			}
			if err := tx.Model(&models.DeviceConfigRevision{}).
				Where("id = ?", prevRev.ID).
				Updates(updates).Error; err != nil {
				return err
			}
			mergedID = prevRev.ID
			mergedAction = "merge"
			return nil
		}

		// INSERT path: new state (or first-ever, or suspect bytes).
		if rev.FirstSeenAt.IsZero() {
			rev.FirstSeenAt = now
		}
		if rev.LastVerifiedAt.IsZero() {
			rev.LastVerifiedAt = now
		}
		if rev.VerifyCount == 0 {
			rev.VerifyCount = 1
		}
		if rev.Timestamp.IsZero() {
			rev.Timestamp = now
		}
		if err := tx.Create(&rev).Error; err != nil {
			return err
		}
		mergedID = rev.ID
		switch {
		case suspect:
			mergedAction = "insert-suspect"
		case !hasPrev:
			mergedAction = "insert-first"
		default:
			mergedAction = "insert-change"
		}
		return nil
	})
	if txErr != nil {
		log.Printf("ReceiveConfigRevision: tx error for device %d: %v", rev.DeviceID, txErr)
		httputil.InternalError(c, "Failed to save config revision", txErr)
		return
	}

	actualLen := len(rev.ConfigText)
	if rev.Length != actualLen {
		log.Printf("WARNING: ReceiveConfigRevision: device %d Length mismatch - reported=%d actual=%d",
			rev.DeviceID, rev.Length, actualLen)
	}
	log.Printf("ReceiveConfigRevision: %s for device %d (rev.ID=%d, len=%d, raw=%s norm=%s trigger=%s quality=%s)",
		mergedAction, rev.DeviceID, mergedID, actualLen,
		rev.Checksum, rev.NormalizedChecksum, rev.TriggerSource, rev.BackupQuality)

	// Alert only on real INSERT-change (not merge, not first-ever, not suspect).
	// Suspect insertions are visible in the History UI as "suspect" rows; a
	// CONFIG_CHANGE alert there would be misleading because we can't actually
	// confirm what changed.
	if mergedAction == "insert-change" {
		// Classify the security impact (per-object semantic diff) and attribute
		// the change to an admin via FortiGate config-change syslog events.
		info := alerts.ConfigChangeInfo{Attributed: true}
		if changes, ok := configdiff.DiffObjects(vendor, []byte(prevConfigText), []byte(rev.ConfigText)); ok {
			overall, _ := configdiff.ClassifyChanges(changes)
			info.Severity = overall.Severity
			info.Impact = overall.Summary
		}
		// Correlation was attempted for this real change — record that, so the UI
		// can distinguish "no session found (out-of-band)" from "never checked".
		attrUpdates := map[string]interface{}{"attribution_checked": true}
		if att, found := h.attributeConfigChange(rev.DeviceID, now); found {
			info.ChangedBy = att.User
			info.Method = att.Method
			info.Attributed = true
			attrUpdates["changed_by"] = att.User
			attrUpdates["changed_from"] = att.Source
			attrUpdates["change_method"] = att.Method
			attrUpdates["attributed"] = true
		} else {
			info.Attributed = false
		}
		h.db.Gorm().Model(&models.DeviceConfigRevision{}).Where("id = ?", mergedID).Updates(attrUpdates)

		if h.alertManager != nil {
			h.alertManager.CheckConfigRevision(rev.DeviceID, prevNormalized, rev.NormalizedChecksum, info)
		}
	}

	// rev.Timestamp is this delivery's collection time — config revisions ride
	// the AUDIT-054 retry queue, so a replayed hours-old backup must not count
	// as fresh reachability evidence.
	h.bumpDevicesOnline(map[uint]time.Time{rev.DeviceID: rev.Timestamp}, time.Now())

	c.JSON(http.StatusOK, response.Success(gin.H{
		"saved":               mergedID,
		"action":              mergedAction,
		"normalized_checksum": rev.NormalizedChecksum,
		"trigger_source":      rev.TriggerSource,
		"backup_quality":      rev.BackupQuality,
	}))
}

// attributeConfigChange correlates a detected config change with the most recent
// FortiGate config-change syslog event for the device, to populate who/how/from.
// FortiGate emits these audit events natively (no TACACS+ required); the messages
// are already stored server-side in syslog_messages. found is false when no
// matching authenticated session exists within the lookback window — a possible
// out-of-band change.
func (h *Handler) attributeConfigChange(deviceID uint, when time.Time) (ev configdiff.FortiAuditEvent, found bool) {
	if h.db == nil {
		return ev, false
	}
	// A change-detection backup can lag the actual edit (poll cadence), so look
	// back generously but accept only events at/just-after the edit.
	start := when.Add(-15 * time.Minute)
	end := when.Add(2 * time.Minute)
	var msgs []models.SyslogMessage
	if err := h.db.Gorm().
		Where("device_id = ? AND timestamp >= ? AND timestamp <= ?", deviceID, start, end).
		Order("timestamp DESC").Limit(100).Find(&msgs).Error; err != nil {
		return ev, false
	}
	for _, m := range msgs {
		if parsed := configdiff.ParseFortiAuditEvent(m.Message); parsed.IsConfigChange {
			if parsed.Source == "" {
				parsed.Source = m.SourceIP
			}
			return parsed, true
		}
	}
	return ev, false
}

func (h *Handler) ReceiveProcessSnapshot(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var snap models.ProcessStats
	if err := c.ShouldBindJSON(&snap); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	if allowedDevices != nil && !allowedDevices[snap.DeviceID] {
		c.JSON(http.StatusForbidden, response.Error("Device not assigned to probe"))
		return
	}

	if snap.Timestamp.IsZero() {
		snap.Timestamp = time.Now()
	}

	if err := h.db.Gorm().Create(&snap).Error; err != nil {
		log.Printf("ReceiveProcessSnapshot: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save process snapshot", err)
		return
	}

	if snap.DeviceID > 0 {
		h.bumpDevicesOnline(map[uint]time.Time{snap.DeviceID: snap.Timestamp}, time.Now())
	}

	c.JSON(http.StatusOK, response.Success(gin.H{"saved": snap.ID}))
}

func (h *Handler) ReceiveInterfaceErrors(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var errs []models.InterfaceErrors
	if err := c.ShouldBindJSON(&errs); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(errs) > 500 {
		errs = errs[:500]
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := errs[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range errs {
		if errs[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[errs[i].DeviceID] {
			continue
		}
		if errs[i].Timestamp.IsZero() {
			errs[i].Timestamp = now
		}
		filtered = append(filtered, errs[i])
		if errs[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, errs[i].DeviceID, errs[i].Timestamp)
		}
	}

	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveInterfaceErrors: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save interface errors", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveSensorDetails(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var sensors []models.HardwareSensor
	if err := c.ShouldBindJSON(&sensors); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	log.Printf("ReceiveSensorDetails: probe=%d received %d sensors", probe.ID, len(sensors))
	if len(sensors) > 500 {
		sensors = sensors[:500]
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	log.Printf("ReceiveSensorDetails: probe=%d allowed devices=%v", probe.ID, allowedDevices)
	now := time.Now()
	filtered := sensors[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range sensors {
		log.Printf("ReceiveSensorDetails: sensor[%d] device_id=%d name=%q value=%.1f unit=%q status=%q", i, sensors[i].DeviceID, sensors[i].Name, sensors[i].Value, sensors[i].Unit, sensors[i].Status)
		if sensors[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[sensors[i].DeviceID] {
			log.Printf("ReceiveSensorDetails: filtering out device_id=%d (not in allowed list)", sensors[i].DeviceID)
			continue
		}
		if sensors[i].Timestamp.IsZero() {
			sensors[i].Timestamp = now
		}
		filtered = append(filtered, sensors[i])
		if sensors[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, sensors[i].DeviceID, sensors[i].Timestamp)
		}
	}
	log.Printf("ReceiveSensorDetails: probe=%d filtered to %d sensors", probe.ID, len(filtered))

	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveSensorDetails: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save sensor details", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveLicenseDetails(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	var licenses []models.LicenseInfo
	if err := c.ShouldBindJSON(&licenses); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return
	}
	if len(licenses) > 100 {
		licenses = licenses[:100]
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := licenses[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range licenses {
		if licenses[i].DeviceID > 0 && allowedDevices != nil && !allowedDevices[licenses[i].DeviceID] {
			continue
		}
		if licenses[i].Timestamp.IsZero() {
			licenses[i].Timestamp = now
		}
		filtered = append(filtered, licenses[i])
		if licenses[i].DeviceID > 0 {
			trackDeviceTime(deviceTimes, licenses[i].DeviceID, licenses[i].Timestamp)
		}
	}

	if err := h.db.Gorm().Create(&filtered).Error; err != nil {
		log.Printf("ReceiveLicenseDetails: DB save error: %v", err)
		httputil.InternalError(c, "Failed to save license details", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}
