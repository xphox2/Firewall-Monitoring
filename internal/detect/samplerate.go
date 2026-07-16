package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// Tranche 4 Phase 1 — sampling_rate_change (operational).
//
// Guards the pre-multiplied-bytes contract every volume detector trusts: a
// stale or unexpectedly changed sampler rate mis-scales traffic permanently
// (research doc §4 item 9). Stateless by design — the poller runs under a
// leader lock and fails over; an in-memory "previous cycle" map would silently
// lose state and skip a comparison at the worst time. Raw retention (~1h)
// trivially holds two 15-minute windows, so the detector compares the
// per-(device, flow_source) sampling-rate SET between (end-30m, end-15m] and
// (end-15m, end].
//
// Fires ONLY on rate-set ADDITIONS for a (device, source) present in both
// windows: a low-volume rate flickering out of the set (idle interface,
// MinRows filter) must not page, and additions still catch the case that
// matters — FortiGate 7.6+ netflow-sample-rate being enabled, which silently
// invalidates every complete-only detector on that device.
const defaultSampRateMinRows = 3

type samplingRateChangeDetector struct{}

func (samplingRateChangeDetector) Name() string       { return "sampling_rate_change" }
func (samplingRateChangeDetector) Category() Category { return CategoryOperational }

type samplerKey struct {
	DeviceID   uint
	FlowSource uint8
}

type samplerRow struct {
	DeviceID     uint
	FlowSource   uint8
	SamplingRate uint32
	C            int64
}

func (d samplingRateChangeDetector) rateSets(w Window, from, to interface{}, minRows int64) (map[samplerKey]map[uint32]bool, error) {
	var rows []samplerRow
	if err := w.DB.Model(&models.FlowSample{}).
		Where("timestamp >= ? AND timestamp < ?", from, to).
		Select("device_id, flow_source, sampling_rate, COUNT(*) as c").
		Group("device_id, flow_source, sampling_rate").
		Limit(2000).Scan(&rows).Error; err != nil {
		return nil, err
	}
	sets := map[samplerKey]map[uint32]bool{}
	for _, r := range rows {
		if r.C < minRows {
			continue // a single mangled datagram must not register as a rate
		}
		k := samplerKey{r.DeviceID, r.FlowSource}
		if sets[k] == nil {
			sets[k] = map[uint32]bool{}
		}
		sets[k][r.SamplingRate] = true
	}
	return sets, nil
}

func (d samplingRateChangeDetector) Detect(w Window) ([]Detection, error) {
	cfg := w.Config.withDefaults()
	if cfg.SamplingRateChangeDisabled {
		return nil, nil
	}
	minRows := int64(cfg.SampRateMinRows)
	curStart := w.End.Add(-15 * time.Minute)
	prevStart := w.End.Add(-30 * time.Minute) // both windows inside the ~1h raw retention

	prev, err := d.rateSets(w, prevStart, curStart, minRows)
	if err != nil {
		return nil, err
	}
	cur, err := d.rateSets(w, curStart, w.End, minRows)
	if err != nil {
		return nil, err
	}

	var out []Detection
	for k, curSet := range cur {
		prevSet, seenBefore := prev[k]
		if !seenBefore {
			continue // new exporter — first appearance is not a change
		}
		var added []uint32
		for rate := range curSet {
			if !prevSet[rate] {
				added = append(added, rate)
			}
		}
		if len(added) == 0 {
			continue
		}
		sort.Slice(added, func(i, j int) bool { return added[i] < added[j] })

		sourceName := map[uint8]string{0: "sFlow", 1: "NetFlow v5", 2: "NetFlow v9", 3: "IPFIX"}[k.FlowSource]
		if sourceName == "" {
			sourceName = fmt.Sprintf("source %d", k.FlowSource)
		}
		msg := fmt.Sprintf("Sampling rate changed on device %d (%s): rate set was %s, now also %s. Byte/packet scaling is stamped per-row at ingest, so history is safe — but verify the exporter change was intentional.",
			k.DeviceID, sourceName, rateSetString(prevSet), rateListString(added))
		// The escalation case: a NetFlow/IPFIX source newly SAMPLING (rate>1)
		// silently invalidates every complete-only detector on the device.
		for _, r := range added {
			if k.FlowSource != 0 && r > 1 {
				msg += " NetFlow with rate>1 also disables flow-count-based detectors for this device."
				break
			}
		}
		out = append(out, Detection{
			Detector: d.Name(), Category: d.Category(), Severity: "warning",
			DeviceID: k.DeviceID,
			Score:    float64(len(added)),
			Message:  msg,
			DedupKey: fmt.Sprintf("samprate_%d_%d", k.DeviceID, k.FlowSource),
			Details: map[string]any{
				"flow_source": k.FlowSource, "source": sourceName,
				"previous_rates": rateSetString(prevSet), "added_rates": rateListString(added),
			},
		})
	}
	// Deterministic output order for tests.
	sort.Slice(out, func(i, j int) bool { return out[i].DedupKey < out[j].DedupKey })
	return out, nil
}

func rateSetString(set map[uint32]bool) string {
	rates := make([]uint32, 0, len(set))
	for r := range set {
		rates = append(rates, r)
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i] < rates[j] })
	return rateListString(rates)
}

func rateListString(rates []uint32) string {
	parts := make([]string, len(rates))
	for i, r := range rates {
		parts[i] = fmt.Sprintf("%d", r)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
