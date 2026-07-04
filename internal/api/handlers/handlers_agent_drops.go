package handlers

import (
	"log"
	"time"

	"firewall-mon/internal/models"
)

// maxTrackedDropAgents bounds the per-agent cumulative-drops baseline map.
// Agents are the monitored firewalls (dozens, not thousands), but the sampler
// address arrives from the network, so the map must not grow unbounded
// (project invariant). Beyond the cap, new agents simply aren't drop-tracked.
const maxTrackedDropAgents = 4096

// recordAgentDrops folds a flow batch's sFlow sample-pool drops counters into
// flow_agent_drops — the missing half of the drops pipeline (M2 of the
// 2026-07-01 audit): FlowSample.Drops was persisted per row, but nothing
// aggregated it, so the sampling_backoff detector read a table nothing wrote
// and SFLOW_SAMPLING_BACKOFF could never fire while operators believed drop
// monitoring was active.
//
// The sFlow v5 drops field is a CUMULATIVE running counter per agent (not a
// per-sample delta), so this tracks the last seen value per agent and stores
// only the positive delta per batch, bucketed to the minute window the
// detector SUMs over. A counter that goes BACKWARD means the agent restarted;
// the new value becomes both the new baseline and (if non-zero) the delta.
func (h *Handler) recordAgentDrops(samples []models.FlowSample) {
	if h.db == nil || len(samples) == 0 {
		return
	}

	// Highest cumulative counter per (agent, sampling rate) in this batch.
	type agentKey struct {
		agent string
		rate  uint32
	}
	batchMax := make(map[agentKey]uint64)
	for i := range samples {
		if samples[i].SamplerAddress == "" {
			continue
		}
		// Tranche 3: only sFlow rows feed this. The delta logic below assumes
		// sFlow's CUMULATIVE sample-pool drops counter (RFC 3176 §3.1.1);
		// NetFlow/IPFIX has no such counter — the collector sends drops=0 for
		// those rows, but the server must not depend on that: a future
		// collector sending per-batch sequence-gap counts here would corrupt
		// the cumulative baseline for a dual-exporting sampler address and
		// mis-compute every delta. NetFlow export-loss lives in the
		// collector's seq-gap metric instead.
		if samples[i].FlowSource != models.FlowSourceSFlow {
			continue
		}
		k := agentKey{samples[i].SamplerAddress, samples[i].SamplingRate}
		if cur, ok := batchMax[k]; !ok || samples[i].Drops > cur {
			batchMax[k] = samples[i].Drops
		}
	}
	if len(batchMax) == 0 {
		return
	}

	type pending struct {
		agent string
		rate  uint32
		delta uint64
	}
	var saves []pending

	h.agentDropsMu.Lock()
	if h.agentDropsLast == nil {
		h.agentDropsLast = make(map[string]uint64)
	}
	for k, cur := range batchMax {
		last, seen := h.agentDropsLast[k.agent]
		switch {
		case !seen:
			if len(h.agentDropsLast) >= maxTrackedDropAgents {
				continue // bounded map: new agents past the cap aren't tracked
			}
			// First sighting: the cumulative value predates our observation
			// window, so it becomes the baseline without counting as a delta.
			h.agentDropsLast[k.agent] = cur
		case cur > last:
			h.agentDropsLast[k.agent] = cur
			saves = append(saves, pending{k.agent, k.rate, cur - last})
		case cur < last:
			// Counter went backward: agent restart. Re-baseline; the drops
			// accumulated since its restart are real.
			h.agentDropsLast[k.agent] = cur
			if cur > 0 {
				saves = append(saves, pending{k.agent, k.rate, cur})
			}
		}
	}
	h.agentDropsMu.Unlock()

	window := time.Now().UTC().Truncate(time.Minute)
	for _, s := range saves {
		if err := h.db.SaveAgentDrops(s.agent, s.rate, window, s.delta); err != nil {
			log.Printf("recordAgentDrops: agent %s: %v", s.agent, err)
		}
	}
}
