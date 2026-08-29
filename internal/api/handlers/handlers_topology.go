package handlers

import (
	"log"
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/l2infer"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// L2 topology ingestion (relay schema v5). Both endpoints receive STATE
// SNAPSHOTS: each batch is the device's complete current table for the entry
// types / protocols it contains, and the save REPLACES those scopes (see
// database/topology.go). Batch caps: the collector self-caps the combined
// ARP+FDB payload at 4000 rows/device, below the 5000 here, so a well-behaved
// collector's snapshot is never truncated server-side — truncating a replace
// batch would silently draw wrong links.

// normalizeTopologyMAC canonicalizes a relayed MAC into the lowercase colon
// form the inference joins on: full canonicalization via l2infer.NormalizeMAC
// when the value parses as a MAC (also accepts hyphen/Cisco-dot forms — the
// FDB SQL filter would silently match nothing on a non-colon form), else a
// lowercase/trim fallback (LLDP chassis IDs are legitimately non-MAC strings).
func normalizeTopologyMAC(s string) string {
	if mac := l2infer.NormalizeMAC(s); mac != "" {
		return mac
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// clampIngestTimestamp bounds a collector-controlled timestamp: zero → now,
// future → now, implausibly ancient → now. An unclamped future timestamp
// would pin the row as the newest sample forever (MAX(timestamp) "latest"
// queries), defeat the telemetry staleness staircase, and never be purged by
// retention — and a value more than 6 months in the FUTURE would have no
// partition. Recent-past timestamps are left untouched on purpose:
// legitimately delayed/spooled batches carry a real past collection time.
//
// AUDIT-204 (review fix): the ancient lower bound exists because the
// collector's generic BSD/RFC3164 syslog parser emits YEAR-0 timestamps (the
// layout has no year field; only the FortiGate parser clamps), and a single
// stored year-0 row used to stretch the aggregation window walk across
// millennia of empty windows. No legitimate spool is older than this bound —
// the deepest outage spool is days, not decades.
//
// AUDIT T1: every Receive* writer that trusts the collector's timestamp must
// run it through this (previously only the topology path did; the high-volume
// telemetry writers only replaced a zero value).
func clampIngestTimestamp(ts, now time.Time) time.Time {
	if ts.IsZero() || ts.After(now) || ts.Year() < 2000 {
		return now
	}
	return ts
}

func (h *Handler) ReceiveTopologyEntries(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	entries, ok := decodeCappedProbeBatch[models.TopologyEntry](h, c, probe, "topology-entries", 5000)
	if !ok {
		return
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := entries[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range entries {
		if entries[i].DeviceID == 0 {
			continue // unattributed rows are junk under per-device replace semantics
		}
		if allowedDevices != nil && !allowedDevices[entries[i].DeviceID] {
			continue // skip data for devices not assigned to this probe
		}
		if entries[i].EntryType != "arp" && entries[i].EntryType != "fdb" {
			continue
		}
		entries[i].Timestamp = clampIngestTimestamp(entries[i].Timestamp, now)
		entries[i].ID = 0 // server-assigned
		entries[i].MACAddress = normalizeTopologyMAC(entries[i].MACAddress)
		// An FDB row whose MAC didn't canonicalize can never join against
		// interface MACs — drop it rather than store dead weight. ARP rows
		// keep the fallback: an empty/odd MAC with a valid IP still feeds
		// the IP-fallback match.
		if entries[i].EntryType == "fdb" && l2infer.NormalizeMAC(entries[i].MACAddress) == "" {
			continue
		}
		filtered = append(filtered, entries[i])
		// Bump with now, not the entry timestamps: snapshots are never spooled
		// (send-or-drop), so arrival IS collection time, and ARP/FDB timestamps
		// are probe-controlled values with their own clamp above.
		deviceTimes[entries[i].DeviceID] = now
	}

	if err := h.db.SaveTopologyEntriesSnapshot(filtered); err != nil {
		log.Printf("Probe %d: failed to save topology entries snapshot: %v", probe.ID, err)
		httputil.InternalError(c, "Failed to save topology entries", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)

	log.Printf("Probe %d: saved %d/%d topology entries", probe.ID, len(filtered), len(entries))
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}

func (h *Handler) ReceiveTopologyNeighbors(c *gin.Context) {
	probe, ok := h.validateProbe(c)
	if !ok {
		return
	}
	batchID, dup := h.batchDedupCheck(c, probe.ID)
	if dup {
		return
	}
	defer h.markBatchIfOK(c, probe.ID, batchID)
	neighbors, ok := decodeCappedProbeBatch[models.TopologyNeighbor](h, c, probe, "topology-neighbors", 500)
	if !ok {
		return
	}

	allowedDevices := h.probeDeviceIDs(probe.ID)
	now := time.Now()
	filtered := neighbors[:0]
	deviceTimes := make(map[uint]time.Time)
	for i := range neighbors {
		if neighbors[i].DeviceID == 0 {
			continue
		}
		if allowedDevices != nil && !allowedDevices[neighbors[i].DeviceID] {
			continue
		}
		if neighbors[i].Protocol != "lldp" && neighbors[i].Protocol != "cdp" {
			continue
		}
		neighbors[i].Timestamp = clampIngestTimestamp(neighbors[i].Timestamp, now)
		neighbors[i].ID = 0
		// Chassis IDs are MAC-form when the neighbor advertised subtype
		// macAddress — normalize so the inference's ownership join works.
		neighbors[i].RemoteChassisID = normalizeTopologyMAC(neighbors[i].RemoteChassisID)
		filtered = append(filtered, neighbors[i])
		// Bump with now — see ReceiveTopologyEntries: snapshots never spool.
		deviceTimes[neighbors[i].DeviceID] = now
	}

	if err := h.db.SaveTopologyNeighborsSnapshot(filtered); err != nil {
		log.Printf("Probe %d: failed to save topology neighbors snapshot: %v", probe.ID, err)
		httputil.InternalError(c, "Failed to save topology neighbors", err)
		return
	}

	h.bumpDevicesOnline(deviceTimes, now)

	log.Printf("Probe %d: saved %d/%d topology neighbors", probe.ID, len(filtered), len(neighbors))
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(filtered)}))
}
