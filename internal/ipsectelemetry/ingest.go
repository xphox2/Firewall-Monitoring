package ipsectelemetry

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/vpnsession"
)

// reportView mirrors the collector's fwapi.StatusReport envelope.
type reportView struct {
	Vendor string `json:"vendor"`
	Steps  []struct {
		Path   string `json:"path"`
		Status int    `json:"status"`
		Body   string `json:"body"`
		Note   string `json:"note"`
	} `json:"steps"`
	Error string `json:"error"`
}

// bodyFor returns the body of the step whose path ends with suffix. Matching on
// the path rather than the index means a future reordering of OPNsenseSteps
// cannot silently feed the SPD document in as the SAD one — which would parse
// without error and produce quietly wrong counters.
func (r reportView) bodyFor(suffix string) (string, bool) {
	for _, s := range r.Steps {
		if strings.HasSuffix(s.Path, suffix) {
			return s.Body, true
		}
	}
	return "", false
}

// Ingest turns one ipsec_telemetry command result into per-child-SA rows.
//
// Parsing happens server-side deliberately: internal/vpnsession lives here with
// its fixtures, and the server already parses raw IPSec device documents from
// command results. Moving it collector-side would duplicate a tested parser
// across repos to honour a convention the IPSec path has already set aside.
func Ingest(db database.Store, deviceID uint, result string, now time.Time) ([]models.VPNStatus, error) {
	// Truncation first. A cut result is invalid JSON, so without this check the
	// failure surfaces as an unexplained parse error — and it would recur on
	// every poll, writing nothing, until the tunnel silently aged out.
	if database.ProbeCommandResultTruncated(result) {
		return nil, fmt.Errorf("telemetry result was truncated before storage — raise the "+
			"per-type cap; device %d wrote nothing this cycle", deviceID)
	}

	var rv reportView
	if err := json.Unmarshal([]byte(result), &rv); err != nil {
		return nil, fmt.Errorf("decode telemetry report: %w", err)
	}
	if rv.Error != "" {
		return nil, fmt.Errorf("collector reported: %s", rv.Error)
	}

	phase1, ok1 := rv.bodyFor("searchPhase1")
	spd, ok2 := rv.bodyFor("spd/search")
	sad, ok3 := rv.bodyFor("sad/search")
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("telemetry report missing documents (phase1=%t spd=%t sad=%t)", ok1, ok2, ok3)
	}

	rows, err := vpnsession.ParseOPNsense(deviceID, now, phase1, sad, spd, expectedFor(db, deviceID))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if err := db.SaveVPNStatuses(rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// expectedFor lists the child SAs that SHOULD exist on this device.
//
// A down child leaves no SPD or SAD trace at all, so without this an outage is
// invisible — the tunnel simply reports fewer rows and nothing says why.
//
// Deliberately built from ProvisionedTunnelPair.PathsFor, NOT
// TunnelIntent.PathsFor: the latter returns the full cross product with each
// pair flagged, so feeding it unfiltered would turn every path the operator
// switched OFF into a permanent "down" row — a manufactured outage. This one
// already filters to enabled pairs and already orients local/remote for the
// reporting device, which also disposes of the which-end question.
//
// Best-effort: a device with no provisioned tunnels yields nil, and the parser
// then reports only what it can see.
func expectedFor(db database.Store, deviceID uint) []vpnsession.ExpectedChild {
	pairs, err := db.GetProvisionedTunnelPairs()
	if err != nil || len(pairs) == 0 {
		return nil
	}
	var out []vpnsession.ExpectedChild
	for _, pp := range pairs {
		paths, ok := pp.PathsFor(deviceID)
		if !ok {
			continue // not an endpoint, or no pair-level detail (route-based)
		}
		for _, p := range paths {
			out = append(out, vpnsession.ExpectedChild{
				TunnelName: pp.Name,
				Local:      p[0],
				Remote:     p[1],
			})
		}
	}
	return out
}
