// Package ipsectelemetry builds the recurring read-only command that fetches a
// device's IPSec session documents, and holds the step list those documents come
// from.
//
// It lives outside internal/api/handlers because the PRODUCER is the poller: the
// only existing payload builder (ipsecBuildStatusCmd) sits in the handlers
// package, which cmd/poller neither imports nor should. Both processes can reach
// here.
package ipsectelemetry

import (
	"encoding/json"
	"fmt"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"github.com/google/uuid"
)

// OPNsenseSteps are the three documents internal/vpnsession correlates on reqid.
//
// All three are parameterless GETs, which is not incidental: the collector hard-
// refuses any non-GET status step, which is also why searchPhase2 — POST-only —
// is unusable and why the SPD/SAD pair is the route taken instead.
//
//	searchPhase1 → the connection index (phase1desc, remote address)
//	spd/search   → the traffic selectors
//	sad/search   → the byte counters and SA age
var OPNsenseSteps = []ipsec.ProbeStep{
	{Kind: ipsec.StepHTTPAPI, Method: "GET", Path: "/api/ipsec/sessions/searchPhase1"},
	{Kind: ipsec.StepHTTPAPI, Method: "GET", Path: "/api/ipsec/spd/search"},
	{Kind: ipsec.StepHTTPAPI, Method: "GET", Path: "/api/ipsec/sad/search"},
}

// StepsFor returns the session-document steps for a vendor, or nil if this
// vendor has no session telemetry. Nil is a normal answer, not an error: most
// vendors report VPN state over SNMP and need nothing here.
func StepsFor(vendor string) []ipsec.ProbeStep {
	if vendor == "opnsense" {
		return OPNsenseSteps
	}
	return nil
}

// Payload mirrors the shape the collector already understands for read-only
// probes (fwapi.StatusPayload), so ipsec_telemetry rides the existing executor
// rather than needing one of its own.
type Payload struct {
	Vendor      string            `json:"vendor"`
	DeviceID    uint              `json:"device_id"`
	TunnelName  string            `json:"tunnel_name"`
	BaseURL     string            `json:"base_url"`
	APIToken    string            `json:"api_token"`
	InsecureTLS bool              `json:"insecure_tls"`
	Steps       []ipsec.ProbeStep `json:"steps"`
}

// BuildCommand assembles the recurring telemetry command for one device.
//
// Returns (nil, nil) when the device has no session telemetry to fetch — an
// ordinary outcome the caller should skip quietly rather than log.
func BuildCommand(dev *models.Device) (*models.ProbeCommand, error) {
	if dev == nil {
		return nil, fmt.Errorf("nil device")
	}
	steps := StepsFor(dev.Vendor)
	if len(steps) == 0 {
		return nil, nil
	}
	// Not configured for API reads is a normal state, not an error: an OPNsense
	// box monitored over SNMP only has no collector or no token, and erroring
	// here would log the same line every five minutes forever — 288 a day, per
	// device. Nil means "nothing to do", same as an unsupported vendor.
	if dev.ProbeID == nil || *dev.ProbeID == 0 || dev.APIToken == "" {
		return nil, nil
	}
	port := dev.APIPort
	if port == 0 {
		port = 443
	}
	// api_token marshaled intentionally, as for ipsec_status: encrypted at rest
	// in the command row and TLS-delivered to the collector.
	buf, err := json.Marshal(Payload{
		Vendor:      dev.Vendor,
		DeviceID:    dev.ID,
		BaseURL:     fmt.Sprintf("https://%s:%d", dev.IPAddress, port),
		APIToken:    dev.APIToken,
		InsecureTLS: dev.APIInsecureTLS,
		Steps:       steps,
	})
	if err != nil {
		return nil, err
	}
	return &models.ProbeCommand{
		ProbeID:   *dev.ProbeID,
		DeviceID:  dev.ID,
		CommandID: uuid.NewString(),
		Type:      database.ProbeCommandTypeIPSecTelemetry,
		Payload:   string(buf),
	}, nil
}
