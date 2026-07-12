package handlers

import (
	"testing"

	"firewall-mon/internal/models"
)

// validateEventRule gained a "state" source + dampen_json validation in the
// unified-alerting phase 1. These pin the new branches without a DB.

func TestValidateEventRule_StateSourceAllowed(t *testing.T) {
	r := &models.EventRule{
		Name:       "Interface down",
		Source:     "state",
		Action:     "alert",
		MatchJSON:  `{"op":"eq","field":"event_type","value":"interface_down"}`,
		DampenJSON: `{"refire_mode":"episode","min_up_seconds":3600,"daily_cap":1}`,
	}
	if msg := validateEventRule(r); msg != "" {
		t.Fatalf("valid state rule rejected: %s", msg)
	}
}

func TestValidateEventRule_StateEmptyDampenOK(t *testing.T) {
	r := &models.EventRule{Name: "S", Source: "state", Action: "alert"}
	if msg := validateEventRule(r); msg != "" {
		t.Fatalf("empty dampen_json should be allowed (defaults apply): %s", msg)
	}
}

func TestValidateEventRule_StateBadDampenRejected(t *testing.T) {
	cases := map[string]string{
		"malformed json": `{not json`,
		"bad refire":     `{"refire_mode":"nope"}`,
		"negative min":   `{"min_up_seconds":-5}`,
		"negative cap":   `{"daily_cap":-1}`,
	}
	for name, dj := range cases {
		r := &models.EventRule{Name: "S", Source: "state", Action: "alert", DampenJSON: dj}
		if msg := validateEventRule(r); msg == "" {
			t.Errorf("%s: expected rejection, got none", name)
		}
	}
}

func TestValidateEventRule_UnknownSourceRejected(t *testing.T) {
	r := &models.EventRule{Name: "S", Source: "telepathy", Action: "alert"}
	if msg := validateEventRule(r); msg == "" {
		t.Fatal("unknown source should be rejected")
	}
}

// Metric source (Phase 2) — validateEventRule allows source=metric and validates
// the threshold dampen_json.

func TestValidateEventRule_MetricSourceAllowed(t *testing.T) {
	r := &models.EventRule{
		Name:       "CPU high",
		Source:     "metric",
		Action:     "alert",
		MatchJSON:  `{"op":"eq","field":"event_type","value":"cpu_high"}`,
		DampenJSON: `{"mode":"zscore","threshold":90,"clear_threshold":80,"zscore_k":3}`,
	}
	if msg := validateEventRule(r); msg != "" {
		t.Fatalf("valid metric rule rejected: %s", msg)
	}
}

func TestValidateEventRule_MetricEmptyAndModeOnlyOK(t *testing.T) {
	for _, dj := range []string{"", `{"mode":"static"}`} {
		r := &models.EventRule{Name: "M", Source: "metric", Action: "alert", DampenJSON: dj}
		if msg := validateEventRule(r); msg != "" {
			t.Errorf("dampen_json %q should be allowed: %s", dj, msg)
		}
	}
}

func TestValidateEventRule_MetricBadDampenRejected(t *testing.T) {
	cases := map[string]string{
		"malformed":     `{oops`,
		"bad mode":      `{"mode":"magic"}`,
		"neg threshold": `{"threshold":-1}`,
		"neg k":         `{"zscore_k":-2}`,
		"inverted band": `{"threshold":90,"clear_threshold":95}`,
	}
	for name, dj := range cases {
		r := &models.EventRule{Name: "M", Source: "metric", Action: "alert", DampenJSON: dj}
		if msg := validateEventRule(r); msg == "" {
			t.Errorf("%s: expected rejection, got none", name)
		}
	}
}

// Spike + trap sources (Phase 3) — validateEventRule allows both; spike validates
// its dampen_json, trap carries none.

func TestValidateEventRule_SpikeSourceAllowed(t *testing.T) {
	r := &models.EventRule{
		Name: "Traffic spike", Source: "spike", Action: "alert",
		MatchJSON:  `{"op":"eq","field":"event_type","value":"traffic_spike"}`,
		DampenJSON: `{"stddev_k":3,"min_duration_minutes":15}`,
	}
	if msg := validateEventRule(r); msg != "" {
		t.Fatalf("valid spike rule rejected: %s", msg)
	}
}

func TestValidateEventRule_SpikeBadDampenRejected(t *testing.T) {
	cases := map[string]string{
		"malformed": `{nope`,
		"neg k":     `{"stddev_k":-1}`,
		"neg dur":   `{"min_duration_minutes":-5}`,
	}
	for name, dj := range cases {
		r := &models.EventRule{Name: "S", Source: "spike", Action: "alert", DampenJSON: dj}
		if msg := validateEventRule(r); msg == "" {
			t.Errorf("%s: expected rejection, got none", name)
		}
	}
}

func TestValidateEventRule_TrapSourceAllowed(t *testing.T) {
	r := &models.EventRule{
		Name: "HA member down", Source: "trap", Action: "alert",
		AlertType: models.AlertTypeHAMemberDown,
		MatchJSON: `{"op":"eq","field":"trap_type","value":"HA_MEMBER_DOWN"}`,
	}
	if msg := validateEventRule(r); msg != "" {
		t.Fatalf("valid trap rule rejected: %s", msg)
	}
}
