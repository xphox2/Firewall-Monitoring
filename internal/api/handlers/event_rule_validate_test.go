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
