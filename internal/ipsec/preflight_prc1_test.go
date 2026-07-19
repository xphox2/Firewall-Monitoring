package ipsec_test

import (
	"strings"
	"testing"

	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors"
)

// TestPreflightProbe_Fortigate pins that the FortiGate preflight emits ONLY
// read-only GETs: an auth/version check plus cmdb reads of the exact objects
// Render creates (all named after the tunnel), each marked ExpectAbsent.
func TestPreflightProbe_Fortigate(t *testing.T) {
	intent := canonicalIntent()
	d, ok := ipsec.Driver("fortigate")
	if !ok {
		t.Fatal("no fortigate driver")
	}
	steps := d.PreflightProbe(ipsec.ViewFor(intent, 0))
	if len(steps) == 0 {
		t.Fatal("no preflight steps")
	}
	var sawAuth, sawPhase1 bool
	for _, s := range steps {
		if s.Method != "GET" {
			t.Errorf("preflight step %q is %s, must be GET (read-only)", s.Check, s.Method)
		}
		switch s.Check {
		case "auth":
			sawAuth = true
			if s.ExpectAbsent {
				t.Error("auth check must not be ExpectAbsent")
			}
		case "phase1":
			sawPhase1 = true
			if !strings.Contains(s.Path, intent.Name) {
				t.Errorf("phase1 path %q missing tunnel name %q", s.Path, intent.Name)
			}
			if !s.ExpectAbsent {
				t.Error("phase1 collision check must be ExpectAbsent")
			}
			if !strings.Contains(s.Path, "/api/v2/cmdb/vpn.ipsec/phase1-interface/") {
				t.Errorf("unexpected phase1 path %q", s.Path)
			}
		}
	}
	if !sawAuth || !sawPhase1 {
		t.Errorf("missing auth (%t) or phase1 (%t) check", sawAuth, sawPhase1)
	}
}

// TestPreflightProbe_OPNsense pins the OPNsense preflight is read-only GETs with
// an auth check + a connection collision search.
func TestPreflightProbe_OPNsense(t *testing.T) {
	intent := canonicalIntent()
	d, ok := ipsec.Driver("opnsense")
	if !ok {
		t.Fatal("no opnsense driver")
	}
	steps := d.PreflightProbe(ipsec.ViewFor(intent, 1))
	var sawAuth, sawConn bool
	for _, s := range steps {
		if s.Method != "GET" {
			t.Errorf("preflight step %q is %s, must be GET", s.Check, s.Method)
		}
		switch s.Check {
		case "auth":
			sawAuth = true
		case "connection":
			sawConn = true
			if !s.ExpectAbsent {
				t.Error("connection collision check must be ExpectAbsent")
			}
		}
	}
	if !sawAuth || !sawConn {
		t.Errorf("missing auth (%t) or connection (%t) check", sawAuth, sawConn)
	}
}
