package database

import (
	"strings"
	"testing"
)

// The command result column is NOT encrypted, so a device document that
// carries a secret must never reach it in the clear. The OPNsense
// pre-shared-key search is the case that matters: its rows carry the key
// itself.
func TestRedactProbeCommandResult_BlanksThePreSharedKey(t *testing.T) {
	body := `{"vendor":"opnsense","steps":[{"path":"/api/ipsec/pre_shared_keys/searchItem","status":200,` +
		`"body":"{\"total\":1,\"rows\":[{\"description\":\"fwm-t7\",\"ident\":\"fwm-b\",\"remote_ident\":\"fwm-a\",\"keyType\":\"PSK\",\"Key\":\"SUPERSECRETKEY\",\"uuid\":\"11111111-2222-3333-4444-555555555555\"}]}"}]}`
	out := RedactProbeCommandResult(body)
	if strings.Contains(out, "SUPERSECRETKEY") {
		t.Fatalf("the pre-shared key must never be persisted in the clear: %s", out)
	}
	// Everything else survives: the discovery needs the uuid and the
	// identifiers.
	for _, keep := range []string{"fwm-t7", "fwm-b", "fwm-a", "11111111-2222-3333-4444-555555555555", "pre_shared_keys"} {
		if !strings.Contains(out, keep) {
			t.Errorf("the redaction dropped %q: %s", keep, out)
		}
	}
}

// An ordinary device document is untouched — the shape is precise: a
// pre-shared key carries a "Key" field BESIDE an identifier ("ident" or
// "keyType").
func TestRedactProbeCommandResult_LeavesOrdinaryDocumentsAlone(t *testing.T) {
	body := `{"vendor":"opnsense","steps":[{"path":"/api/ipsec/sad/search","status":200,"body":"{\"total\":1,\"rows\":[{\"name\":\"ike-a\",\"ikeid\":\"a\",\"state\":\"ESTABLISHED\"}]}"}]}`
	if out := RedactProbeCommandResult(body); out != body {
		t.Errorf("an ordinary document must not be rewritten: %s", out)
	}
	// A body that is not JSON is returned unchanged.
	notJSON := "opnsense said something"
	if out := RedactProbeCommandResult(notJSON); out != notJSON {
		t.Errorf("a non-JSON body must be returned unchanged: %s", out)
	}
}

// A key with NO peer identifier ("matches any peer") may have no
// "remote_ident" at all — the secret must still be caught.
func TestRedactProbeCommandResult_CatchesAKeyWithoutAPeerIdentifier(t *testing.T) {
	body := `{"total":1,"rows":[{"description":"fwm-t7","ident":"fwm-b","keyType":"PSK","Key":"SUPERSECRETKEY","uuid":"11111111-2222-3333-4444-555555555555"}]}`
	out := RedactProbeCommandResult(body)
	if strings.Contains(out, "SUPERSECRETKEY") {
		t.Fatalf("a key without a remote_ident must still be redacted: %s", out)
	}
	if !strings.Contains(out, "fwm-b") {
		t.Errorf("the redaction must keep the identifiers: %s", out)
	}
}
