package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"firewall-mon/internal/models"
)

// The list response must state the SERVER'S delete rule per row.
//
// The status alone cannot tell a `draft` (no deploy record — deletable) from a
// partially-deployed `error` (record kept — the server refuses the delete). The
// deploy record is the removal snapshot and is never serialized, so without
// this flag the UI can only approximate — and an enabled delete that always
// answers 409 is a lie the operator has to learn the hard way.
func TestListIPSecTunnels_StatesTheDeleteRule(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)

	deletable := func() bool {
		t.Helper()
		c, rec := jsonReq(http.MethodGet, "/x", "")
		h.ListIPSecTunnels(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("list = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data []struct {
				ID        uint   `json:"id"`
				Name      string `json:"name"`
				Status    string `json:"status"`
				Deletable bool   `json:"deletable"`
				Editable  bool   `json:"editable"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		for _, row := range resp.Data {
			if row.ID == id {
				return row.Deletable
			}
		}
		t.Fatalf("tunnel %d not in the list response", id)
		return false
	}

	// A draft tunnel carries no deploy record → the intent may be deleted.
	if !deletable() {
		t.Error("a draft tunnel (no deploy record) must be deletable")
	}
	// After a deploy the record exists → the server refuses the delete.
	deployAndSettle(t, h, db, id, "up")
	if deletable() {
		t.Error("a tunnel with a deploy record must NOT be deletable")
	}
	// And the row still carries the fields the console needs.
	c, rec := jsonReq(http.MethodGet, "/x", "")
	h.ListIPSecTunnels(c)
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data) == 0 {
		t.Fatal("the list is empty")
	}
	for _, field := range []string{"id", "name", "status", "deletable", "editable"} {
		if _, ok := resp.Data[0][field]; !ok {
			t.Errorf("the list row is missing %q", field)
		}
	}
	// The removal snapshot must never be serialized.
	if _, leaked := resp.Data[0]["deploy_json"]; leaked {
		t.Error("the deploy record must not be serialized")
	}
	var _ models.IPSecTunnel
}
