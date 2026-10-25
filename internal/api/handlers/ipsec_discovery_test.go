package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// The device-side discovery: when the server has lost the uuids the apply
// captured, the only way to clean the device is to ASK it. The objects are all
// tagged with the tunnel's name (the owner tag the apply wrote), and the
// OPNsense search endpoints answer with their uuids.

// discoveryIntent builds a policy-based tunnel whose OPNsense end is end B.
func discoveryIntent() *ipsec.TunnelIntent {
	in := &ipsec.TunnelIntent{
		Name: "fwm-discovery", Enabled: true, IKEVersion: ipsec.IKEv2, Mode: ipsec.ModePolicyBased,
	}
	in.Ends[0] = ipsec.EndpointSpec{DeviceID: 1, Vendor: "fortigate", PeerIP: "203.0.113.9",
		LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "fwm-a"}, ProtectedSubnets: []string{"192.168.113.0/24"}}
	in.Ends[1] = ipsec.EndpointSpec{DeviceID: 2, Vendor: "opnsense", PeerIP: "198.51.100.7",
		LocalID: ipsec.IKEIdentity{Type: ipsec.IDTypeFQDN, Value: "fwm-b"}, ProtectedSubnets: []string{"192.168.150.0/24"}}
	return in
}

// The driver must render the searches that locate each object kind, with the
// selectors that make a row OURS rather than merely same-named.
func TestOPNsenseDiscovery_StepsAndSelectors(t *testing.T) {
	drv, ok := ipsec.Driver("opnsense")
	if !ok {
		t.Fatal("no opnsense driver registered")
	}
	disc, ok := drv.(ipsec.Discoverer)
	if !ok {
		t.Fatal("the opnsense driver must implement ipsec.Discoverer")
	}
	steps := disc.Discovery(ipsec.ViewFor(discoveryIntent(), 1))
	if len(steps) == 0 {
		t.Fatal("the driver must render discovery steps")
	}
	byToken := map[string]ipsec.DiscoverStep{}
	for _, s := range steps {
		byToken[s.Token] = s
	}
	conn, ok := byToken["conn"]
	if !ok {
		t.Fatalf("no connection step in %+v", steps)
	}
	if conn.Path != "/api/ipsec/connections/searchConnection" {
		t.Errorf("connection search path = %q", conn.Path)
	}
	if conn.Match["local_addrs"] != "198.51.100.7" || conn.Match["remote_addrs"] != "203.0.113.9" {
		t.Errorf("the connection must be selected by its peer addresses, got %+v", conn.Match)
	}
	if conn.Match["version"] != "2" {
		t.Errorf("the connection must be selected by its IKE version, got %+v", conn.Match)
	}
	psk, ok := byToken["psk"]
	if !ok {
		t.Fatalf("no pre-shared-key step in %+v", steps)
	}
	if psk.Path != "/api/ipsec/pre_shared_keys/searchItem" {
		t.Errorf("psk search path = %q", psk.Path)
	}
	if psk.Match["ident"] != "fwm-b" || psk.Match["remote_ident"] != "fwm-a" {
		t.Errorf("the psk must be selected by its identities, got %+v", psk.Match)
	}
	out, ok := byToken["rule_out_0"]
	if !ok {
		t.Fatalf("no outbound-rule step in %+v", steps)
	}
	// The rule search mirrors the deploy's own collision anchor: the search
	// phrase narrows a rule-heavy box's answer to ours.
	if out.Path != "/api/firewall/filter/searchRule?searchPhrase=fwm-discovery" {
		t.Errorf("rule search path = %q", out.Path)
	}
	if out.Match["source_net"] != "192.168.150.0/24" || out.Match["destination_net"] != "192.168.113.0/24" {
		t.Errorf("the rule must be selected by its subnets, got %+v", out.Match)
	}
	in, ok := byToken["rule_in_0"]
	if !ok {
		t.Fatalf("no inbound-rule step in %+v", steps)
	}
	if in.Match["source_net"] != "192.168.113.0/24" || in.Match["destination_net"] != "192.168.150.0/24" {
		t.Errorf("the inbound rule's selectors must be swapped, got %+v", in.Match)
	}
}

// A row is ours ONLY when the owner tag AND the selectors match. A row with
// someone else's subnets under our name is not ours.
func TestIPSecMatchDiscoveryRow_RequiresDescriptionAndSelectors(t *testing.T) {
	match := map[string]string{"source_net": "10.0.0.0/24", "destination_net": "10.1.0.0/24"}
	row := map[string]any{
		"description":     "fwm-discovery",
		"uuid":            "11111111-2222-3333-4444-555555555555",
		"source_net":      "10.0.0.0/24",
		"destination_net": "10.1.0.0/24",
	}
	ok, fields, unverified := ipsecMatchDiscoveryRow(row, "fwm-discovery", match)
	if !ok {
		t.Fatal("an exactly-matching row must match")
	}
	if fields["description"] != "fwm-discovery" || fields["source_net"] != "10.0.0.0/24" {
		t.Errorf("the matched fields must be reported, got %+v", fields)
	}
	if len(unverified) != 0 {
		t.Errorf("nothing is unverified here, got %v", unverified)
	}

	// A different name is not ours.
	other := map[string]any{"description": "fwm-someone-else", "source_net": "10.0.0.0/24", "destination_net": "10.1.0.0/24"}
	if ok, _, _ := ipsecMatchDiscoveryRow(other, "fwm-discovery", match); ok {
		t.Error("a row with another description must not match")
	}
	// Same name, someone else's subnets: not ours.
	wrong := map[string]any{"description": "fwm-discovery", "source_net": "192.168.0.0/24", "destination_net": "10.1.0.0/24"}
	if ok, _, _ := ipsecMatchDiscoveryRow(wrong, "fwm-discovery", match); ok {
		t.Error("a row whose selectors differ must not match")
	}
	// Same name, the document does not carry the selector: matched, but the
	// operator must see that it was NOT confirmed by it.
	missing := map[string]any{"description": "fwm-discovery", "source_net": "10.0.0.0/24"}
	ok, _, unverified = ipsecMatchDiscoveryRow(missing, "fwm-discovery", match)
	if !ok {
		t.Fatal("a row missing a selector must still match on the owner tag")
	}
	if len(unverified) != 1 || unverified[0] != "destination_net" {
		t.Errorf("the absent selector must be reported as unverified, got %v", unverified)
	}
}

// The parse turns a device's search documents into the uuids the removal can
// address. A malformed uuid is dropped (it could never address an object),
// and a token the device did not report stays UNRESOLVED — it is never
// invented.
func TestIPSecParseDiscovery_FoundUnresolvedAndMalformed(t *testing.T) {
	steps := []ipsec.DiscoverStep{
		{Token: "conn", ObjectType: "connection", Path: "/api/ipsec/connections/searchConnection",
			Match: map[string]string{"local_addrs": "198.51.100.7"}},
		{Token: "psk", ObjectType: "pre_shared_key", Path: "/api/ipsec/pre_shared_keys/searchItem",
			Match: map[string]string{"ident": "fwm-b"}},
	}
	connBody := `{"total":1,"rows":[{"description":"fwm-discovery","uuid":"11111111-2222-3333-4444-555555555555","local_addrs":"198.51.100.7"}]}`
	pskBody := `{"total":1,"rows":[{"description":"fwm-discovery","uuid":"not-a-uuid","ident":"fwm-b"}]}`
	result, _ := json.Marshal(map[string]any{
		"vendor": "opnsense",
		"steps": []map[string]any{
			{"path": "/api/ipsec/connections/searchConnection", "status": 200, "body": connBody},
			{"path": "/api/ipsec/pre_shared_keys/searchItem", "status": 200, "body": pskBody},
		},
	})
	outcome := ipsecParseDiscovery(steps, "fwm-discovery", string(result))
	if outcome.Captures["conn"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("the connection uuid was not discovered: %+v", outcome.Captures)
	}
	if _, ok := outcome.Captures["psk"]; ok {
		t.Error("a malformed uuid must never become a capture")
	}
	if len(outcome.Found) != 1 || outcome.Found[0].Token != "conn" {
		t.Errorf("exactly the connection must be reported, got %+v", outcome.Found)
	}
	if len(outcome.Unresolved) != 1 || outcome.Unresolved[0] != "psk" {
		t.Errorf("the psk must be reported as unresolved, got %v", outcome.Unresolved)
	}
	if len(outcome.Unsearched) != 0 {
		t.Errorf("every search answered here, got unsearched %v", outcome.Unsearched)
	}
	// A body that is not a search document yields nothing at all — and every
	// token counts as NOT searched, so the removal refuses to call the device
	// clean on the strength of a lookup that never happened.
	outcome = ipsecParseDiscovery(steps, "fwm-discovery", "not json")
	if len(outcome.Captures) != 0 || len(outcome.Found) != 0 {
		t.Error("an unparseable result must yield no objects")
	}
	if len(outcome.Unsearched) != len(steps) {
		t.Errorf("an unparseable result must leave every token unsearched, got %v", outcome.Unsearched)
	}
}

// A search the device does not answer leaves the object's absence UNPROVEN:
// the removal must not call the device clean on the strength of a lookup that
// never happened.
func TestIPSecParseDiscovery_UnansweredSearchIsNotAbsence(t *testing.T) {
	steps := []ipsec.DiscoverStep{
		{Token: "conn", ObjectType: "connection", Path: "/api/ipsec/connections/searchConnection"},
		{Token: "psk", ObjectType: "pre_shared_key", Path: "/api/ipsec/pre_shared_keys/searchItem"},
	}
	result, _ := json.Marshal(map[string]any{
		"steps": []map[string]any{
			{"path": "/api/ipsec/connections/searchConnection", "status": 200, "body": `{"rows":[]}`},
			{"path": "/api/ipsec/pre_shared_keys/searchItem", "status": 404, "body": ""},
		},
	})
	outcome := ipsecParseDiscovery(steps, "fwm-discovery", string(result))
	// The connection search answered and found nothing → absence proven.
	if len(outcome.Unresolved) != 1 || outcome.Unresolved[0] != "conn" {
		t.Errorf("the searched-and-empty connection must be unresolved, got %v", outcome.Unresolved)
	}
	// The psk search did not answer → absence NOT proven.
	if len(outcome.Unsearched) != 1 || outcome.Unsearched[0] != "psk" {
		t.Errorf("the unanswered psk search must be unsearched, got %v", outcome.Unsearched)
	}
}

// A search the device does not answer leaves the end UNPROVEN: the removal
// must not call the device clean on the strength of a lookup that never
// happened.
func TestDiscover_UnansweredSearchLeavesTheEndUnproven(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	if resp := discoverReq(t, h, id); resp.code != http.StatusOK {
		t.Fatalf("discover = %d, want 200; body: %s", resp.code, resp.body)
	}
	st := deployStateOf(t, db, id)
	name := id2name(t, db, id)
	// The device answers the connection search and FAILS the psk one.
	result, _ := json.Marshal(map[string]any{
		"steps": []map[string]any{
			{"path": "/api/ipsec/connections/searchConnection", "status": 200, "body": `{"total":0,"rows":[]}`},
			{"path": "/api/ipsec/pre_shared_keys/searchItem", "status": 500, "body": ""},
		},
	})
	if _, _, err := db.CompleteProbeCommand(probe.ID, st.DiscoveryCommandID, "succeeded", string(result)); err != nil {
		t.Fatalf("complete the discovery: %v", err)
	}
	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecDiscovery(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET discover = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data ipsecDiscoveryReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if len(out.Data.Unsearched) == 0 {
		t.Errorf("the unanswered search must be reported as unsearched: %+v", out.Data)
	}
	// The end stays unproven: its absence was never looked for.
	st2 := deployStateOf(t, db, id)
	if !st2.Ends[1].RollbackUnproven {
		t.Error("an end whose objects were not searched for must stay unproven")
	}
	_ = name
}

// A discovery that finds NOTHING proves the device holds none of the tunnel's
// objects: the removal is then a genuine no-op and a clean rolled_back is the
// TRUTH, not a false clean.
func TestDiscover_AnEmptyDeviceIsAProvenCleanRollback(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	deployAndSettle(t, h, db, id, "up")

	if resp := discoverReq(t, h, id); resp.code != http.StatusOK {
		t.Fatalf("discover = %d, want 200; body: %s", resp.code, resp.body)
	}
	st := deployStateOf(t, db, id)
	name := id2name(t, db, id)
	// The device holds nothing of ours: every search answers and finds nothing.
	result, _ := json.Marshal(map[string]any{
		"steps": []map[string]any{
			{"path": "/api/ipsec/connections/searchConnection", "status": 200, "body": `{"total":0,"rows":[]}`},
			{"path": "/api/ipsec/pre_shared_keys/searchItem", "status": 200, "body": `{"total":0,"rows":[]}`},
			{"path": "/api/firewall/filter/searchRule?searchPhrase=" + name, "status": 200, "body": `{"total":0,"rows":[]}`},
		},
	})
	if _, _, err := db.CompleteProbeCommand(probe.ID, st.DiscoveryCommandID, "succeeded", string(result)); err != nil {
		t.Fatalf("complete the discovery: %v", err)
	}
	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecDiscovery(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET discover = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st2 := deployStateOf(t, db, id)
	if st2.Ends[1].DiscoveryState != ipsec.DiscoveryStateClean {
		t.Fatalf("the end must be marked clean, got %q", st2.Ends[1].DiscoveryState)
	}
	if st2.Ends[1].RollbackUnproven {
		t.Error("an end the device provably does not hold must not be unproven")
	}
	// The rollback is a no-op and settles CLEANLY — the truth, not a false clean.
	if rec := rollbackReq(t, h, id); rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	st3 := deployStateOf(t, db, id)
	for _, e := range st3.Rollback.Ends {
		if e.CommandID != "" {
			_, _, _ = db.CompleteProbeCommand(probe.ID, e.CommandID, "succeeded", `{"applied":true,"verified":true}`)
		}
	}
	if data := pollDeploy(t, h, id); data["status"] != "rolled_back" {
		t.Fatalf("an empty device must settle as rolled_back, got %v (note: %v)", data["status"], data["note"])
	}
}

// A discovery that could not ask the device about everything leaves the end
// PARTIAL: it stays unproven AND it can be searched again — otherwise the
// object that was never looked for could never be found.
func TestDiscover_APartialDiscoveryCanBeSearchedAgain(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	deployAndSettle(t, h, db, id, "up")

	if resp := discoverReq(t, h, id); resp.code != http.StatusOK {
		t.Fatalf("discover = %d, want 200; body: %s", resp.code, resp.body)
	}
	st := deployStateOf(t, db, id)
	// The connection search answers; the psk search does not.
	result, _ := json.Marshal(map[string]any{
		"steps": []map[string]any{
			{"path": "/api/ipsec/connections/searchConnection", "status": 200, "body": `{"total":0,"rows":[]}`},
			{"path": "/api/ipsec/pre_shared_keys/searchItem", "status": 500, "body": ""},
		},
	})
	if _, _, err := db.CompleteProbeCommand(probe.ID, st.DiscoveryCommandID, "succeeded", string(result)); err != nil {
		t.Fatalf("complete the discovery: %v", err)
	}
	c, _ := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecDiscovery(c)

	st2 := deployStateOf(t, db, id)
	if st2.Ends[1].DiscoveryState != ipsec.DiscoveryStatePartial {
		t.Fatalf("the end must be marked partial, got %q", st2.Ends[1].DiscoveryState)
	}
	if !st2.Ends[1].RollbackUnproven {
		t.Error("a partially-searched end must stay unproven")
	}
	// And it can be searched AGAIN — otherwise the object that was never
	// looked for could never be found.
	resp := discoverReq(t, h, id)
	if resp.code != http.StatusOK {
		t.Fatalf("a partial discovery must be searchable again: %d, body: %s", resp.code, resp.body)
	}
}

// The device holds MORE THAN ONE object of the same kind: the removal can
// address one uuid per token, so the extra one is reported and the end stays
// unproven — it would otherwise be an invisible leftover.
func TestDiscover_ADuplicateObjectIsReportedAndKeepsTheEndUnproven(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	deployAndSettle(t, h, db, id, "up")

	if resp := discoverReq(t, h, id); resp.code != http.StatusOK {
		t.Fatalf("discover = %d, want 200; body: %s", resp.code, resp.body)
	}
	st := deployStateOf(t, db, id)
	name := id2name(t, db, id)
	intent, _ := database.IPSecModelToIntent(mustTunnel(t, db, id))
	local := intent.Ends[1]
	remote := intent.Ends[0]
	// TWO connections carry our owner tag.
	connBody := `{"total":2,"rows":[` +
		`{"description":"` + name + `","uuid":"11111111-2222-3333-4444-555555555555","local_addrs":"` + local.PeerIP + `","remote_addrs":"` + remote.PeerIP + `","version":"2"},` +
		`{"description":"` + name + `","uuid":"99999999-8888-7777-6666-555555555555","local_addrs":"` + local.PeerIP + `","remote_addrs":"` + remote.PeerIP + `","version":"2"}]}`
	result, _ := json.Marshal(map[string]any{
		"steps": []map[string]any{
			{"path": "/api/ipsec/connections/searchConnection", "status": 200, "body": connBody},
		},
	})
	if _, _, err := db.CompleteProbeCommand(probe.ID, st.DiscoveryCommandID, "succeeded", string(result)); err != nil {
		t.Fatalf("complete the discovery: %v", err)
	}
	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecDiscovery(c)
	var out struct {
		Data ipsecDiscoveryReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if len(out.Data.Found) != 2 {
		t.Fatalf("BOTH connections must be reported, got %+v", out.Data.Found)
	}
	if !out.Data.Found[1].Duplicate {
		t.Error("the second connection must be marked as a duplicate")
	}
	if len(out.Data.Duplicates) == 0 {
		t.Error("the duplicate must be listed")
	}
	st2 := deployStateOf(t, db, id)
	if !st2.Ends[1].RollbackUnproven {
		t.Error("a leftover object means the device is not clean — the end must stay unproven")
	}
}

// discoverReq drives the discovery endpoint for one tunnel.
func discoverReq(t *testing.T, h *Handler, id uint) *httptestResponse {
	t.Helper()
	c, rec := jsonReq(http.MethodPost, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.DiscoverIPSecTunnel(c)
	return &httptestResponse{code: rec.Code, body: rec.Body.String()}
}

type httptestResponse struct {
	code int
	body string
}

// The whole point: a tunnel whose apply's uuids are gone is DISCOVERED on the
// device, and the removal can then address the objects it finds.
func TestDiscover_FindsTheTunnelObjectsOnTheDevice(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	// The apply's uuids are gone (the command result was pruned) — the end has
	// no captures at all.
	st := deployStateOf(t, db, id)
	if len(st.Ends[1].CapturedUUIDs) != 0 {
		t.Fatal("the fixture must start with no captured uuids")
	}

	resp := discoverReq(t, h, id)
	if resp.code != http.StatusOK {
		t.Fatalf("discover = %d, want 200; body: %s", resp.code, resp.body)
	}
	st2 := deployStateOf(t, db, id)
	if st2.DiscoveryCommandID == "" {
		t.Fatal("the discovery probe must be recorded on the deploy record")
	}

	// The collector answers: the device holds a connection and a psk for us.
	// The values are the ones the deploy RENDERED — the driver selects the
	// objects by them, so the device's rows must carry them.
	name := id2name(t, db, id)
	intent, ierr := database.IPSecModelToIntent(mustTunnel(t, db, id))
	if ierr != nil {
		t.Fatalf("decode the intent: %v", ierr)
	}
	local := intent.Ends[1] // the OPNsense end
	remote := intent.Ends[0]
	connBody := `{"total":1,"rows":[{"description":"` + name + `","uuid":"11111111-2222-3333-4444-555555555555","local_addrs":"` +
		local.PeerIP + `","remote_addrs":"` + remote.PeerIP + `","version":"2"}]}`
	pskBody := `{"total":1,"rows":[{"description":"` + name + `","uuid":"22222222-3333-4444-5555-666666666666","ident":"` +
		local.LocalID.Value + `","remote_ident":"` + remote.LocalID.Value + `"}]}`
	result, _ := json.Marshal(map[string]any{
		"vendor": "opnsense",
		"steps": []map[string]any{
			{"path": "/api/ipsec/connections/searchConnection", "status": 200, "body": connBody},
			{"path": "/api/ipsec/pre_shared_keys/searchItem", "status": 200, "body": pskBody},
			{"path": "/api/firewall/filter/searchRule?searchPhrase=" + name, "status": 200, "body": `{"total":0,"rows":[]}`},
		},
	})
	if _, _, err := db.CompleteProbeCommand(probe.ID, st2.DiscoveryCommandID, "succeeded", string(result)); err != nil {
		t.Fatalf("complete the discovery: %v", err)
	}

	// The report is the operator's review — nothing was deleted.
	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(id))}}
	h.GetIPSecDiscovery(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET discover = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data ipsecDiscoveryReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if out.Data.Status != "complete" {
		t.Fatalf("the discovery must be complete, got %q", out.Data.Status)
	}
	if len(out.Data.Found) != 2 {
		t.Fatalf("want 2 discovered objects, got %+v", out.Data.Found)
	}
	if out.Data.Captures["conn"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("the discovered connection uuid is missing: %+v", out.Data.Captures)
	}
	// The device's objects are now addressable: the end is no longer unproven.
	st3 := deployStateOf(t, db, id)
	if len(st3.Ends[1].CapturedUUIDs) == 0 {
		t.Fatal("the discovered uuids must be merged into the deploy record")
	}
	if st3.Ends[1].RollbackUnproven {
		t.Error("a discovered end is proven — it must not be marked unproven")
	}
}

// id2name is the tunnel's name (the owner tag the device carries).
func id2name(t *testing.T, db *database.Database, id uint) string {
	t.Helper()
	row, err := db.GetIPSecTunnel(id)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	return row.Name
}

// mustTunnel reads a tunnel row.
func mustTunnel(t *testing.T, db *database.Database, id uint) *models.IPSecTunnel {
	t.Helper()
	row, err := db.GetIPSecTunnel(id)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	return row
}

// The bulk cleanup asks the device BEFORE it removes anything: an orphan
// whose uuids are unknown is reported as "discovering" rather than rolled back
// blindly.
func TestBulkRollbackOrphaned_DiscoversBeforeRemoving(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	gone := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	live := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", gone.ID, live.ID, 1)
	deployAndSettle(t, h, db, id, "up")
	if err := db.RetireDevice(gone.ID); err != nil {
		t.Fatalf("retire peer: %v", err)
	}
	// The apply's uuids are gone.
	st := deployStateOf(t, db, id)
	if len(st.Ends[1].CapturedUUIDs) != 0 {
		t.Fatal("the fixture must start with no captured uuids")
	}

	report := bulkRollback(t, h)
	if len(report) != 1 {
		t.Fatalf("want the orphan reported, got %d entries: %+v", len(report), report)
	}
	if report[0]["action"] != "discovering" {
		t.Fatalf("action = %v, want discovering (the device must be asked first)", report[0]["action"])
	}
	// The probe is recorded and NO remove command was enqueued.
	st2 := deployStateOf(t, db, id)
	if st2.DiscoveryCommandID == "" {
		t.Fatal("the discovery probe must be recorded")
	}
	cmds, _ := db.GetProbeCommands(probe.ID, 50)
	for _, cmd := range cmds {
		if cmd.Type == database.ProbeCommandTypeIPSecRemove {
			t.Error("nothing may be removed before the device has answered")
		}
	}
}

// The discovery probe is READ-ONLY: it must never carry a write step.
func TestDiscover_ProbeCarriesOnlyReadOnlyGets(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)
	fw := makeFortiDevice(t, db, probe.ID, "203.0.113.9")
	opn := makeOpnsenseDevice(t, db, probe.ID, "198.51.100.7")
	id := createTunnelRow(t, db, "fortigate", "opnsense", fw.ID, opn.ID, 1)
	deployAndSettle(t, h, db, id, "up")

	resp := discoverReq(t, h, id)
	if resp.code != http.StatusOK {
		t.Fatalf("discover = %d, want 200; body: %s", resp.code, resp.body)
	}
	st := deployStateOf(t, db, id)
	cmd, err := db.GetProbeCommandByCommandID(st.DiscoveryCommandID)
	if err != nil || cmd == nil {
		t.Fatalf("read the discovery command: %v", err)
	}
	var payload struct {
		Steps []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"steps"`
	}
	if err := json.Unmarshal([]byte(cmd.Payload), &payload); err != nil {
		t.Fatalf("decode the probe payload: %v", err)
	}
	if len(payload.Steps) == 0 {
		t.Fatal("the discovery probe must ship steps")
	}
	for _, s := range payload.Steps {
		if s.Method != "GET" {
			t.Errorf("the discovery probe must be read-only, got %s %s", s.Method, s.Path)
		}
	}
	_ = context.Background()
}
