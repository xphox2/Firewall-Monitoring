package vpnsession

import (
	"strings"
	"testing"
	"time"
)

// Fixtures captured from the live OPNsense 26.1 box (device 5, tunnel fwm-t11
// to the FortiGate at 66.179.9.155), via the API controllers' own backing
// commands. The shapes here are load-bearing: two of them encode differences
// between endpoints that a "tidier" single struct would silently break.

// NOTE phase1desc IS present here — the connection description is exposed by
// sessions/searchPhase1 even though the SAD/SPD documents cannot carry it.
const phase1Fixture = `{"total":1,"rowCount":1,"rows":[
 {"local-addrs":"%any","remote-addrs":"66.179.9.155","local-id":"opnsense","remote-id":"techlabs-fw-01",
  "version":"IKEv2","connected":true,"ikeid":"91f25bb5-f9c9-41e6-876b-6232560cc1f3",
  "phase1desc":"fwm-t11","name":"91f25bb5-f9c9-41e6-876b-6232560cc1f3","install-time":"55"}]}`

// reqid is a STRING here.
const spdFixture = `{"rowCount":2,"rows":[
 {"src":"192.168.13.0/24","dst":"192.168.50.0/24","dir":"in","reqid":"2",
  "src-dst":["66.179.9.155","192.168.5.107"]},
 {"src":"192.168.50.0/24","dst":"192.168.13.0/24","dir":"out","reqid":"2",
  "src-dst":["192.168.5.107","66.179.9.155"]}]}`

// reqid is a NUMBER here — the same field, typed differently by the other
// endpoint. Verified on the live box.
const sadFixture = `{"rowCount":2,"rows":[
 {"src":"192.168.5.107[4500]","dst":"66.179.9.155[4500]","spi":"ad878099","reqid":2,
  "state":"mature","bytes_current":381524,"addtime_diff":1677},
 {"src":"66.179.9.155[4500]","dst":"192.168.5.107[4500]","spi":"c11c373a","reqid":2,
  "state":"mature","bytes_current":197340,"addtime_diff":1677}]}`

func parse(t *testing.T, p1, sad, spd string, exp ...ExpectedChild) []rowView {
	t.Helper()
	rows, err := ParseOPNsense(5, time.Now(), p1, sad, spd, exp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	out := make([]rowView, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowView{r.TunnelName, r.Phase1Name, r.Status,
			r.LocalSubnet, r.RemoteSubnet, r.BytesIn, r.BytesOut, r.TunnelUptime})
	}
	return out
}

type rowView struct {
	name, phase1, status, local, remote string
	in, out, uptime                     uint64
}

// The whole point: one row per child, carrying its own selectors and counters.
func TestParseOPNsense_PerChildRow(t *testing.T) {
	rows := parse(t, phase1Fixture, sadFixture, spdFixture)
	if len(rows) != 1 {
		t.Fatalf("want 1 child row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.status != "up" {
		t.Errorf("status = %q, want up", r.status)
	}
	if r.local != "192.168.50.0/24" || r.remote != "192.168.13.0/24" {
		t.Errorf("selectors = %s → %s, want the OUT direction (local→remote)", r.local, r.remote)
	}
	// Direction is decided by which SA's source is this box.
	if r.out != 381524 {
		t.Errorf("bytes_out = %d, want 381524 (the SA sourced from 192.168.5.107)", r.out)
	}
	if r.in != 197340 {
		t.Errorf("bytes_in = %d, want 197340", r.in)
	}
}

// TunnelName must be unique per child or GetAllLatestVPNStatuses — which keeps
// only the newest row per (device_id, tunnel_name) — collapses a multi-subnet
// tunnel to one row. Phase1Name must stay the bare provisioned name so the
// connection map's provisioned attribution still matches.
func TestParseOPNsense_MultiChildNamingIsDistinctButShareaParent(t *testing.T) {
	spd := `{"rows":[
	 {"src":"192.168.50.0/24","dst":"192.168.13.0/24","dir":"out","reqid":"2","src-dst":["192.168.5.107","66.179.9.155"]},
	 {"src":"192.168.50.0/24","dst":"192.168.25.0/24","dir":"out","reqid":"3","src-dst":["192.168.5.107","66.179.9.155"]}]}`
	sad := `{"rows":[
	 {"src":"192.168.5.107[4500]","reqid":2,"bytes_current":100,"addtime_diff":10},
	 {"src":"192.168.5.107[4500]","reqid":3,"bytes_current":200,"addtime_diff":10}]}`

	rows := parse(t, phase1Fixture, sad, spd)
	if len(rows) != 2 {
		t.Fatalf("want 2 child rows, got %d", len(rows))
	}
	if rows[0].name == rows[1].name {
		t.Fatalf("both children got tunnel_name %q — the newest-per-name query would "+
			"discard one, which is exactly the multi-subnet case this exists for", rows[0].name)
	}
	if rows[0].phase1 != "fwm-t11" || rows[1].phase1 != "fwm-t11" {
		t.Errorf("both children must share phase1_name fwm-t11; got %q and %q",
			rows[0].phase1, rows[1].phase1)
	}
}

// THE 404 TRAP. The name is passed in a URL PATH by every chart caller and gin
// routes on the decoded path, so an escaped slash becomes a real separator.
func TestParseOPNsense_TunnelNameIsURLPathSafe(t *testing.T) {
	rows := parse(t, phase1Fixture, sadFixture, spdFixture)
	for _, r := range rows {
		if strings.ContainsAny(r.name, "/?#") {
			t.Errorf("tunnel_name %q contains a URL-path metacharacter — the chart route "+
				"/api/devices/:id/vpn/:tunnel/chart would 404 on it", r.name)
		}
	}
}

// A down child leaves NO trace on the box — no SAD entry, no SPD policy — so
// without synthesis the row silently vanishes and the alert path, which needs a
// literal down row, never fires.
func TestParseOPNsense_ExpectedChildAbsentIsReportedDown(t *testing.T) {
	rows := parse(t, phase1Fixture, `{"rows":[]}`, `{"rows":[]}`,
		ExpectedChild{TunnelName: "fwm-t11", Local: "192.168.50.0/24", Remote: "192.168.13.0/24"})

	if len(rows) != 1 {
		t.Fatalf("an expected-but-absent child must produce a down row, got %d rows", len(rows))
	}
	r := rows[0]
	if r.status != "down" {
		t.Errorf("status = %q, want down", r.status)
	}
	// Zero counters and zero uptime keep the ever-up gate honest: a child that
	// never established must not become alertable on first sight.
	if r.in != 0 || r.out != 0 || r.uptime != 0 {
		t.Errorf("a synthesized down row must carry zero counters and zero uptime; got in=%d out=%d uptime=%d",
			r.in, r.out, r.uptime)
	}
}

// A child that IS present must not also be synthesized as down.
func TestParseOPNsense_PresentChildIsNotDuplicatedAsDown(t *testing.T) {
	rows := parse(t, phase1Fixture, sadFixture, spdFixture,
		ExpectedChild{TunnelName: "fwm-t11", Local: "192.168.50.0/24", Remote: "192.168.13.0/24"})
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 row, got %d: %+v", len(rows), rows)
	}
	if rows[0].status != "up" {
		t.Errorf("status = %q, want up", rows[0].status)
	}
}

// During rekey two SAs share one reqid AND direction. Summing them inflates the
// counter for the overlap and then drops when the old SA expires — a drop the
// downstream reset-clamp re-counts as a full cumulative, spiking every chart.
func TestParseOPNsense_RekeyOverlapTakesNewestNotSum(t *testing.T) {
	sad := `{"rows":[
	 {"src":"192.168.5.107[4500]","reqid":2,"bytes_current":900,"addtime_diff":3900,"state":"dying"},
	 {"src":"192.168.5.107[4500]","reqid":2,"bytes_current":50,"addtime_diff":30,"state":"mature"}]}`

	rows := parse(t, phase1Fixture, sad, spdFixture)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].out == 950 {
		t.Fatal("the two overlapping SAs were SUMMED — every rekey would spike the chart")
	}
	if rows[0].out != 50 {
		t.Errorf("bytes_out = %d, want 50 (the newest SA, age 30s)", rows[0].out)
	}
}

// Two connections to the same peer cannot be told apart from these documents.
// Guessing would put an authoritative-looking name on the wrong tunnel.
func TestParseOPNsense_AmbiguousPeerFallsBackFromTheDescription(t *testing.T) {
	p1 := `{"rows":[
	 {"remote-addrs":"66.179.9.155","phase1desc":"fwm-t11","name":"uuid-a"},
	 {"remote-addrs":"66.179.9.155","phase1desc":"fwm-t99","name":"uuid-b"}]}`

	rows := parse(t, p1, sadFixture, spdFixture)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if strings.HasPrefix(rows[0].name, "fwm-t11") || strings.HasPrefix(rows[0].name, "fwm-t99") {
		t.Errorf("ambiguous peer must NOT be attributed to either tunnel; got %q", rows[0].name)
	}
}

// A tunnel we did not provision has no description; the UUID is the only stable
// identity available.
func TestParseOPNsense_UnnamedTunnelUsesTheConnectionUUID(t *testing.T) {
	p1 := `{"rows":[{"remote-addrs":"66.179.9.155","phase1desc":"","name":"91f25bb5-uuid"}]}`
	rows := parse(t, p1, sadFixture, spdFixture)
	if len(rows) != 1 || !strings.HasPrefix(rows[0].name, "91f25bb5-uuid") {
		t.Errorf("want the UUID as the name stem, got %+v", rows)
	}
}

// An unparseable document must fail the whole batch. A partial view is
// indistinguishable from "these tunnels went away", and deriving down rows from
// it would raise false outages.
func TestParseOPNsense_PartialDocumentIsFatal(t *testing.T) {
	for name, docs := range map[string][3]string{
		"phase1": {`{"rows":[`, sadFixture, spdFixture},
		"sad":    {phase1Fixture, `{"rows":[`, spdFixture},
		"spd":    {phase1Fixture, sadFixture, `{"rows":[`},
	} {
		if _, err := ParseOPNsense(5, time.Now(), docs[0], docs[1], docs[2], nil); err == nil {
			t.Errorf("%s: an unparseable document must error, not yield partial rows", name)
		}
	}
}

// An IKE SA can be established with no child installed — that state moves no
// packets and is exactly what should read as down.
func TestParseOPNsense_ConnectedWithNoInstalledChildIsDown(t *testing.T) {
	rows := parse(t, phase1Fixture, `{"rows":[]}`, spdFixture)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].status != "down" {
		t.Errorf("status = %q — a policy with no installed SA carries no traffic", rows[0].status)
	}
	if rows[0].uptime != 0 {
		t.Errorf("uptime = %d, want 0 — a non-installed child must not arm the ever-up gate", rows[0].uptime)
	}
}

// THE MIRRORED TWO-SUBNET CASE. v0.11.168 made multiple local subnets per
// endpoint first-class, so a tunnel can fan out local×remote. From OPNsense's
// side the FortiGate's two subnets are REMOTE (distinct), but the mirror —
// two LOCAL subnets to one remote — produces children whose remote selector is
// identical. Naming on the remote selector alone collapses them, and
// GetAllLatestVPNStatuses keeps only the newest.
func TestParseOPNsense_MultiLocalSubnetChildrenDoNotCollide(t *testing.T) {
	spd := `{"rows":[
	 {"src":"192.168.50.0/24","dst":"192.168.13.0/24","dir":"out","reqid":"2","src-dst":["192.168.5.107","66.179.9.155"]},
	 {"src":"192.168.60.0/24","dst":"192.168.13.0/24","dir":"out","reqid":"3","src-dst":["192.168.5.107","66.179.9.155"]}]}`
	sad := `{"rows":[
	 {"src":"192.168.5.107[4500]","reqid":2,"bytes_current":100,"addtime_diff":10},
	 {"src":"192.168.5.107[4500]","reqid":3,"bytes_current":200,"addtime_diff":10}]}`

	rows := parse(t, phase1Fixture, sad, spd)
	if len(rows) != 2 {
		t.Fatalf("want 2 child rows, got %d", len(rows))
	}
	if rows[0].name == rows[1].name {
		t.Fatalf("two children sharing one REMOTE selector both got %q — the "+
			"newest-per-name query discards one. The name must carry BOTH selectors.", rows[0].name)
	}
}

// When this box is the RESPONDER to a dynamic peer the driver renders
// remote_addrs as "%any", so searchPhase1 offers no address to join on while
// the kernel SPD holds the peer's observed address. Leaving the child unnamed
// would empty Phase1Name — the field the connection map matches provisioned
// tunnels on — dropping the row back to IP matching against a NAT address.
func TestParseOPNsense_WildcardPeerStillNamesASoleConnection(t *testing.T) {
	p1 := `{"rows":[{"local-addrs":"%any","remote-addrs":"%any","phase1desc":"fwm-t11","name":"uuid-a"}]}`
	rows := parse(t, p1, sadFixture, spdFixture)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].phase1 != "fwm-t11" {
		t.Errorf("phase1_name = %q, want fwm-t11 — with exactly one connection on the box, "+
			"elimination is not a guess, and an empty phase1_name loses provisioned attribution",
			rows[0].phase1)
	}
}

// But elimination only holds when there IS one connection. With several and no
// address match, naming one of them would be a guess wearing a trusted label.
func TestParseOPNsense_WildcardPeerWithSeveralConnectionsRefusesToGuess(t *testing.T) {
	p1 := `{"rows":[
	 {"remote-addrs":"%any","phase1desc":"fwm-t11","name":"uuid-a"},
	 {"remote-addrs":"%any","phase1desc":"fwm-t99","name":"uuid-b"}]}`
	rows := parse(t, p1, sadFixture, spdFixture)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].phase1 == "fwm-t11" || rows[0].phase1 == "fwm-t99" {
		t.Errorf("phase1_name = %q — with two wildcard connections there is no evidence "+
			"which one this child belongs to", rows[0].phase1)
	}
}

// A child that IS established but whose connection could not be NAMED falls
// back to the UUID. The expected-children list uses the provisioned name, so if
// the "already seen" bookkeeping is keyed on the name, the same child is
// reported twice: once up under the UUID and once synthesized down under the
// provisioned name. An operator would see a phantom outage next to a working
// tunnel — worse than either alone.
func TestParseOPNsense_UnnamedButPresentChildIsNotAlsoReportedDown(t *testing.T) {
	// Two connections, neither joinable by address, so naming falls back to UUID.
	p1 := `{"rows":[
	 {"remote-addrs":"%any","phase1desc":"fwm-t11","name":"uuid-a"},
	 {"remote-addrs":"%any","phase1desc":"fwm-t99","name":"uuid-b"}]}`

	rows := parse(t, p1, sadFixture, spdFixture,
		ExpectedChild{TunnelName: "fwm-t11", Local: "192.168.50.0/24", Remote: "192.168.13.0/24"})

	var up, down int
	for _, r := range rows {
		switch r.status {
		case "up":
			up++
		case "down":
			down++
		}
	}
	if up == 1 && down == 1 {
		t.Fatalf("the same child was reported BOTH up and down: %+v", rows)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 row for 1 child, got %d: %+v", len(rows), rows)
	}
}
