package database

import (
	"testing"
	"time"

	"firewall-mon/internal/classify"
	"firewall-mon/internal/models"
)

// threatRow seeds one flow sample the way ingest stamps it: service port and
// category from the classifier.
type threatRow struct {
	dir              uint8
	src              string
	sport            uint16
	dst              string
	dport            uint16
	proto            uint8
	flag, tcp, fwEvt uint8
	age              time.Duration
	bytes            uint64
}

func seedThreatRows(t *testing.T, d *Database, now time.Time, rows ...threatRow) {
	t.Helper()
	for _, r := range rows {
		proto := r.proto
		if proto == 0 {
			proto = 6
		}
		b := r.bytes
		if b == 0 {
			b = 100
		}
		fs := models.FlowSample{
			Timestamp: now.Add(-r.age), DeviceID: 1, SamplerAddress: "10.9.0.1",
			SrcAddr: r.src, DstAddr: r.dst, SrcPort: r.sport, DstPort: r.dport, Protocol: proto,
			Bytes: b, Packets: 1, SamplingRate: 1, TCPFlags: r.tcp, Direction: r.dir,
			ThreatFlag: r.flag, FirewallEvent: r.fwEvt,
			ServicePort: classify.ServicePort(proto, r.sport, r.dport),
			AppCategory: uint8(classify.Classify(proto, r.sport, r.dport, r.tcp)),
		}
		if err := d.db.Create(&fs).Error; err != nil {
			t.Fatalf("seed flow: %v", err)
		}
	}
}

func threatTopAt(t *testing.T, d *Database, now time.Time) *NOCThreatTop {
	t.Helper()
	feedClock(t, now)
	top, err := d.getNOCThreatTop()
	if err != nil {
		t.Fatalf("getNOCThreatTop: %v", err)
	}
	return top
}

func findEntry(list []ThreatEntry, addr string) *ThreatEntry {
	for i := range list {
		if list[i].Addr == addr {
			return &list[i]
		}
	}
	return nil
}

const (
	bad  = "203.0.113.9"
	bad2 = "198.51.100.7"
	ours = "10.0.0.5"
)

// A session is a request row and a reply row, one in each direction. It must
// count once, in the list of the side that started it.
func TestNOCThreats_RequestReplyPairIsOneRequestInTheInitiatorsList(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		// Inbound: a flagged scanner reaches our SSH.
		threatRow{dir: 1, src: bad, sport: 51000, dst: ours, dport: 22, flag: 1, age: 10 * time.Second},
		threatRow{dir: 2, src: ours, sport: 22, dst: bad, dport: 51000, flag: 2, age: 10 * time.Second},
		// Outbound: our host connects to a flagged web server.
		threatRow{dir: 2, src: "10.0.0.7", sport: 50000, dst: bad2, dport: 443, flag: 2, age: 5 * time.Second},
		threatRow{dir: 1, src: bad2, sport: 443, dst: "10.0.0.7", dport: 50000, flag: 1, age: 5 * time.Second},
	)
	top := threatTopAt(t, d, now)

	in, out := findEntry(top.Inbound, bad), findEntry(top.Outbound, bad2)
	if in == nil || in.Requests != 1 || in.Service != 22 || in.Bytes != 200 {
		t.Errorf("inbound %s = %+v, want 1 request to service 22, 200 bytes", bad, in)
	}
	if out == nil || out.Requests != 1 || out.Service != 443 || len(out.InternalHosts) != 1 || out.InternalHosts[0] != "10.0.0.7" {
		t.Errorf("outbound %s = %+v, want 1 request to 443 from 10.0.0.7", bad2, out)
	}
	if findEntry(top.Outbound, bad) != nil || findEntry(top.Inbound, bad2) != nil {
		t.Error("an address appears in both lists; the reply row was classified by its own direction")
	}
	if top.Summary.Inbound != 1 || top.Summary.Outbound != 1 {
		t.Errorf("summary = %+v, want inbound 1 and outbound 1 (request records)", top.Summary)
	}
	if in.Inferred || out.Inferred || !in.IPMatch {
		t.Errorf("known-port IP matches must be neither inferred nor ASN-only: in=%+v out=%+v", in, out)
	}
}

func TestNOCThreats_UnclassifiableRows(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: bad, sport: 123, dst: ours, dport: 123, proto: 17, flag: 1, age: time.Second}, // equal ports
		threatRow{dir: 1, src: bad2, dst: ours, proto: 1, flag: 1, age: time.Second},                         // ICMP
	)
	top := threatTopAt(t, d, now)
	if len(top.Inbound)+len(top.Outbound) != 0 {
		t.Errorf("unclassifiable rows produced entries: in=%+v out=%+v", top.Inbound, top.Outbound)
	}
	if top.Summary.Unclassified != 2 {
		t.Errorf("unclassified = %d, want 2", top.Summary.Unclassified)
	}
}

// A SYN names the initiator even when the ports point the other way — the
// spoofed-source-port scan (nmap -g 443).
func TestNOCThreats_SYNOverridesThePortRule(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: bad, sport: 443, dst: ours, dport: 51234, flag: 1, tcp: 2, age: time.Second})
	top := threatTopAt(t, d, now)
	if e := findEntry(top.Inbound, bad); e == nil || e.Requests != 1 {
		t.Errorf("SYN from %s: inbound entry %+v, want 1 request (the port rule alone says outbound)", bad, e)
	}
	if findEntry(top.Outbound, bad) != nil {
		t.Error("the SYN was ignored: the scanner is listed as one of our hosts connecting out")
	}
}

// Both ports well-known and no SYN: the stored service port is the lower one,
// the shape of a spoofed-source scan. Our side's port decides, marked inferred,
// and the request is still counted.
func TestNOCThreats_BothKnownPortsUseOurSide(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: bad, sport: 53, dst: ours, dport: 445, flag: 1, age: time.Second})
	top := threatTopAt(t, d, now)
	e := findEntry(top.Inbound, bad)
	if e == nil || e.Requests != 1 || !e.Inferred || e.Service != 445 {
		t.Errorf("bad:53 -> our:445 = %+v, want inbound, 1 request to 445, inferred", e)
	}
}

func TestNOCThreats_GuessedServicePortIsInferred(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: bad, sport: 51000, dst: ours, dport: 2222, flag: 1, age: time.Second})
	top := threatTopAt(t, d, now)
	if e := findEntry(top.Inbound, bad); e == nil || !e.Inferred {
		t.Errorf("a service port outside the known table must be marked inferred: %+v", e)
	}
}

// Only the external side's flag counts; transit and internal rows are "other".
func TestNOCThreats_OtherRows(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: bad, sport: 51000, dst: ours, dport: 22, flag: 2, age: time.Second}, // flag on OUR side
		threatRow{dir: 4, src: bad, sport: 51000, dst: bad2, dport: 22, flag: 1, age: time.Second}, // transit
		threatRow{dir: 3, src: ours, sport: 51000, dst: "10.0.0.8", dport: 22, flag: 1, age: time.Second},
	)
	top := threatTopAt(t, d, now)
	if len(top.Inbound)+len(top.Outbound) != 0 || top.Summary.Other != 3 {
		t.Errorf("entries in=%+v out=%+v other=%d, want none and other=3", top.Inbound, top.Outbound, top.Summary.Other)
	}
}

func TestNOCThreats_WindowBlockedAndASNRanking(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: "192.0.2.1", sport: 51000, dst: ours, dport: 22, flag: 1, age: 61 * time.Second}, // outside
		// Only the reply half of a session is inside the window: no request, no entry.
		threatRow{dir: 2, src: ours, sport: 22, dst: "192.0.2.2", dport: 51000, flag: 2, age: time.Second},
		threatRow{dir: 1, src: bad, sport: 51000, dst: ours, dport: 22, flag: 1, fwEvt: 3, age: time.Second}, // denied
		// An ASN-only match with more requests still ranks after the IP match.
		threatRow{dir: 1, src: bad2, sport: 51001, dst: ours, dport: 22, flag: 4, age: time.Second},
		threatRow{dir: 1, src: bad2, sport: 51002, dst: ours, dport: 22, flag: 4, age: time.Second},
	)
	top := threatTopAt(t, d, now)
	if findEntry(top.Inbound, "192.0.2.1") != nil {
		t.Error("a flow older than 60 s is in the list")
	}
	if findEntry(top.Inbound, "192.0.2.2") != nil {
		t.Error("an address with only a reply row (0 requests) is listed")
	}
	if top.Summary.Blocked != 1 {
		t.Errorf("blocked = %d, want 1", top.Summary.Blocked)
	}
	if len(top.Inbound) != 2 || top.Inbound[0].Addr != bad || top.Inbound[1].IPMatch {
		t.Errorf("inbound order = %+v, want the IP match first and the ASN-only match marked", top.Inbound)
	}
}

// A SYN decides the whole session: the reply (SYN|ACK, flags 18) must not fall
// to the port rule and land in the opposite list. Flags 18 also pins the
// "SYN without ACK" mask.
func TestNOCThreats_SYNDecidesTheReplyToo(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		threatRow{dir: 1, src: bad, sport: 443, dst: ours, dport: 51234, flag: 1, tcp: 2, age: 2 * time.Second},
		threatRow{dir: 2, src: ours, sport: 51234, dst: bad, dport: 443, flag: 2, tcp: 18, age: time.Second},
	)
	top := threatTopAt(t, d, now)
	if e := findEntry(top.Inbound, bad); e == nil || e.Requests != 1 || e.Bytes != 200 {
		t.Errorf("inbound %s = %+v, want 1 request and both halves' bytes", bad, e)
	}
	if e := findEntry(top.Outbound, bad); e != nil {
		t.Errorf("the SYN session's reply was listed outbound: %+v", e)
	}
	if top.Summary.Inbound != 1 || top.Summary.Outbound != 0 {
		t.Errorf("summary = %+v, want inbound 1, outbound 0", top.Summary)
	}
}

func TestNOCThreats_InternalHostsCappedAndCounted(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	var rows []threatRow
	for i, host := range []string{"10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"} {
		for j := 0; j <= i; j++ { // 10.0.0.14 makes the most requests
			rows = append(rows, threatRow{dir: 2, src: host, sport: uint16(50000 + 10*i + j), dst: bad2, dport: 443, flag: 2, age: time.Second})
		}
	}
	seedThreatRows(t, d, now, rows...)
	e := findEntry(threatTopAt(t, d, now).Outbound, bad2)
	if e == nil || e.InternalCount != 4 || len(e.InternalHosts) != nocThreatMaxHosts || e.InternalHosts[0] != "10.0.0.14" {
		t.Errorf("outbound %s = %+v, want the top %d hosts (busiest first) and a count of 4", bad2, e, nocThreatMaxHosts)
	}
}

// "inferred" means most requests rest on a guessed service port.
func TestNOCThreats_InferredIsAMajorityOfRequests(t *testing.T) {
	d := NewDatabaseForTesting(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedThreatRows(t, d, now,
		// bad: 1 known (22) + 2 guessed (2222) -> inferred
		threatRow{dir: 1, src: bad, sport: 51000, dst: ours, dport: 22, flag: 1, age: time.Second},
		threatRow{dir: 1, src: bad, sport: 51001, dst: ours, dport: 2222, flag: 1, age: time.Second},
		threatRow{dir: 1, src: bad, sport: 51002, dst: ours, dport: 2222, flag: 1, age: time.Second},
		// bad2: 2 known + 1 guessed -> not inferred
		threatRow{dir: 1, src: bad2, sport: 51000, dst: ours, dport: 22, flag: 1, age: time.Second},
		threatRow{dir: 1, src: bad2, sport: 51001, dst: ours, dport: 22, flag: 1, age: time.Second},
		threatRow{dir: 1, src: bad2, sport: 51002, dst: ours, dport: 2222, flag: 1, age: time.Second},
		// the replies of bad2's guessed request must not tip it
		threatRow{dir: 2, src: ours, sport: 2222, dst: bad2, dport: 51002, flag: 2, age: time.Second},
		threatRow{dir: 2, src: ours, sport: 2222, dst: bad2, dport: 51002, flag: 2, age: time.Second},
	)
	top := threatTopAt(t, d, now)
	if e := findEntry(top.Inbound, bad); e == nil || !e.Inferred {
		t.Errorf("%s = %+v, want inferred (2 of 3 requests guessed)", bad, e)
	}
	if e := findEntry(top.Inbound, bad2); e == nil || e.Inferred {
		t.Errorf("%s = %+v, want not inferred (1 of 3 requests guessed)", bad2, e)
	}
}
