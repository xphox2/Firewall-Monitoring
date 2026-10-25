package snmp

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const prefilterCommunity = "d18-test-community-0123"

// encodeV2cTrap builds a real SNMPv2c trap datagram with gosnmp's encoder.
func encodeV2cTrap(t *testing.T, community string, version gosnmp.SnmpVersion) []byte {
	t.Helper()
	pkt := &gosnmp.SnmpPacket{
		Version:   version,
		Community: community,
		PDUType:   gosnmp.SNMPv2Trap,
		RequestID: 1,
		Variables: []gosnmp.SnmpPDU{
			{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(100)},
			{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: oidLinkDown},
			{Name: oidIfIndex + ".3", Type: gosnmp.Integer, Value: 3},
		},
	}
	b, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatalf("marshal trap: %v", err)
	}
	return b
}

func TestTrapCommunity_Header(t *testing.T) {
	msg := encodeV2cTrap(t, prefilterCommunity, gosnmp.Version2c)
	got, ok := trapCommunity(msg)
	if !ok || string(got) != prefilterCommunity {
		t.Fatalf("trapCommunity = %q, %v; want %q, true", got, ok, prefilterCommunity)
	}
	v1 := encodeV2cTrap(t, "v1-community", gosnmp.Version1)
	if got, ok := trapCommunity(v1); !ok || string(got) != "v1-community" {
		t.Errorf("v1 header: got %q, %v", got, ok)
	}

	// Re-encode the outer length in long form (0x82 hi lo): same result.
	_, body, _, ok := berTLV(msg)
	if !ok {
		t.Fatal("berTLV rejected a gosnmp-encoded message")
	}
	long := append([]byte{0x30, 0x82, byte(len(body) >> 8), byte(len(body))}, body...)
	if got, ok := trapCommunity(long); !ok || string(got) != prefilterCommunity {
		t.Errorf("long-form length: got %q, %v", got, ok)
	}

	bad := map[string][]byte{
		"empty":            {},
		"not a sequence":   append([]byte{0x31}, msg[1:]...),
		"truncated":        msg[:10],
		"length overflow":  {0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01},
		"indefinite len":   {0x30, 0x80, 0x02, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00},
		"version 3":        {0x30, 0x08, 0x02, 0x01, 0x03, 0x04, 0x03, 'a', 'b', 'c'},
		"community not OS": {0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 'a', 'b', 'c'},
		"community short":  {0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x09, 'a', 'b', 'c'},
	}
	for name, b := range bad {
		if c, ok := trapCommunity(b); ok {
			t.Errorf("%s: accepted (community %q)", name, c)
		}
	}
}

// TestHandleDatagram_PrefilterOrder pins D-18: a wrong-community datagram is
// dropped before the rate limiters (it must not create a per-source bucket),
// and the receiver-wide cap stops authenticated traffic beyond its budget.
func TestHandleDatagram_PrefilterOrder(t *testing.T) {
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = prefilterCommunity
	rcv, _ := NewTrapReceiver(cfg)
	var got int
	rcv.handler = func(*models.TrapEvent) { got++ }
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.77")}
	want := []byte(prefilterCommunity)

	rcv.handleDatagram(encodeV2cTrap(t, "wrong-community-xxxxxx", gosnmp.Version2c), src, want)
	if got != 0 {
		t.Fatalf("wrong community reached the handler")
	}
	if n := len(rcv.rlBuckets); n != 0 {
		t.Fatalf("wrong-community datagram created %d rate-limit bucket(s); the community check must run first", n)
	}

	rcv.handleDatagram(encodeV2cTrap(t, prefilterCommunity, gosnmp.Version2c), src, want)
	if got != 1 {
		t.Fatalf("valid trap: handler calls = %d, want 1", got)
	}

	// Exhaust the global budget: with burst 2 and no refill, only 2 more of
	// these (from fresh sources, so the per-source limiter is not the cause)
	// may pass.
	rcv.globalTokens, rcv.globalBurst, rcv.globalRate = 2, 2, 0
	for i := 0; i < 5; i++ {
		rcv.handleDatagram(encodeV2cTrap(t, prefilterCommunity, gosnmp.Version2c),
			&net.UDPAddr{IP: net.IPv4(198, 51, 100, byte(i+1))}, want)
	}
	if got != 3 {
		t.Errorf("handler calls = %d after the global cap, want 3", got)
	}
}

// TestTrapReceiver_StartDoesNotBlock_EndToEnd drives the real socket: Start
// must return (the caller's prune/refresh/shutdown code runs after it), a
// valid trap reaches the handler, a forged one does not, an INFORM is
// acknowledged, and Stop ends the read loop.
func TestTrapReceiver_StartDoesNotBlock_EndToEnd(t *testing.T) {
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = prefilterCommunity
	cfg.SNMP.TrapListenAddr = "127.0.0.1:0"
	rcv, _ := NewTrapReceiver(cfg)

	var mu sync.Mutex
	var traps []*models.TrapEvent
	started := make(chan error, 1)
	go func() {
		started <- rcv.Start(func(tr *models.TrapEvent) {
			mu.Lock()
			traps = append(traps, tr)
			mu.Unlock()
		})
	}()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start blocked instead of returning after binding the socket")
	}
	defer rcv.Stop()
	port := rcv.conn.LocalAddr().(*net.UDPAddr).Port

	send := func(community string, inform bool) error {
		g := &gosnmp.GoSNMP{
			Target: "127.0.0.1", Port: uint16(port), Community: community,
			Version: gosnmp.Version2c, Timeout: 2 * time.Second, Retries: 0,
		}
		if err := g.Connect(); err != nil {
			return err
		}
		defer g.Conn.Close()
		_, err := g.SendTrap(gosnmp.SnmpTrap{IsInform: inform, Variables: []gosnmp.SnmpPDU{
			{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: oidLinkDown},
			{Name: oidIfIndex + ".7", Type: gosnmp.Integer, Value: 7},
		}})
		return err
	}

	if err := send("forged-community-xxxxxxx", false); err != nil {
		t.Fatalf("send forged: %v", err)
	}
	if err := send(prefilterCommunity, true); err != nil {
		t.Fatalf("INFORM was not acknowledged: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(traps)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(traps) != 1 {
		t.Fatalf("handler received %d traps, want exactly 1 (the authenticated INFORM)", len(traps))
	}
	if traps[0].TrapType == "" || !bytes.Equal([]byte(traps[0].SourceIP), []byte("127.0.0.1")) {
		t.Errorf("unexpected trap: %+v", traps[0])
	}

	rcv.Stop()
	select {
	case <-rcv.done:
	case <-time.After(3 * time.Second):
		t.Fatal("read loop did not exit after Stop")
	}
}

// TestAllowGlobal_RefillsAndCounts covers the receiver-wide bucket's refill
// and its drop accounting (reason="global").
func TestAllowGlobal_RefillsAndCounts(t *testing.T) {
	rcv, _ := NewTrapReceiver(&config.Config{})
	rcv.globalTokens, rcv.globalBurst, rcv.globalRate = 1, 1, 1000
	before := testutil.ToFloat64(trapRateLimitDrops.WithLabelValues("global"))
	if !rcv.allowGlobal() {
		t.Fatal("first datagram refused with a full bucket")
	}
	if rcv.allowGlobal() {
		t.Fatal("second immediate datagram allowed past an empty burst-1 bucket")
	}
	if got := testutil.ToFloat64(trapRateLimitDrops.WithLabelValues("global")) - before; got != 1 {
		t.Errorf("global drops counted = %v, want 1", got)
	}
	time.Sleep(5 * time.Millisecond) // 1000/s refills a token in 1ms
	if !rcv.allowGlobal() {
		t.Error("bucket did not refill over time")
	}
}

// TestHandleDatagram_CommunityDropCounted: a forged datagram is visible in
// fwmon_trap_community_drops_total even though it never touches a limiter.
func TestHandleDatagram_CommunityDropCounted(t *testing.T) {
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = prefilterCommunity
	rcv, _ := NewTrapReceiver(cfg)
	before := testutil.ToFloat64(trapCommunityDrops)
	rcv.handleDatagram(encodeV2cTrap(t, "forged-community-yyyyyyy", gosnmp.Version2c),
		&net.UDPAddr{IP: net.ParseIP("192.0.2.9")}, []byte(prefilterCommunity))
	if got := testutil.ToFloat64(trapCommunityDrops) - before; got != 1 {
		t.Errorf("community drops counted = %v, want 1", got)
	}
}

func TestTrapReceiver_RejectsNonUDPListen(t *testing.T) {
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = prefilterCommunity
	cfg.SNMP.TrapListenAddr = "tcp://127.0.0.1:0"
	rcv, _ := NewTrapReceiver(cfg)
	err := rcv.Start(func(*models.TrapEvent) {})
	if err == nil || !strings.Contains(err.Error(), "only UDP") {
		rcv.Stop()
		t.Fatalf("Start(tcp://) = %v, want an only-UDP error", err)
	}
}

// TestHandleDatagram_HandlerPanicPropagates: the decode recover must not
// swallow a bug in the alert handler.
func TestHandleDatagram_HandlerPanicPropagates(t *testing.T) {
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = prefilterCommunity
	rcv, _ := NewTrapReceiver(cfg)
	rcv.handler = func(*models.TrapEvent) { panic("handler bug") }
	defer func() {
		if recover() == nil {
			t.Error("handler panic was swallowed by handleDatagram")
		}
	}()
	rcv.handleDatagram(encodeV2cTrap(t, prefilterCommunity, gosnmp.Version2c),
		&net.UDPAddr{IP: net.ParseIP("192.0.2.10")}, []byte(prefilterCommunity))
}
