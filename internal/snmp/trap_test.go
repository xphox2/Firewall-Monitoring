package snmp

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"

	"github.com/gosnmp/gosnmp"
)

// newTestReceiver builds a receiver with a set community (community/rate-limit
// paths are unused by parseTrap directly).
func newTestReceiver(t *testing.T) *TrapReceiver {
	t.Helper()
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = "public"
	rcv, err := NewTrapReceiver(cfg)
	if err != nil {
		t.Fatalf("NewTrapReceiver: %v", err)
	}
	return rcv
}

var testTrapAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.50")}

// TestParseTrap_ClassifiesByTrapOIDValue is the AUDIT-296 regression: a vendor
// notification OID arrives ONLY as the VALUE of the snmpTrapOID.0 varbind (RFC
// 3418), never as a varbind name. The pre-fix phase-2 loop matched varbind
// NAMES against the registry, so this packet classified as nothing and parseTrap
// returned nil — the trap was silently discarded. The fix classifies by the
// snmpTrapOID.0 value, matching the collector.
func TestParseTrap_ClassifiesByTrapOIDValue(t *testing.T) {
	t.Parallel()
	rcv := newTestReceiver(t)

	// .1.3.6.1.4.1.25461.2.1.3.2.0.1747 = PaloAlto vpn-tunnel-down (critical),
	// registered in vendor_paloalto.go TrapOIDs.
	const paVPNDown = ".1.3.6.1.4.1.25461.2.1.3.2.0.1747"
	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(12345)},
			{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: paVPNDown},
			{Name: ".1.3.6.1.4.1.25461.2.1.3.2.1.1", Type: gosnmp.OctetString, Value: []byte("tunnel to HQ down")},
		},
	}

	trap := rcv.parseTrap(packet, testTrapAddr)
	if trap == nil {
		t.Fatal("parseTrap returned nil for a trap whose notification OID is in snmpTrapOID.0's value (pre-fix drop); want a classified TrapEvent")
	}
	if trap.TrapType != "vpn-tunnel-down" {
		t.Errorf("TrapType = %q, want vpn-tunnel-down", trap.TrapType)
	}
	if trap.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", trap.Severity)
	}
	if trap.TrapOID != paVPNDown {
		t.Errorf("TrapOID = %q, want %q", trap.TrapOID, paVPNDown)
	}
	// The message must be built from a representative DATA varbind, not the
	// snmpTrapOID.0/sysUpTime wrappers.
	if !strings.Contains(trap.Message, "tunnel to HQ down") {
		t.Errorf("Message = %q, want it to include the data varbind payload", trap.Message)
	}
}

// TestParseTrap_NameBasedFallbackStillWorks proves the fallback path is kept:
// a device that (non-standardly) sends the notification OID as a varbind NAME
// still classifies.
func TestParseTrap_NameBasedFallbackStillWorks(t *testing.T) {
	t.Parallel()
	rcv := newTestReceiver(t)

	const paVPNUp = ".1.3.6.1.4.1.25461.2.1.3.2.0.1746" // vpn-tunnel-up (info)
	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{Name: paVPNUp, Type: gosnmp.OctetString, Value: []byte("up")},
		},
	}
	trap := rcv.parseTrap(packet, testTrapAddr)
	if trap == nil {
		t.Fatal("parseTrap returned nil; name-based fallback must still classify a notification OID sent as a varbind name")
	}
	if trap.TrapType != "vpn-tunnel-up" {
		t.Errorf("TrapType = %q, want vpn-tunnel-up", trap.TrapType)
	}
}

// TestParseLinkTrap_IfColumnDotBoundary is the AUDIT-297 regression: the switch
// used HasPrefix without a trailing dot, so ifIndex (...2.2.1.1) prefix-matched
// ...2.2.1.10..19. A varbind in column 10 (...2.2.1.10.x) must NOT be read as
// ifIndex; the real ifIndex column (...2.2.1.1.x) must be.
func TestParseLinkTrap_IfColumnDotBoundary(t *testing.T) {
	t.Parallel()
	rcv := newTestReceiver(t)

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: oidLinkDown},
			// Real ifIndex column (...2.2.1.1.7): value 7 is the interface index.
			{Name: oidIfIndex + ".7", Type: gosnmp.Integer, Value: 7},
			// A different IF-MIB column that begins with ...2.2.1.1 as a text
			// prefix (...2.2.1.10.99) — pre-fix this was misread as ifIndex,
			// clobbering it with 99.
			{Name: ".1.3.6.1.2.1.2.2.1.10.99", Type: gosnmp.Counter32, Value: uint(4096)},
		},
	}

	trap := rcv.parseLinkTrap(packet)
	if trap == nil {
		t.Fatal("parseLinkTrap returned nil for a linkDown trap")
	}
	if !strings.Contains(trap.Message, "ifIndex=7") {
		t.Errorf("Message = %q, want ifIndex=7 (column 10 must not be misread as ifIndex)", trap.Message)
	}
	if strings.Contains(trap.Message, "ifIndex=4096") || strings.Contains(trap.Message, "ifIndex=99") {
		t.Errorf("Message = %q: a ...2.2.1.10 varbind was misread as ifIndex", trap.Message)
	}
}

// TestFormatTrapMessage_SanitizeAndCap is the AUDIT-239 regression: an
// OctetString varbind's raw bytes must be stripped of control characters (CR/LF
// forge log lines — CWE-117) and the whole message capped at 256 chars before
// it reaches the log and the DB.
func TestFormatTrapMessage_SanitizeAndCap(t *testing.T) {
	t.Parallel()
	rcv := newTestReceiver(t)

	payload := "line1\nline2\r\ninjected\x1bESC" + strings.Repeat("A", 1024)
	v := gosnmp.SnmpPDU{
		Name:  ".1.3.6.1.4.1.25461.2.1.3.2.1.1",
		Type:  gosnmp.OctetString,
		Value: []byte(payload),
	}
	msg := rcv.formatTrapMessage(v, ".1.3.6.1.4.1.25461.2.1.3.2.0.1747")

	if strings.ContainsAny(msg, "\n\r") || strings.Contains(msg, "\x1b") {
		t.Errorf("Message %q still contains control characters", msg)
	}
	if r := []rune(msg); len(r) > 256 {
		t.Errorf("Message length = %d runes, want <= 256", len(r))
	}
}

// TestTrapReceiver_Start_RequiresCommunity locks in AUDIT-012: an empty
// SNMP_TRAP_COMMUNITY must cause Start to fail. The pre-AUDIT code
// short-circuited the community check when the configured value was
// empty, so the listener accepted every UDP packet on port 162 — which
// is the open-relay shape we're closing.
func TestTrapReceiver_Start_RequiresCommunity(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = ""
	cfg.SNMP.TrapListenAddr = "127.0.0.1:0" // unused, Start returns before binding

	rcv, err := NewTrapReceiver(cfg)
	if err != nil {
		t.Fatalf("NewTrapReceiver: %v", err)
	}
	err = rcv.Start(func(*models.TrapEvent) {})
	if err == nil {
		t.Fatal("Start with empty TrapCommunity returned no error; must refuse to start")
	}
	if !contains(err.Error(), "SNMP_TRAP_COMMUNITY") {
		t.Errorf("error %q does not mention SNMP_TRAP_COMMUNITY by name", err.Error())
	}
}

// TestTrapReceiver_Enabled_AUDIT094 locks in the graceful-disable behavior: with
// no SNMP_TRAP_COMMUNITY, Enabled() is false so the daemon idles instead of
// fatal-exiting (which under the entrypoint supervisor crash-looped the whole
// container). With a community set, Enabled() is true.
func TestTrapReceiver_Enabled_AUDIT094(t *testing.T) {
	t.Parallel()

	on := &config.Config{}
	on.SNMP.TrapCommunity = "public"
	r1, err := NewTrapReceiver(on)
	if err != nil {
		t.Fatalf("NewTrapReceiver(on): %v", err)
	}
	if !r1.Enabled() {
		t.Error("Enabled() = false with a community set, want true")
	}

	off := &config.Config{} // empty community
	r2, err := NewTrapReceiver(off)
	if err != nil {
		t.Fatalf("NewTrapReceiver(off): %v", err)
	}
	if r2.Enabled() {
		t.Error("Enabled() = true with an empty community, want false")
	}
}

// TestTrapReceiver_Allow_BurstThenRefill exercises the per-IP token-bucket
// rate limiter at unit-test scale (using a fast refill rate so tests stay
// quick). Asserts:
//   - First `burst` calls succeed (burst capacity).
//   - The next call fails (bucket empty).
//   - After waiting long enough to refill 1 token, one more call succeeds.
func TestTrapReceiver_Allow_BurstThenRefill(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing/concurrency-dependent test in -short mode (AUDIT-142)")
	}
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = "x" // not used by allow()
	rcv, _ := NewTrapReceiver(cfg)
	// Override defaults for a fast deterministic test: 100/s, burst 5.
	rcv.rlRate = 100.0
	rcv.rlBurst = 5.0

	const ip = "192.0.2.1"
	for i := 0; i < 5; i++ {
		if !rcv.allow(ip) {
			t.Fatalf("call %d: expected allow=true (within burst)", i+1)
		}
	}
	if rcv.allow(ip) {
		t.Fatal("call 6: expected allow=false (burst exhausted)")
	}
	// Wait long enough for 1 token to refill (1/100s = 10ms; sleep 30ms
	// for clock-jitter safety).
	time.Sleep(30 * time.Millisecond)
	if !rcv.allow(ip) {
		t.Fatal("after 30ms: expected allow=true (token refilled)")
	}
}

// TestTrapReceiver_Allow_PerIPIsolated verifies that exhausting one IP's
// bucket does not affect a different IP's bucket — a spoofing-defense
// requirement (one bad IP must not block all others).
func TestTrapReceiver_Allow_PerIPIsolated(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = "x"
	rcv, _ := NewTrapReceiver(cfg)
	rcv.rlRate = 1.0
	rcv.rlBurst = 3.0

	const ipA = "192.0.2.10"
	const ipB = "192.0.2.20"

	// Drain ipA.
	for i := 0; i < 3; i++ {
		if !rcv.allow(ipA) {
			t.Fatalf("ipA call %d: expected allow=true", i+1)
		}
	}
	if rcv.allow(ipA) {
		t.Fatal("ipA call 4: expected allow=false")
	}
	// ipB must still be fully refreshed.
	for i := 0; i < 3; i++ {
		if !rcv.allow(ipB) {
			t.Fatalf("ipB call %d: expected allow=true (independent of ipA)", i+1)
		}
	}
}

// TestTrapReceiver_Allow_MapCapped — the per-IP map must not grow without
// bound when an attacker sprays unique source IPs. After hitting the cap,
// new IPs are rejected.
func TestTrapReceiver_Allow_MapCapped(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = "x"
	rcv, _ := NewTrapReceiver(cfg)
	// Test against the production cap (maxRateLimitedIPs) by filling it
	// then asserting the (cap+1)th IP is rejected.
	for i := 0; i < maxRateLimitedIPs; i++ {
		ip := uniqueIP(i)
		if !rcv.allow(ip) {
			t.Fatalf("ip %s (i=%d): expected allow=true while cap not reached", ip, i)
		}
	}
	if rcv.allow("198.51.100.99") {
		t.Fatal("new IP after cap: expected allow=false (map capped to prevent OOM)")
	}
	// But an existing tracked IP is still serviced (only NEW IPs are rejected).
	// uniqueIP(0) was just inserted with tokens=burst-1. Drain to 0, then
	// expect the next call to fail (not because of cap — because of bucket).
	first := uniqueIP(0)
	// Force-set tokens to 0 so we don't depend on burst arithmetic.
	rcv.rlMu.Lock()
	rcv.rlBuckets[first].tokens = 0
	rcv.rlBuckets[first].last = time.Now()
	rcv.rlMu.Unlock()
	if rcv.allow(first) {
		t.Fatal("drained existing IP: expected allow=false")
	}
}

// TestTrapReceiver_Allow_ConcurrencySafe runs allow() from N goroutines
// under -race. The total accepted count must not exceed the burst.
func TestTrapReceiver_Allow_ConcurrencySafe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing/concurrency-dependent test in -short mode (AUDIT-142)")
	}
	cfg := &config.Config{}
	cfg.SNMP.TrapCommunity = "x"
	rcv, _ := NewTrapReceiver(cfg)
	rcv.rlRate = 0.0 // no refill during the test
	rcv.rlBurst = 10.0

	const ip = "203.0.113.1"
	const goroutines = 50
	const callsPer = 5

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := 0; c < callsPer; c++ {
				if rcv.allow(ip) {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	// With burst=10 and no refill, at most 10 of the 250 calls can succeed.
	if allowed > 10 {
		t.Errorf("allowed=%d, want <=10 (burst); concurrent calls leaked tokens", allowed)
	}
	if allowed < 10 {
		t.Errorf("allowed=%d, want 10 (burst); concurrent calls dropped tokens (over-conservative locking)", allowed)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// uniqueIP returns a unique IPv4 string for i in [0, 65536). Used to fill
// the rate-limit map past its cap without hitting NAT-shaped collisions.
func uniqueIP(i int) string {
	a := (i >> 8) & 0xff
	b := i & 0xff
	// 100.64.0.0/10 is CGNAT, guaranteed not to clash with localhost / RFC1918
	// rejections elsewhere in the test suite.
	return formatIPv4(100, 64+byte(a>>2), byte(a<<6)|byte(b>>2), byte(b<<6))
}

func formatIPv4(a, b, c, d byte) string {
	return itoa(int(a)) + "." + itoa(int(b)) + "." + itoa(int(c)) + "." + itoa(int(d))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [4]byte
	n := 0
	for i > 0 {
		buf[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	// reverse
	for j := 0; j < n/2; j++ {
		buf[j], buf[n-1-j] = buf[n-1-j], buf[j]
	}
	return string(buf[:n])
}
