package snmp

import (
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/config"
	"firewall-mon/internal/models"
)

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
