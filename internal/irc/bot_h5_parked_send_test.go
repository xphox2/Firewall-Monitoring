package irc

import (
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"

	irclib "github.com/thoj/go-ircevent"
)

// These tests pin the H5 parked-send fix (2026-08 prod wedge): a send into a
// dead connection's full pwrite buffer parks forever — Disconnect() cannot
// free it because its irc.Wait() deadlocks on the library's own pingLoop
// parked on the same channel, so close(pwrite) is never reached. Every IRC
// write must therefore be timeout-bounded, and every loop must advance past
// a parked target instead of wedging for the process lifetime.
//
// Test double: a fresh irclib.IRC() connection is connected-looking
// (Connected() == true, stopped is zero-value false) with a nil pwrite —
// a send into it parks forever, exactly like the prod dead conn. No mocks.

// shortenSendTimeout drops ircSendTimeout for one test. These tests must not
// use t.Parallel — the var is package-global.
func shortenSendTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := ircSendTimeout
	ircSendTimeout = d
	t.Cleanup(func() { ircSendTimeout = old })
}

// withWatchdog fails the test instead of hanging `go test` if fn wedges —
// a regression here IS an infinite park.
func withWatchdog(t *testing.T, limit time.Duration, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v — parked send wedged the loop again", name, limit)
	}
}

func parkedConn(t *testing.T) *irclib.Connection {
	t.Helper()
	conn := irclib.IRC("fwmon-test", "fwmon-test")
	if !conn.Connected() {
		t.Fatal("test double invalid: fresh connection no longer reports Connected() — library changed?")
	}
	return conn
}

func TestSendWithTimeout_ParkedSendReturnsError(t *testing.T) {
	shortenSendTimeout(t, 50*time.Millisecond)
	var err error
	withWatchdog(t, 5*time.Second, "sendWithTimeout", func() {
		err = sendWithTimeout("PRIVMSG to #x", func() { select {} })
	})
	if err == nil {
		t.Fatal("parked send returned nil, want timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want timeout error", err)
	}
}

func TestSendWithTimeout_PanicBecomesError(t *testing.T) {
	shortenSendTimeout(t, time.Second)
	var err error
	withWatchdog(t, 5*time.Second, "sendWithTimeout", func() {
		err = sendWithTimeout("PRIVMSG to #x", func() { panic("send on closed channel") })
	})
	if err == nil || !strings.Contains(err.Error(), "torn down mid-send") {
		t.Fatalf("err = %v, want torn-down-mid-send error (old safePrivmsg behavior)", err)
	}
}

func TestSendWithTimeout_FastSendReturnsNil(t *testing.T) {
	shortenSendTimeout(t, time.Second)
	if err := sendWithTimeout("PRIVMSG to #x", func() {}); err != nil {
		t.Fatalf("fast send returned %v, want nil", err)
	}
}

// TestSendAutoStatus_AdvancesPastParkedConn_H5 is the headline regression:
// the prod wedge was sendAutoStatus parking forever on the FIRST dead conn,
// never reaching later targets and never ticking again.
func TestSendAutoStatus_AdvancesPastParkedConn_H5(t *testing.T) {
	shortenSendTimeout(t, 50*time.Millisecond)

	m := NewManager(nil)
	var mu sync.Mutex
	statusCalls := 0
	m.SetStatusProvider(func() (map[string]interface{}, error) {
		mu.Lock()
		statusCalls++
		mu.Unlock()
		// Empty map → "No devices configured" → exactly one send per target.
		return map[string]interface{}{}, nil
	})

	for i := uint(1); i <= 2; i++ {
		b := &Bot{
			ID: i,
			Server: &models.IRCServer{
				Channels: []models.IRCChannel{{
					ID:             i,
					ChannelName:    "#x",
					Enabled:        true,
					SendStatus:     true,
					StatusInterval: 1,
				}},
			},
			manager:  m,
			channels: map[string]bool{"#x": true},
			quit:     make(chan struct{}),
			Conn:     parkedConn(t),
		}
		m.bots[i] = b
	}

	withWatchdog(t, 5*time.Second, "sendAutoStatus", m.sendAutoStatus)

	mu.Lock()
	defer mu.Unlock()
	if statusCalls != 2 {
		t.Fatalf("statusFn called %d times, want 2 — the loop did not advance past the first parked conn", statusCalls)
	}
	if len(m.lastStatus) != 0 {
		t.Fatalf("lastStatus = %v, want empty — a failed send must retry on the next due tick", m.lastStatus)
	}
}

// TestBotStop_QuitOutsideLock: the parked QUIT must not hold b.mu — a held
// lock would stall every callback and admin handler snapshotting b.Conn.
func TestBotStop_QuitOutsideLock(t *testing.T) {
	shortenSendTimeout(t, 200*time.Millisecond)

	b := &Bot{
		Server:   &models.IRCServer{},
		channels: map[string]bool{},
		quit:     make(chan struct{}),
		Conn:     parkedConn(t),
	}

	stopDone := make(chan struct{})
	go func() {
		b.Stop()
		close(stopDone)
	}()

	// While Stop's QUIT is parked (~200ms), the lock must be acquirable and
	// Conn already nil. Poll (Stop's goroutine may not be scheduled yet)
	// instead of assuming a fixed scheduling delay; the watchdog converts a
	// held-forever lock into a failure instead of a hung test.
	withWatchdog(t, time.Second, "lock acquisition while QUIT parked", func() {
		for {
			b.mu.Lock()
			conn := b.Conn
			b.mu.Unlock()
			if conn == nil {
				// Legit fix: we got here ~195ms before Stop returns. In the
				// regression (QUIT under the lock) we could only acquire it
				// after Stop finished — stopDone closes within microseconds
				// of the unlock, so after a short grace it must still be open.
				time.Sleep(10 * time.Millisecond)
				select {
				case <-stopDone:
					t.Error("lock only became free after Stop returned — QUIT was sent under b.mu")
				default:
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
	})

	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return — parked QUIT is unbounded again")
	}
}

// TestHandleCommand_ParkedSendReturns covers the read-loop-stall family:
// RunCallbacks waits unboundedly for callbacks, so a parked command reply
// would freeze the connection's entire event dispatch.
func TestHandleCommand_ParkedSendReturns(t *testing.T) {
	shortenSendTimeout(t, 50*time.Millisecond)

	b := &Bot{
		Server:   &models.IRCServer{},
		manager:  NewManager(nil),
		channels: map[string]bool{},
		quit:     make(chan struct{}),
		Conn:     parkedConn(t),
	}
	cmd := &models.IRCCommand{Command: "!ping", CommandType: "custom", Response: "pong", Enabled: true}

	withWatchdog(t, 5*time.Second, "handleCommand", func() {
		b.handleCommand("#x", cmd, nil)
	})
}
