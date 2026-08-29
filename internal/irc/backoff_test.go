package irc

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestReconnectBackoff_Escalation: consecutive failures push nextAttempt out
// with (jittered) exponential delays, capped at reconnectBackoffMax — a dead
// IRC server (expired TLS cert) must settle at a few attempts per hour, never
// the pre-fix hot loop.
func TestReconnectBackoff_Escalation(t *testing.T) {
	b := &Bot{Server: &models.IRCServer{AutoReconnect: true}}

	prevMin := time.Duration(0)
	for i := 1; i <= 8; i++ {
		before := time.Now()
		b.noteConnectFailure()
		got := b.nextAttempt.Sub(before)

		// Expected un-jittered delay: base * 2^(n-1), capped.
		want := reconnectBackoffBase
		for j := 1; j < i && want < reconnectBackoffMax; j++ {
			want *= 2
		}
		if want > reconnectBackoffMax {
			want = reconnectBackoffMax
		}
		// jitter(d) returns [d, 2d): the delay must be >= want and < 2*want
		// (plus a little scheduling slack on the low side).
		if got < want-time.Second || got >= 2*want+time.Second {
			t.Errorf("failure %d: delay = %v, want in [%v, %v)", i, got, want, 2*want)
		}
		if got+time.Second < prevMin {
			t.Errorf("failure %d: delay %v shrank below previous minimum %v", i, got, prevMin)
		}
		prevMin = want
	}
	if b.failCount != 8 {
		t.Errorf("failCount = %d, want 8", b.failCount)
	}
}

// TestReconnectBackoff_ResetOnConnect: a successful registration clears the
// streak so the next unrelated drop retries fast again.
func TestReconnectBackoff_ResetOnConnect(t *testing.T) {
	b := &Bot{Server: &models.IRCServer{Enabled: true, AutoReconnect: true}}
	for i := 0; i < 5; i++ {
		b.noteConnectFailure()
	}
	b.resetBackoff()
	if b.failCount != 0 || !b.nextAttempt.IsZero() {
		t.Fatalf("backoff not reset: failCount=%d nextAttempt=%v", b.failCount, b.nextAttempt)
	}
	if !b.reconnectDue(time.Now()) {
		t.Error("bot with cleared backoff and nil Conn must be due for reconnect")
	}
}

// TestReconnectDue_Gates: the manager sweep must skip bots that are connected,
// have auto-reconnect off, or are still inside their backoff window.
func TestReconnectDue_Gates(t *testing.T) {
	now := time.Now()

	t.Run("auto-reconnect off", func(t *testing.T) {
		b := &Bot{Server: &models.IRCServer{AutoReconnect: false}}
		if b.reconnectDue(now) {
			t.Error("due despite AutoReconnect=false")
		}
	})
	t.Run("inside backoff window", func(t *testing.T) {
		b := &Bot{Server: &models.IRCServer{Enabled: true, AutoReconnect: true}}
		b.nextAttempt = now.Add(time.Minute)
		if b.reconnectDue(now) {
			t.Error("due despite nextAttempt in the future")
		}
		if !b.reconnectDue(now.Add(2 * time.Minute)) {
			t.Error("not due after the backoff window passed")
		}
	})
}

// TestReconnectDue_DisabledServerNeverReconnects_AUDIT205: a disabled server
// must NEVER be auto-reconnected by the manager's 30s sweep, even with
// AutoReconnect=true (the default), a nil Conn, and the backoff window elapsed.
// RestartBot (called on any channel edit) stores a fresh disabled bot into
// m.bots and gates only the immediate Start() on Enabled; without the Enabled
// gate in reconnectDue the sweep would connect a server the operator explicitly
// disabled — silently defeating the disable control.
func TestReconnectDue_DisabledServerNeverReconnects_AUDIT205(t *testing.T) {
	now := time.Now()
	b := &Bot{Server: &models.IRCServer{Enabled: false, AutoReconnect: true}}
	// Conn nil, nextAttempt zero (already past) — the pre-fix reconnectDue
	// returned true here.
	if b.reconnectDue(now) {
		t.Fatal("disabled server reported due for reconnect — the sweep would defeat the disable control")
	}
	// A legitimately enabled server with the same state must still reconnect.
	b.Server.Enabled = true
	if !b.reconnectDue(now) {
		t.Fatal("enabled server with AutoReconnect and nil Conn must still be due for reconnect")
	}
}
