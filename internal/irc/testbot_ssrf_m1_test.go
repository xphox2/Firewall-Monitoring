package irc

import (
	"strings"
	"testing"
)

// TestTestBot_Connect_RefusesBlockedResolvedIP is the AUDIT M1 regression for
// the IRC test path: go-ircevent re-resolves the host with no dialer hook, so
// TestBot.Connect resolves + validates first and refuses to dial a host that
// resolves only to a blocked/internal address (here "localhost" → loopback),
// closing the DNS-rebinding window.
func TestTestBot_Connect_RefusesBlockedResolvedIP(t *testing.T) {
	bot := NewTestBot("localhost", 6667, "nick", "user", false, "", false, "", "")
	err := bot.Connect()
	if err == nil {
		t.Fatal("expected Connect to refuse a host resolving only to loopback")
	}
	if !strings.Contains(err.Error(), "blocked/internal") {
		t.Fatalf("expected a blocked-address refusal, got: %v", err)
	}

	// AUDIT-325: a Connect that refuses before dialling must not publish the
	// connection. It was never dialled, so its Error channel is nil — and
	// teardownConn on such a conn blocks FOREVER, because Disconnect ends by
	// sending ErrDisconnected on that nil channel while holding the connection
	// lock. Publishing it would arm that hang for any caller that later adds
	// the natural `defer bot.Disconnect()`.
	if bot.conn != nil {
		t.Fatal("a refused Connect published a connection that was never dialled: " +
			"its Error channel is nil, so tearing it down would block forever")
	}
}
