package irc

import (
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// TestStart_EmptyNick_FailsCleanly: go-ircevent's IRC() returns nil (not an
// error) for an empty nick, and Start used to dereference it while holding
// b.mu. launchBot's recover contained the panic, but the mutex stayed locked
// forever, so the next Stop()/RestartBot() on that bot hung the manager — and
// with it API shutdown. Start must now return without panicking, release the
// lock, record the reason on the server row, and schedule backoff like any
// other connect failure.
func TestStart_EmptyNick_FailsCleanly(t *testing.T) {
	db := openIRCTestDB(t)
	srv := models.IRCServer{
		Name:          "no-nick",
		ServerHost:    "localhost",
		ServerPort:    6667,
		Nick:          "",
		Enabled:       true,
		AutoReconnect: true,
	}
	if err := db.Create(&srv).Error; err != nil {
		t.Fatalf("seed server: %v", err)
	}

	m := NewManager(db)
	b := m.createBot(&srv)

	withWatchdog(t, 5*time.Second, "Start with empty nick", b.Start)

	// Stop takes b.mu: if Start had left it locked this would hang.
	withWatchdog(t, 5*time.Second, "Stop after empty-nick Start", b.Stop)

	b.mu.RLock()
	conn, fails := b.Conn, b.failCount
	b.mu.RUnlock()
	if conn != nil {
		t.Fatalf("b.Conn = %v after empty-nick Start, want nil", conn)
	}
	if fails != 1 {
		t.Fatalf("failCount = %d after empty-nick Start, want 1 (treated as a connect failure)", fails)
	}

	var got models.IRCServer
	if err := db.First(&got, srv.ID).Error; err != nil {
		t.Fatalf("reload server: %v", err)
	}
	if got.Status != "error" || got.LastError != "nick is empty" {
		t.Fatalf("server row = status %q / last_error %q, want error / \"nick is empty\"", got.Status, got.LastError)
	}
}
