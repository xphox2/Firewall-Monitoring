package irc

import (
	"bufio"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/glebarez/sqlite"
	irclib "github.com/thoj/go-ircevent"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testIRCServer is a minimal loopback TCP server standing in for an ircd: it
// accepts client connections, records every line the client sends, and tracks
// how many client sockets are currently open (so a test can assert a raced
// connection was actually torn down). It never sends anything unless a test
// asks it to. No real IRC protocol — just enough for go-ircevent's Connect to
// succeed and for the client's writes to be observed.
type testIRCServer struct {
	ln       net.Listener
	mu       sync.Mutex
	lines    []string
	accepted int
	closed   int
}

func startTestIRCServer(t *testing.T) *testIRCServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testIRCServer{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.accepted++
			s.mu.Unlock()
			go func(c net.Conn) {
				// Keepalive writer: go-ircevent's readLoop only re-checks its
				// `end` channel between blocking reads, so a client Disconnect()
				// stalls in Wait() until the peer sends something or the read
				// deadline (~16min) fires. A benign numeric every 25ms lets a
				// client tear down promptly. Stops when the reader goroutine
				// closes the conn.
				done := make(chan struct{})
				go func() {
					tk := time.NewTicker(25 * time.Millisecond)
					defer tk.Stop()
					for {
						select {
						case <-done:
							return
						case <-tk.C:
							if _, err := c.Write([]byte(":ka.srv 999 * :ka\r\n")); err != nil {
								return
							}
						}
					}
				}()
				defer func() {
					close(done)
					c.Close()
					s.mu.Lock()
					s.closed++
					s.mu.Unlock()
				}()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if line != "" {
						s.mu.Lock()
						s.lines = append(s.lines, strings.TrimRight(line, "\r\n"))
						s.mu.Unlock()
					}
					if err != nil {
						return
					}
					// A real ircd drops the session on QUIT; so does this one,
					// which is what lets a client teardown's read loop return
					// instead of waiting out teardownConn's drain bound.
					if strings.HasPrefix(line, "QUIT") {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *testIRCServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}
	return host, port
}

func (s *testIRCServer) openConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted - s.closed
}

// waitForLinePrefix polls the recorded client lines for the first one starting
// with prefix, returning it (or "" on timeout).
func (s *testIRCServer) waitForLinePrefix(prefix string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, l := range s.lines {
			if strings.HasPrefix(l, prefix) {
				s.mu.Unlock()
				return l
			}
		}
		s.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return ""
}

// TestStart_StopRace_TearsDownConn_AUDIT206: Start releases b.mu before dialing,
// so a Stop() can race the unlocked Connect. When it does, the fix has Start —
// the creator of the connection — tear down the exact conn it registered
// instead of leaking a live, unowned session. The startConnectHook seam
// deterministically injects that race in the same window a real Stop would hit.
func TestStart_StopRace_TearsDownConn_AUDIT206(t *testing.T) {
	srv := startTestIRCServer(t)
	host, port := srv.hostPort(t)

	b := &Bot{
		Server: &models.IRCServer{
			Nick:          "fwmon206",
			Username:      "fwmon206",
			ServerHost:    host,
			ServerPort:    port,
			AutoReconnect: false,
		},
		channels: map[string]bool{},
		quit:     make(chan struct{}),
	}

	old := startConnectHook
	startConnectHook = func(bb *Bot) {
		// Mimic Stop() winning the race: close quit and drop the owner ref while
		// Start is between its unlock and the post-Connect re-check.
		bb.mu.Lock()
		select {
		case <-bb.quit:
		default:
			close(bb.quit)
		}
		bb.Conn = nil
		bb.mu.Unlock()
	}
	t.Cleanup(func() { startConnectHook = old })

	// Must not hang (a live watcher blocked on ErrorChan would never return).
	withWatchdog(t, 5*time.Second, "Start under stop-race", b.Start)

	// The registered connection must be closed, not left squatting the nick.
	deadline := time.Now().Add(3 * time.Second)
	for srv.openConns() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := srv.openConns(); got != 0 {
		t.Fatalf("raced connection left live/unowned: %d open server-side conns (want 0)", got)
	}

	b.mu.RLock()
	c := b.Conn
	b.mu.RUnlock()
	if c != nil {
		t.Fatalf("b.Conn = %v after stop-race teardown, want nil", c)
	}
}

// TestOnPrivmsg_PMReplyGoesToSender_AUDIT278: a command PM'd to the bot must be
// answered to the sender, not to the bot's own nick (IRC sets Arguments[0] to
// the bot's nick for a PM). A channel command is still answered to the channel.
func TestOnPrivmsg_PMReplyGoesToSender_AUDIT278(t *testing.T) {
	srv := startTestIRCServer(t)
	addr := srv.ln.Addr().String()

	newBot := func(t *testing.T) (*Bot, *irclib.Connection) {
		conn := irclib.IRC("botnick", "botnick")
		if conn == nil {
			t.Fatal("irc.IRC returned nil")
		}
		if err := conn.Connect(addr); err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { forgetConn(conn); conn.Disconnect() })
		return &Bot{
			Server:   &models.IRCServer{},
			manager:  NewManager(nil), // lookupCommand needs no DB; "!help" is unknown here
			channels: map[string]bool{},
			quit:     make(chan struct{}),
			Conn:     conn,
		}, conn
	}

	t.Run("PM replies to sender", func(t *testing.T) {
		b, _ := newBot(t)
		// PRIVMSG target is the bot's own nick → PM.
		b.onPrivmsg(&irclib.Event{Nick: "alice", Arguments: []string{"botnick", "!help"}})
		line := srv.waitForLinePrefix("NOTICE ", 3*time.Second)
		if line == "" {
			t.Fatal("no NOTICE sent for PM'd command")
		}
		if !strings.HasPrefix(line, "NOTICE alice ") {
			t.Fatalf("PM reply target wrong: %q, want a NOTICE to alice (the sender), not to the bot", line)
		}
	})

	t.Run("channel replies to channel", func(t *testing.T) {
		b, _ := newBot(t)
		b.onPrivmsg(&irclib.Event{Nick: "alice", Arguments: []string{"#ops", "!help"}})
		line := srv.waitForLinePrefix("NOTICE #ops ", 3*time.Second)
		if line == "" {
			t.Fatal("channel command reply did not go to the channel")
		}
	})
}

// TestSendVia_WedgedConnLatched_AUDIT314: repeated sends to a wedged connection
// (nil/full pwrite — a send parks forever and can never be reclaimed with this
// library) must not spawn a fresh doomed goroutine each time. The first send
// times out and latches the conn write-dead; every later send short-circuits.
// The leak is bounded to ONE parked sender per wedged conn, not one per call.
func TestSendVia_WedgedConnLatched_AUDIT314(t *testing.T) {
	shortenSendTimeout(t, 80*time.Millisecond)
	conn := parkedConn(t) // nil pwrite: every real send parks forever
	t.Cleanup(func() { forgetConn(conn) })

	before := runtime.NumGoroutine()

	const n = 12
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := safePrivmsg(conn, "#x", "hello"); err == nil {
			t.Fatalf("send %d to wedged conn returned nil, want an error", i)
		}
	}
	elapsed := time.Since(start)

	if !connWriteDead(conn) {
		t.Fatal("conn was not latched write-dead after the first timeout")
	}

	// With the latch: ~1 timeout total (first send) then instant short-circuits.
	// Without it (reverted): n timeouts ≈ n*80ms. Give generous slack.
	if elapsed > 4*ircSendTimeout {
		t.Fatalf("%d sends took %v — the latch is not short-circuiting (each send is timing out)", n, elapsed)
	}

	// Let any spawned senders settle, then confirm only a bounded number parked.
	time.Sleep(50 * time.Millisecond)
	if grew := runtime.NumGoroutine() - before; grew > n/2 {
		t.Fatalf("goroutine count grew by %d over %d sends — parked senders are accumulating unbounded", grew, n)
	}
}

func openIRCTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.IRCServer{}, &models.IRCChannel{}, &models.IRCCommand{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// TestRestartBot_PanicInStartRecovered_AUDIT315: RestartBot must launch Bot.Start
// through the same panic-recovered path as its two siblings, so a panic in
// Start is contained instead of crashing the whole fwmon-api process — the
// exact class REL-01 guards. The panic is injected through the startConnectHook
// seam right after the dial (an empty Nick used to be the trigger, until Start
// learned to refuse it cleanly — see TestStart_EmptyNick_FailsCleanly). If the
// recover is missing (reverted), the panic escapes the goroutine and crashes
// the test binary; with it, the goroutine unwinds cleanly and wg drains.
func TestRestartBot_PanicInStartRecovered_AUDIT315(t *testing.T) {
	fake := startTestIRCServer(t)
	host, port := fake.hostPort(t)

	db := openIRCTestDB(t)
	srv := models.IRCServer{
		Name:          "boom",
		ServerHost:    host,
		ServerPort:    port,
		Nick:          "fwmon315",
		Enabled:       true,
		AutoReconnect: false,
	}
	if err := db.Create(&srv).Error; err != nil {
		t.Fatalf("seed server: %v", err)
	}

	old := startConnectHook
	startConnectHook = func(*Bot) { panic("AUDIT-315: injected panic inside Bot.Start") }
	t.Cleanup(func() { startConnectHook = old })

	m := NewManager(db) // NewManager starts no goroutines; only RestartBot's launch touches wg
	if err := m.RestartBot(srv.ID); err != nil {
		t.Fatalf("RestartBot returned error: %v", err)
	}

	// Reaching here at all proves the panic did not crash the process; wg
	// draining proves the recovered goroutine ran its deferred wg.Done.
	withWatchdog(t, 5*time.Second, "wg drain after recovered Start panic", func() { m.wg.Wait() })
}
