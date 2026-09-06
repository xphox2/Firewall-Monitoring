package irc

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/logging"
	"firewall-mon/internal/models"

	"github.com/thoj/go-ircevent"
	"gorm.io/gorm"
)

// jitter returns d plus a uniformly random extra delay in [0, d). The bot
// restart/reconnect path uses it so that a server-wide event that restarts
// many bots at once doesn't reconnect them in lock-step (AUDIT-088 —
// thundering herd). Falls back to d on the practically-impossible
// crypto/rand failure.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(d)))
	if err != nil {
		return d
	}
	return d + time.Duration(n.Int64())
}

type Bot struct {
	ID       uint
	Server   *models.IRCServer
	Conn     *irc.Connection
	db       *gorm.DB
	manager  *Manager
	channels map[string]bool
	mu       sync.RWMutex
	quit     chan struct{}
	// Exponential reconnect backoff (mu-guarded). failCount counts consecutive
	// failed connections since the last successful registration (001);
	// nextAttempt is the earliest time reconnectLoop may try again. Without
	// this, a persistently failing server (expired TLS cert, dead host) was
	// re-dialed in a tight loop — go-ircevent's Loop() reconnects with ZERO
	// delay when the TCP dial succeeds but the connection dies right after
	// (this version wraps tls.Client lazily, so an expired cert fails in the
	// READ loop, not the dial), which produced ~3,500 log lines/min in prod.
	failCount   int
	nextAttempt time.Time
}

// Reconnect backoff bounds: first retry after ~30-60s (jittered), doubling to
// a 15-minute ceiling. A healthy netsplit reconnect stays fast; a dead server
// settles at 4 attempts/hour instead of a hot loop.
const (
	reconnectBackoffBase = 30 * time.Second
	reconnectBackoffMax  = 15 * time.Minute
)

// noteConnectFailure records a failed connection attempt and schedules the
// next one with jittered exponential backoff.
func (b *Bot) noteConnectFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failCount++
	delay := reconnectBackoffBase
	for i := 1; i < b.failCount && delay < reconnectBackoffMax; i++ {
		delay *= 2
	}
	if delay > reconnectBackoffMax {
		delay = reconnectBackoffMax
	}
	b.nextAttempt = time.Now().Add(jitter(delay))
}

// resetBackoff clears the failure streak after a successful registration.
func (b *Bot) resetBackoff() {
	b.mu.Lock()
	b.failCount = 0
	b.nextAttempt = time.Time{}
	b.mu.Unlock()
}

// reconnectDue reports whether the manager's reconnect sweep should attempt
// this bot now: the server is enabled, auto-reconnect is enabled, it is not
// connected, and it is past the backoff.
//
// AUDIT-205: the Enabled gate is load-bearing. RestartBot (called
// unconditionally by CreateIRCChannel/UpdateIRCChannel/DeleteIRCChannel on any
// channel edit) stores a fresh bot into m.bots even for a DISABLED server,
// gating only the immediate Start() on Enabled. AutoReconnect defaults true, so
// without this check the 30s reconnect sweep would later connect a server the
// operator explicitly disabled — silently defeating the disable control.
func (b *Bot) reconnectDue(now time.Time) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Server.Enabled && b.Server.AutoReconnect && b.Conn == nil && now.After(b.nextAttempt)
}

type Manager struct {
	db         *gorm.DB
	bots       map[uint]*Bot
	mu         sync.RWMutex
	commands   map[string]*models.IRCCommand
	wg         sync.WaitGroup
	quit       chan struct{}
	statusFn   func() (map[string]interface{}, error)
	statsFn    func() (map[string]interface{}, error)
	lastStatus map[uint]time.Time
	decryptFn  func(string) string
}

func NewManager(db *gorm.DB) *Manager {
	return &Manager{
		db:         db,
		bots:       make(map[uint]*Bot),
		commands:   make(map[string]*models.IRCCommand),
		quit:       make(chan struct{}),
		lastStatus: make(map[uint]time.Time),
	}
}

func (m *Manager) SetStatusProvider(fn func() (map[string]interface{}, error)) {
	m.statusFn = fn
}

func (m *Manager) SetStatsProvider(fn func() (map[string]interface{}, error)) {
	m.statsFn = fn
}

func (m *Manager) SetDecryptFunc(fn func(string) string) {
	m.decryptFn = fn
}

// decryptServerSecrets decrypts IRC server and channel credentials in-place.
func (m *Manager) decryptServerSecrets(s *models.IRCServer) {
	if m.decryptFn == nil {
		return
	}
	s.ServerPassword = m.decryptFn(s.ServerPassword)
	s.NickServPassword = m.decryptFn(s.NickServPassword)
	s.SASLPassword = m.decryptFn(s.SASLPassword)
	for i := range s.Channels {
		s.Channels[i].ChanServPass = m.decryptFn(s.Channels[i].ChanServPass)
		s.Channels[i].ChanOperPass = m.decryptFn(s.Channels[i].ChanOperPass)
		s.Channels[i].ChannelKey = m.decryptFn(s.Channels[i].ChannelKey)
	}
}

func (m *Manager) Start() {
	// REL-01: a panic in any manager loop must stay contained — it would
	// otherwise crash the whole cmd/api process.
	logging.SafeGo("irc-load-bots", m.loadAndStartBots)
	logging.SafeGo("irc-reconnect", m.reconnectLoop)
	logging.SafeGo("irc-status", m.statusLoop)
}

func (m *Manager) Stop() {
	close(m.quit)
	// H5 invariant: never send while holding m.mu. Each bot.Stop() sends a
	// QUIT that can block up to ircSendTimeout on a dead conn — done under
	// the read lock, N dead bots would queue every m.mu writer (and then all
	// readers) for N × ircSendTimeout during shutdown.
	m.mu.RLock()
	bots := make([]*Bot, 0, len(m.bots))
	for _, bot := range m.bots {
		bots = append(bots, bot)
	}
	m.mu.RUnlock()
	for _, bot := range bots {
		bot.Stop()
	}
	m.wg.Wait()
}

// launchBot starts b.Start() on a tracked, panic-recovered goroutine. Every
// start site (initial load, reconnect sweep, RestartBot) goes through here so
// the REL-01 recover can never be forgotten: go-ircevent's own callbacks aside,
// an un-recovered panic in Bot.Start crashes the whole fwmon-api process
// (AUDIT-315 — RestartBot's launch used to lack the recover its two siblings
// had). The defer order matches the siblings: Recover is deferred first so it
// runs last and still catches a panic after wg.Done has decremented.
func (m *Manager) launchBot(b *Bot) {
	m.wg.Add(1)
	go func() {
		defer logging.Recover("irc-bot") // REL-01
		defer m.wg.Done()
		b.Start()
	}()
}

func (m *Manager) loadAndStartBots() {
	var servers []models.IRCServer
	if err := m.db.Preload("Channels").Find(&servers).Error; err != nil {
		log.Printf("IRC: Failed to load servers: %v", err)
		return
	}

	m.mu.Lock()
	for _, server := range servers {
		if server.Enabled {
			m.decryptServerSecrets(&server)
			bot := m.createBot(&server)
			m.bots[server.ID] = bot
			m.launchBot(bot)
		}
	}
	m.mu.Unlock()

	m.seedDefaultCommands()
	m.loadCommands()
}

func (m *Manager) seedDefaultCommands() {
	defaults := []models.IRCCommand{
		{Command: "!status", Description: "Show system health dashboard", CommandType: "status", Enabled: true},
		{Command: "!stats", Description: "Show CPU/memory averages", CommandType: "stats", Enabled: true},
		{Command: "!help", Description: "List available commands", CommandType: "help", Enabled: true},
	}
	for _, def := range defaults {
		var count int64
		m.db.Model(&models.IRCCommand{}).Where("command = ?", def.Command).Count(&count)
		if count == 0 {
			if err := m.db.Create(&def).Error; err != nil {
				log.Printf("IRC: Failed to seed command %s: %v", def.Command, err)
			}
		}
	}
}

func (m *Manager) loadCommands() {
	var commands []models.IRCCommand
	if err := m.db.Find(&commands).Error; err != nil {
		log.Printf("IRC: Failed to load commands: %v", err)
		return
	}

	m.mu.Lock()
	m.commands = make(map[string]*models.IRCCommand)
	for i := range commands {
		cmd := &commands[i]
		if cmd.Enabled {
			m.commands[strings.ToLower(cmd.Command)] = cmd
		}
	}
	m.mu.Unlock()
}

// lookupCommand returns the enabled command registered under name (already
// lowercased), read under the Manager's own mutex. onPrivmsg runs on the IRC
// read-loop goroutine while loadCommands replaces m.commands under m.mu from
// API handlers (ReloadCommands). Reading the map under any other lock — as the
// old b.mu.RLock did — provides no mutual exclusion against that writer and
// triggers Go's unrecoverable "concurrent map read and map write".
func (m *Manager) lookupCommand(name string) (*models.IRCCommand, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cmd, ok := m.commands[name]
	return cmd, ok
}

func (m *Manager) reconnectLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.quit:
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.RLock()
			for _, bot := range m.bots {
				if bot.reconnectDue(now) {
					m.launchBot(bot)
				}
			}
			m.mu.RUnlock()
		}
	}
}

func (m *Manager) statusLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.quit:
			return
		case <-ticker.C:
			// Per-tick containment: statusLoop runs under SafeGo, which does
			// NOT restart a panicked goroutine — one tick's panic must not
			// kill auto-status for the process lifetime.
			func() {
				defer logging.Recover("irc-status-tick")
				start := time.Now()
				m.sendAutoStatus()
				if d := time.Since(start); d > 2*time.Minute {
					log.Printf("IRC: status tick took %v — sends timing out against dead connections?", d)
				}
			}()
		}
	}
}

// sendAutoStatus pushes the periodic status box into every due channel.
//
// H5 of the 2026-07-01 audit: this must NEVER send to IRC (or run the N+1-query
// statusFn) while holding m.mu. In the pinned go-ircevent version, Privmsg
// sends into a buffered channel whose consumer dies during an outage and is
// REPLACED on reconnect — a sender parked on the old channel blocks forever.
// The pre-fix code held m.mu.RLock across those sends, so one wedged send
// blocked every m.mu.Lock caller (ReloadCommands/RestartBot from admin HTTP
// handlers), and RWMutex writer-queueing then hung every subsequent RLock
// (alert delivery via SendToChannel, Manager.Stop, graceful shutdown) until
// SIGKILL. Now the due (conn, channel) pairs are snapshotted under the lock,
// the lock is released, and sends happen lock-free. Sends are also
// timeout-bounded (sendWithTimeout): a dead conn costs at most one
// ircSendTimeout per tick, then the parked sender is abandoned — the 2026-08
// prod wedge proved reconnect churn can NEVER free a parked send, because
// Disconnect's irc.Wait() deadlocks on the library's own pingLoop parked on
// the same full pwrite buffer, so close(pwrite) is never reached.
//
// m.lastStatus is intentionally lock-free: statusLoop is its only reader and
// writer (single goroutine).
func (m *Manager) sendAutoStatus() {
	if m.statusFn == nil {
		return
	}

	type statusTarget struct {
		conn    *irc.Connection
		channel string
		chID    uint
	}
	var targets []statusTarget

	m.mu.RLock()
	for _, bot := range m.bots {
		bot.mu.RLock()
		conn := bot.Conn
		bot.mu.RUnlock()
		if conn == nil {
			continue
		}

		for i := range bot.Server.Channels {
			ch := &bot.Server.Channels[i]
			if !ch.Enabled || !ch.SendStatus {
				continue
			}

			interval := time.Duration(ch.StatusInterval) * time.Second
			if interval <= 0 {
				interval = 300 * time.Second
			}

			bot.mu.RLock()
			joined := bot.channels[ch.ChannelName]
			bot.mu.RUnlock()
			if !joined {
				continue
			}

			if time.Since(m.lastStatus[ch.ID]) < interval {
				continue
			}

			targets = append(targets, statusTarget{conn: conn, channel: ch.ChannelName, chID: ch.ID})
		}
	}
	m.mu.RUnlock()

	for _, t := range targets {
		// The DISCONNECTED callback never fires in this go-ircevent version,
		// so poll the connection's own liveness instead of trusting b.Conn:
		// skipping a dead conn avoids parking on its orphaned write channel.
		if !t.conn.Connected() {
			continue
		}

		status, err := m.statusFn()
		if err != nil {
			log.Printf("IRC: Auto-status error for %s: %v", t.channel, err)
			continue
		}

		response := formatStatusResponse(status)
		sendFailed := false
		for _, line := range strings.Split(response, "\n") {
			if line != "" {
				// safePrivmsg: the error watcher can Disconnect (closing the
				// library's write channel) between the Connected() poll above
				// and this send — that must skip the target, not panic.
				if err := safePrivmsg(t.conn, t.channel, line); err != nil {
					log.Printf("IRC: Auto-status send to %s failed: %v", t.channel, err)
					sendFailed = true
					break
				}
			}
		}
		if sendFailed {
			continue // retry this channel on the next due tick
		}

		m.lastStatus[t.chID] = time.Now()
	}
}

func (m *Manager) createBot(server *models.IRCServer) *Bot {
	return &Bot{
		ID:       server.ID,
		Server:   server,
		manager:  m,
		channels: make(map[string]bool),
		quit:     make(chan struct{}),
		db:       m.db,
	}
}

// startConnectHook, when non-nil, runs inside Start immediately after a
// successful Connect and before the AUDIT-206 stop-race re-check. Tests use it
// to deterministically inject a Stop() that raced the unlocked dial. Production
// leaves it nil.
var startConnectHook func(*Bot)

func (b *Bot) Start() {
	b.mu.Lock()
	if b.Conn != nil {
		b.mu.Unlock()
		return
	}

	// Check if bot was stopped — don't reconnect a stopped bot
	select {
	case <-b.quit:
		b.mu.Unlock()
		return
	default:
	}

	server := b.Server
	user := server.Username
	if user == "" {
		user = server.Nick
	}
	conn := irc.IRC(server.Nick, user)
	if conn == nil {
		// go-ircevent returns nil, not an error, for an empty nick or user. The
		// API rejects an empty nick, but a row can still arrive without one
		// (legacy data, a direct DB edit). Dereferencing the nil here used to
		// panic UNDER b.mu: launchBot's recover contained the panic, but the
		// mutex stayed locked forever, so the next Stop()/RestartBot() on this
		// bot hung the manager — and with it API shutdown. Treat it as a
		// connect failure instead: release the lock, record the reason where
		// the operator sees it, and let the sweep back off as it would for an
		// unreachable server.
		b.mu.Unlock()
		log.Printf("IRC: server %q (id %d) has no nick; not connecting", server.Name, server.ID)
		b.updateStatus("error", "nick is empty")
		b.noteConnectFailure()
		return
	}
	conn.RealName = server.RealName
	if server.RealName == "" {
		conn.RealName = server.Nick
	}
	conn.UseTLS = server.UseTLS
	if server.UseTLS && server.ServerHost != "" {
		conn.TLSConfig = &tls.Config{
			ServerName: server.ServerHost,
		}
	}
	conn.Password = server.ServerPassword

	if server.SASLEnabled {
		conn.UseSASL = true
		conn.SASLLogin = server.SASLUsername
		conn.SASLPassword = server.SASLPassword
	}

	b.Conn = conn

	// M8 of the 2026-07-01 audit: go-ircevent runs every callback in a bare
	// `go func` with NO recover, so a panic in any of these closures bypasses
	// the REL-01 SafeGo containment and crashes the whole fwmon-api process.
	// Every closure recovers first; the handlers additionally snapshot b.Conn
	// under b.mu (Stop/RestartBot/onQuit nil it concurrently).
	conn.AddCallback("001", func(e *irc.Event) {
		defer logging.Recover("irc-callback-001")
		b.onConnected()
	})

	conn.AddCallback("PRIVMSG", func(e *irc.Event) {
		defer logging.Recover("irc-callback-privmsg")
		b.onPrivmsg(e)
	})

	conn.AddCallback("JOIN", func(e *irc.Event) {
		defer logging.Recover("irc-callback-join")
		b.onJoin(e)
	})

	conn.AddCallback("PART", func(e *irc.Event) {
		defer logging.Recover("irc-callback-part")
		b.onPart(e)
	})

	conn.AddCallback("QUIT", func(e *irc.Event) {
		defer logging.Recover("irc-callback-quit")
		b.onQuit(e)
	})

	conn.AddCallback("DISCONNECTED", func(e *irc.Event) {
		defer logging.Recover("irc-callback-disconnected")
		log.Printf("IRC: Connection lost to %s", b.Server.ServerHost)
		b.mu.Lock()
		b.Conn = nil
		b.mu.Unlock()
		forgetConn(conn) // AUDIT-314
		b.updateStatus("disconnected", "connection lost")
	})

	conn.AddCallback("NOTICE", func(e *irc.Event) {
		defer logging.Recover("irc-callback-notice")
		b.onNotice(e)
	})

	conn.AddCallback("433", func(e *irc.Event) {
		defer logging.Recover("irc-callback-433")
		// Nick in use — append underscore to the CURRENT nick, not the original
		currentNick := conn.GetNick()
		newNick := currentNick + "_"
		// Safety limit: don't let nicks grow unbounded
		if len(newNick) > 30 {
			newNick = server.Nick + fmt.Sprintf("_%d", time.Now().Unix()%10000)
		}
		log.Printf("IRC: Nick %q in use, trying %q", currentNick, newNick)
		if err := safeNick(conn, newNick); err != nil {
			log.Printf("IRC: nick change failed: %v", err)
		}
	})

	// Server rejections are numerics, and the library swallows every numeric
	// without a registered callback — a send the ircd refuses (spam filter,
	// +m without voice, flood limits) otherwise vanishes with the bot
	// believing it succeeded. Proven in prod 2026-08-24: an InspIRCd
	// repeat-character filter 404'd every auto-status box line for weeks
	// with zero log evidence. 433 stays with its own handler above.
	for _, numeric := range []string{"401", "404", "412", "417", "421", "437", "471", "473", "474", "475", "477", "482", "489", "494"} {
		num := numeric
		conn.AddCallback(num, func(e *irc.Event) {
			defer logging.Recover("irc-callback-errnumeric")
			log.Printf("IRC: server rejected command (%s): %s", num, strings.Join(e.Arguments, " "))
		})
	}

	b.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", server.ServerHost, server.ServerPort)
	if err := conn.Connect(addr); err != nil {
		log.Printf("IRC: Failed to connect to %s: %v", addr, err)
		b.updateStatus("error", err.Error())
		b.mu.Lock()
		b.Conn = nil
		b.mu.Unlock()
		b.noteConnectFailure()
		// AUDIT-319: go-ircevent allocates the socket and spawns its three
		// loops BEFORE it negotiates capabilities, then returns the
		// negotiateCaps error without unwinding any of it. A SASL server that
		// rejects our credentials therefore strands writeLoop, pingLoop and
		// the socket for the process lifetime, and the manager's 30s
		// reconnect sweep strands another set on every retry. (readLoop does
		// eventually exit on its own read deadline; the other two never see
		// `end` close, and pingLoop keeps writing to the live socket.)
		//
		// Only post-spawn failures have anything to unwind, and ErrorChan is
		// the exact discriminator: Connect allocates irc.Error immediately
		// before irc.Add(3), so a nil channel means it bailed during argument
		// validation or the dial, with no goroutine, socket or channel ever
		// created. Tearing down THERE would be far worse than the leak —
		// Disconnect ends by sending on that nil Error channel while holding
		// the connection lock, which blocks forever.
		if conn.ErrorChan() != nil {
			logging.SafeGo("irc-failed-connect-teardown", func() { // REL-01
				teardownConn(conn)
			})
		}
		return
	}

	// Test seam only (nil in production): deterministically simulate a Stop()
	// that won the race against the unlocked dial.
	if startConnectHook != nil {
		startConnectHook(b)
	}

	// AUDIT-206: Start released b.mu (above) before dialing, so a Stop() /
	// RestartBot() (or the reconnect sweep tearing this bot down) can have raced
	// the unlocked Connect. If it did, b.quit is now closed — and Stop's QUIT
	// parked on the pre-Connect nil pwrite and was discarded when Connect
	// allocated the real one, leaving a REGISTERED session that no owner would
	// ever tear down: onConnected sees b.Conn==nil and bails without joining,
	// and the error-watcher below would block on ErrorChan forever. Start
	// created this conn, so Start tears it down here — and does so BEFORE
	// starting the error-watcher, so this Disconnect stays the SOLE Disconnect
	// caller for the conn (a second call panics on the already-closed pwrite).
	// Connect has allocated a live pwrite/Error/socket, so Disconnect on this
	// freshly-registered conn completes cleanly (its loops honor end); the
	// deadlock hazard only exists on a wedged conn with a full pwrite.
	b.mu.Lock()
	stopped := false
	select {
	case <-b.quit:
		stopped = true
	default:
	}
	if stopped {
		if b.Conn == conn {
			b.Conn = nil
		}
		b.mu.Unlock()
		// Re-deliver the QUIT Stop lost into the pre-Connect nil pwrite: pwrite
		// is live now, so this reaches the server, which drops us gracefully
		// (readLoop then unblocks, so the Disconnect completes promptly instead
		// of stalling on the read deadline). That QUIT-then-Disconnect sequence
		// is exactly teardownConn, so this path uses it rather than repeating
		// the three steps and risking drift. Synchronous here: this conn IS
		// registered, so the server answers the QUIT promptly.
		teardownConn(conn) // sole Disconnect caller for this conn (no watcher started)
		return
	}
	b.mu.Unlock()

	// Deliberately NOT conn.Loop(): the library's loop reconnects internally
	// with ZERO delay whenever the TCP dial succeeds but the connection dies
	// right after — this go-ircevent version defers the TLS handshake to the
	// read loop (tls.Client, no explicit Handshake), so an expired/bad server
	// cert becomes an infinite dial→fail hot loop (~3,500 log lines/min in
	// prod). Instead: consume the FIRST error, tear the connection down, and
	// hand reconnection to the manager's 30s sweep, which honors AutoReconnect
	// and this bot's exponential backoff. conn.Quit() is not sent here at all
	// — where Quit IS wanted (Bot.Stop, TestBot.Disconnect) it goes through
	// safeQuit, whose timeout bounds the park-forever H5 hazard.
	logging.SafeGo("irc-conn-loop", func() { // REL-01
		err := <-conn.ErrorChan()
		log.Printf("IRC: Connection to %s lost: %v", addr, err)
		b.mu.Lock()
		b.Conn = nil
		b.mu.Unlock()
		// AUDIT-314: drop any write-dead latch for this conn — it is being
		// abandoned, and no further sends will target it once b.Conn is nil.
		forgetConn(conn)
		// Bookkeeping BEFORE Disconnect: on a half-open socket (writes fail,
		// reads hang) Disconnect's Wait() can stall until the read deadline
		// (Timeout+PingFreq ≈ 16 min) — the backoff bump and status write must
		// not lag behind it, or a late "disconnected" would overwrite a status
		// the sweep's successful reconnect wrote in the meantime.
		// A bot being STOPPED (admin action / shutdown) also surfaces here as
		// a read error after the QUIT — that's a teardown, not a failure.
		select {
		case <-b.quit:
		default:
			b.noteConnectFailure()
			b.updateStatus("disconnected", err.Error())
		}
		// Disconnect stops the library's internal goroutines (close(end) +
		// Wait) and closes the socket; its trailing ErrDisconnected push lands
		// in the buffered (10) error channel of a conn nothing references.
		// This watcher must remain the ONLY Disconnect caller for a conn — a
		// second call would panic on the already-closed pwrite channel.
		conn.Disconnect()
	})
}

func (b *Bot) Stop() {
	// b.quit closes BEFORE the QUIT send, so the error watcher observes the
	// teardown as a stop (no spurious backoff/status write). The QUIT itself
	// happens OUTSIDE b.mu: on a dead conn it can park until ircSendTimeout,
	// and holding the lock that long would stall every callback and admin
	// handler that snapshots b.Conn. The watcher remains the only Disconnect
	// caller.
	b.mu.Lock()
	select {
	case <-b.quit:
		// already closed
	default:
		close(b.quit)
	}
	conn := b.Conn
	b.Conn = nil
	b.mu.Unlock()
	if conn != nil {
		if err := safeQuit(conn); err != nil {
			log.Printf("IRC: QUIT on stop failed: %v", err)
		}
		forgetConn(conn) // AUDIT-314: this conn is abandoned
	}
}

func (b *Bot) onConnected() {
	// Successful registration ends the failure streak — the next drop retries
	// fast again instead of inheriting a stale 15-minute backoff.
	b.resetBackoff()
	// M8: snapshot b.Conn under the lock — Stop/RestartBot nil it from admin
	// handlers while this callback runs on a library goroutine.
	b.mu.RLock()
	conn := b.Conn
	b.mu.RUnlock()
	if conn == nil {
		return
	}
	log.Printf("IRC: Connected to %s as %s", b.Server.ServerHost, conn.GetNick())

	if b.Server.NickServIdentify && b.Server.NickServPassword != "" {
		// Identify failure must not block the joins below.
		if err := safePrivmsg(conn, "NickServ", "IDENTIFY "+b.Server.NickServPassword); err != nil {
			log.Printf("IRC: NickServ identify send failed: %v", err)
		}
	}

	for _, ch := range b.Server.Channels {
		if ch.Enabled && ch.AutoJoin {
			chanName := ch.ChannelName
			if ch.ChannelKey != "" {
				chanName += " " + ch.ChannelKey
			}
			if err := safeJoin(conn, chanName, ch.ChannelName); err != nil {
				// Remaining joins would hit the same dead conn.
				log.Printf("IRC: join %s failed: %v", ch.ChannelName, err)
				break
			}
		}
	}

	now := time.Now()
	b.Server.LastConnected = &now
	b.db.Model(b.Server).Updates(map[string]interface{}{
		"status":         "connected",
		"last_connected": now,
		"last_error":     "",
	})
}

func (b *Bot) onPrivmsg(e *irc.Event) {
	target := e.Arguments[0]
	nick := e.Nick
	message := e.Message()

	if !strings.HasPrefix(message, "!") {
		return
	}

	parts := strings.Fields(message)
	if len(parts) == 0 {
		return
	}

	// M8: snapshot b.Conn under the lock before any dereference — a
	// Stop/RestartBot racing an in-flight PRIVMSG previously nil-deref'd on
	// an unrecovered library goroutine and crashed the whole process.
	b.mu.RLock()
	conn := b.Conn
	b.mu.RUnlock()
	if conn == nil {
		return
	}

	cmdStr := strings.ToLower(parts[0])
	cmd, exists := b.manager.lookupCommand(cmdStr)

	// AUDIT-278: for a private message IRC sets Arguments[0] (target) to the
	// bot's OWN nick, so replying to target would PRIVMSG the bot itself and the
	// sender would see nothing. Reply to the channel for a channel message, and
	// to the sender for a PM. isAdmin still receives the raw target — its own
	// target==ownNick check deliberately denies PM admin.
	replyTo := target
	if strings.EqualFold(target, conn.GetNick()) {
		replyTo = nick
	}

	if !exists {
		if err := safeNotice(conn, replyTo, fmt.Sprintf("Unknown command: %s", parts[0])); err != nil {
			log.Printf("IRC: unknown-command notice to %s failed: %v", replyTo, err)
		}
		return
	}

	if cmd.AdminOnly && !b.isAdmin(target, nick) {
		if err := safeNotice(conn, replyTo, "This command is admin only"); err != nil {
			log.Printf("IRC: admin-only notice to %s failed: %v", replyTo, err)
		}
		return
	}

	b.handleCommand(replyTo, cmd, parts[1:])
}

func (b *Bot) handleCommand(target string, cmd *models.IRCCommand, args []string) {
	var response string

	switch cmd.CommandType {
	case "status":
		if b.manager.statusFn != nil {
			status, err := b.manager.statusFn()
			if err != nil {
				response = fmt.Sprintf("Error getting status: %v", err)
			} else {
				response = formatStatusResponse(status)
			}
		} else {
			response = "Status provider not configured"
		}
	case "stats":
		if b.manager.statsFn != nil {
			stats, err := b.manager.statsFn()
			if err != nil {
				response = fmt.Sprintf("Error getting stats: %v", err)
			} else {
				response = formatStatsResponse(stats)
			}
		} else {
			response = "Stats provider not configured"
		}
	case "help":
		b.manager.mu.RLock()
		var cmds []string
		for name, c := range b.manager.commands {
			if c.Enabled {
				desc := c.Description
				if desc == "" {
					desc = string(c.CommandType)
				}
				cmds = append(cmds, fmt.Sprintf("  %s - %s", name, desc))
			}
		}
		b.manager.mu.RUnlock()
		sort.Strings(cmds)
		response = "Available commands:\n" + strings.Join(cmds, "\n")
	default:
		response = cmd.Response
	}

	if response != "" {
		// M8: the multi-query statusFn/statsFn above widens the race window —
		// re-snapshot b.Conn under the lock instead of dereferencing it raw.
		b.mu.RLock()
		conn := b.Conn
		b.mu.RUnlock()
		if conn == nil {
			return
		}
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if line != "" {
				if err := safePrivmsg(conn, target, line); err != nil {
					log.Printf("IRC: command response to %s failed: %v", target, err)
					break
				}
			}
		}
	}
}

// isAdmin reports whether the given IRC nick is allowed to execute
// AdminOnly commands in the given target. AUDIT-019: previously this
// returned true ONLY for the bot's own nick (which made the admin-only
// check functionally a "no one can run this" check, since the bot never
// PRIVMSGs itself). The pre-fix behavior was a security smell because:
//   - Any admin command was effectively dead code in production
//     (operators couldn't actually use !reset, !config, etc.).
//   - Worse, anyone who could read the code and the channel would
//     assume "admin only" meant "admins only", when in reality it
//     meant "nobody".
//
// The fix: a per-channel allow-list of admin nicks stored on the
// IRCChannel model. If the channel's AdminNicks is empty, no one
// (NOT EVEN THE BOT) can execute admin-only commands — fail-closed
// is the right default for destructive operations.
func (b *Bot) isAdmin(target, nick string) bool {
	if b.Server == nil {
		return false
	}
	// If the message was sent as a private message to the bot
	// (target == bot's own nick), there is no channel config to
	// consult — deny. Operators who want PM-admin can extend this
	// with a server-level allow-list; we deliberately don't ship
	// that until there's a concrete use case.
	if target == "" {
		return false
	}
	// M8: snapshot under the lock — isAdmin runs on the PRIVMSG callback
	// goroutine while Stop/onQuit nil b.Conn.
	b.mu.RLock()
	conn := b.Conn
	b.mu.RUnlock()
	if conn != nil && strings.EqualFold(target, conn.GetNick()) {
		return false
	}
	for i := range b.Server.Channels {
		ch := &b.Server.Channels[i]
		if ch.ChannelName != target {
			continue
		}
		return channelNickAllowed(ch.AdminNicks, nick)
	}
	// Target was a channel we don't have a config record for
	// (e.g. the bot was invited to a channel it wasn't told to
	// join). Fail closed.
	return false
}

// channelNickAllowed returns true if `nick` appears in the
// semicolon-separated `allowList` (case-insensitive, surrounding
// whitespace trimmed). An empty allow list denies everyone.
func channelNickAllowed(allowList, nick string) bool {
	allowList = strings.TrimSpace(allowList)
	if allowList == "" {
		return false
	}
	for _, entry := range strings.Split(allowList, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, nick) {
			return true
		}
	}
	return false
}

func (b *Bot) onJoin(e *irc.Event) {
	channel := e.Arguments[0]
	b.mu.Lock()
	b.channels[channel] = true
	b.mu.Unlock()

	for i := range b.Server.Channels {
		ch := &b.Server.Channels[i]
		if ch.ChannelName == channel {
			now := time.Now()
			ch.Status = "joined"
			ch.JoinedAt = &now
			b.db.Model(ch).Updates(map[string]interface{}{
				"status":    "joined",
				"joined_at": now,
			})

			// M8: snapshot b.Conn under the lock before dereferencing on this
			// library callback goroutine.
			b.mu.RLock()
			conn := b.Conn
			b.mu.RUnlock()
			if conn != nil {
				identifyFailed := false
				if ch.ChanServName != "" && ch.ChanServPass != "" {
					if err := safePrivmsg(conn, ch.ChanServName, "IDENTIFY "+ch.ChanServPass); err != nil {
						log.Printf("IRC: ChanServ identify for %s failed: %v", channel, err)
						identifyFailed = true
					}
				}
				if ch.ChanOperPass != "" && !identifyFailed {
					if err := safePrivmsg(conn, ch.ChanServName, "OP "+channel+" "+ch.ChanOperPass); err != nil {
						log.Printf("IRC: ChanServ OP for %s failed: %v", channel, err)
					}
				}
			}
			break
		}
	}
}

func (b *Bot) onPart(e *irc.Event) {
	channel := e.Arguments[0]
	b.mu.Lock()
	delete(b.channels, channel)
	b.mu.Unlock()

	for i := range b.Server.Channels {
		ch := &b.Server.Channels[i]
		if ch.ChannelName == channel {
			ch.Status = "left"
			b.db.Model(ch).Update("status", "left")
			break
		}
	}
}

func (b *Bot) onQuit(e *irc.Event) {
	// Only handle our own quit, not other users quitting the server
	b.mu.RLock()
	conn := b.Conn
	b.mu.RUnlock()
	if conn == nil || e.Nick != conn.GetNick() {
		return
	}
	log.Printf("IRC: Disconnected from %s", b.Server.ServerHost)
	b.mu.Lock()
	b.Conn = nil
	b.mu.Unlock()
	forgetConn(conn) // AUDIT-314
	b.updateStatus("disconnected", "")
}

func (b *Bot) onNotice(e *irc.Event) {
	message := e.Message()
	nick := e.Nick

	if nick == "NickServ" && strings.Contains(strings.ToUpper(message), "IDENTIFY") {
		log.Printf("IRC: NickServ identification result: %s", message)
	}
}

func (b *Bot) updateStatus(status, errMsg string) {
	updates := map[string]interface{}{
		"status": status,
	}
	if errMsg != "" {
		updates["last_error"] = errMsg
	}
	b.db.Model(b.Server).Updates(updates)
}

// IRC formatting constants
// Pure ASCII characters only — Unicode box-drawing chars break alignment
// in mIRC with Fixedsys font (font-linking substitutes different-width glyphs).
// Bars use colored spaces (background color = the bar) which works in every font.
const (
	ircColor = "\x03"
	ircBold  = "\x02"
	ircReset = "\x0F"
	cBlack   = "01"
	cGreen   = "03"
	cRed     = "04"
	cYellow  = "08"
	cGrey    = "14"
	boxW     = 38 // total visible width per device box
	barW     = 22 // progress bar width (colored spaces)
	contentW = 34 // boxW - 4: usable between "| " and " |"
)

// setC sets IRC foreground color without resetting other formatting
func setC(c string) string { return ircColor + c }

// setCBg sets IRC foreground+background color
func setCBg(fg, bg string) string { return ircColor + fg + "," + bg }

// visLen returns the visible character count (runes, not bytes)
func visLen(s string) int { return utf8.RuneCountInString(s) }

func barColor(pct float64) string {
	if pct > 85 {
		return cRed
	}
	if pct > 60 {
		return cYellow
	}
	return cGreen
}

func makeColorBar(pct float64) string {
	filled := int(pct / 100.0 * float64(barW))
	if filled > barW {
		filled = barW
	}
	if filled < 0 {
		filled = 0
	}
	empty := barW - filled
	var bar string
	// Use colored SPACES for bars — works with any font including Fixedsys
	if filled > 0 {
		bar += setCBg(barColor(pct), barColor(pct)) + strings.Repeat(" ", filled)
	}
	if empty > 0 {
		bar += setCBg(cBlack, cBlack) + strings.Repeat(" ", empty)
	}
	// Reset all formatting to clear background color
	bar += ircReset
	return bar
}

func formatUptime(csec uint64) string {
	if csec == 0 {
		return "N/A"
	}
	// fgSysUpTime is in hundredths of a second (centiseconds)
	seconds := csec / 100
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	mins := (seconds % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func formatSessions(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func truncStr(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// boxLine builds a content line: grey "| " + content + padding + " |"
// pVisLen is the visible character count of ircContent (excluding IRC codes)
func boxLine(ircContent string, pVisLen int) string {
	pad := contentW - pVisLen
	if pad < 0 {
		pad = 0
	}
	return setC(cGrey) + "|" + ircReset + " " + ircContent + strings.Repeat(" ", pad) + " " + setC(cGrey) + "|" + ircReset
}

func deviceBox(d map[string]interface{}) [6]string {
	name, _ := d["name"].(string)
	status, _ := d["status"].(string)
	cpu, _ := d["cpu"].(float64)
	mem, _ := d["mem"].(float64)
	sess, _ := d["sessions"].(int)
	upSec, _ := d["uptime"].(uint64)
	vpnUp, _ := d["vpn_up"].(int)
	vpnTot, _ := d["vpn_total"].(int)
	alerts, _ := d["alerts"].(int)

	upStr := formatUptime(upSec)
	uptimePart := "(Up: " + upStr + ")"

	// Line 1: header +- NAME --- (Up: Xd Xh)-+
	// visible: +(1) + -(1) + " "(1) + name + " "(1) + dashes + uptimePart + -(1) + +(1) = 6 + name + dashes + uptime
	maxName := boxW - 6 - 1 - len(uptimePart)
	if maxName < 3 {
		maxName = 3
	}
	dispName := truncStr(name, maxName)
	dashFill := boxW - 6 - visLen(dispName) - len(uptimePart)
	if dashFill < 1 {
		dashFill = 1
	}
	header := setC(cGrey) + "+-" + ircReset + " " + dispName + " " +
		setC(cGrey) + strings.Repeat("-", dashFill) + uptimePart + "-+" + ircReset

	// Line 2: CPU  [                      ]  42%
	// visible: "CPU  [" (6) + barW (22) + "]" (1) + " %3.0f%%" (5) = 34 = contentW
	cpuPct := fmt.Sprintf(" %3.0f%%", cpu)
	cpuContent := "CPU  [" + makeColorBar(cpu) + "]" + cpuPct
	line2 := boxLine(cpuContent, 6+barW+1+5)

	// Line 3: MEM  [                      ]  62%
	memPct := fmt.Sprintf(" %3.0f%%", mem)
	memContent := "MEM  [" + makeColorBar(mem) + "]" + memPct
	line3 := boxLine(memContent, 6+barW+1+5)

	// Line 4: VPN: 4/5    Alerts: 1
	vpnText := fmt.Sprintf("VPN: %d/%d", vpnUp, vpnTot)
	alertText := fmt.Sprintf("Alerts: %d", alerts)
	l4plain := vpnText + "    " + alertText
	l4irc := "VPN: " + setC(cGreen) + fmt.Sprintf("%d", vpnUp) + ircReset + fmt.Sprintf("/%d", vpnTot) +
		"    Alerts: " + setC(cRed) + fmt.Sprintf("%d", alerts) + ircReset
	line4 := boxLine(l4irc, len(l4plain))

	// Line 5: Sess: 5.2k   * online
	sessStr := formatSessions(sess)
	var sColor string
	if status == "online" {
		sColor = cGreen
	} else {
		sColor = cRed
	}
	l5plain := fmt.Sprintf("Sess: %s   * %s", sessStr, status)
	l5irc := fmt.Sprintf("Sess: %s   ", sessStr) + setC(sColor) + "* " + status + ircReset
	line5 := boxLine(l5irc, len(l5plain))

	// Line 6: footer +------------------------------------+
	footer := setC(cGrey) + "+" + strings.Repeat("-", boxW-2) + "+" + ircReset

	return [6]string{header, line2, line3, line4, line5, footer}
}

func formatStatusResponse(s map[string]interface{}) string {
	devSlice, ok := s["devices"].([]map[string]interface{})
	if !ok || len(devSlice) == 0 {
		return "No devices configured"
	}

	boxes := make([][6]string, len(devSlice))
	for i, d := range devSlice {
		boxes[i] = deviceBox(d)
	}

	// Combine side by side: each IRC line joins all device boxes at that row
	var lines []string
	for row := 0; row < 6; row++ {
		var parts []string
		for _, box := range boxes {
			parts = append(parts, box[row])
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	return strings.Join(lines, "\n")
}

func formatStatsResponse(stats map[string]interface{}) string {
	var parts []string

	if v, ok := stats["total_devices"].(int); ok {
		parts = append(parts, fmt.Sprintf("Total: %d", v))
	}
	if v, ok := stats["cpu_avg"].(float64); ok {
		parts = append(parts, fmt.Sprintf("Avg CPU: %.1f%%", v))
	}
	if v, ok := stats["memory_avg"].(float64); ok {
		parts = append(parts, fmt.Sprintf("Avg Mem: %.1f%%", v))
	}

	if len(parts) == 0 {
		return "No stats data available"
	}
	return strings.Join(parts, " | ")
}

type TestBot struct {
	conn         *irc.Connection
	serverHost   string
	serverPort   int
	nick         string
	username     string
	useTLS       bool
	password     string
	saslEnabled  bool
	saslUsername string
	saslPassword string
}

func NewTestBot(serverHost string, serverPort int, nick, username string, useTLS bool, password string, saslEnabled bool, saslUsername, saslPassword string) *TestBot {
	return &TestBot{
		serverHost:   serverHost,
		serverPort:   serverPort,
		nick:         nick,
		username:     username,
		useTLS:       useTLS,
		password:     password,
		saslEnabled:  saslEnabled,
		saslUsername: saslUsername,
		saslPassword: saslPassword,
	}
}

func (tb *TestBot) Connect() error {
	if tb.username == "" {
		tb.username = tb.nick
	}
	conn := irc.IRC(tb.nick, tb.username)
	conn.UseTLS = tb.useTLS
	if tb.useTLS && tb.serverHost != "" {
		conn.TLSConfig = &tls.Config{
			ServerName: tb.serverHost,
		}
	}
	conn.Password = tb.password
	conn.Timeout = 10 * time.Second

	if tb.saslEnabled {
		conn.UseSASL = true
		conn.SASLLogin = tb.saslUsername
		conn.SASLPassword = tb.saslPassword
	}

	// AUDIT-325: tb.conn is deliberately NOT published yet. The resolve and
	// blocked-IP returns below happen BEFORE any dial, so the conn has a nil
	// Error channel and nothing to unwind; publishing it there would hand a
	// future `defer Disconnect()` a conn whose teardown blocks forever sending
	// on that nil channel. It is published only once Connect has succeeded.

	// AUDIT M1: go-ircevent re-resolves the host inside Connect() with no dialer
	// hook, so resolve + validate here and hand it a pinned IP:port — closing the
	// DNS-rebinding window after the caller's isValidExternalIP pre-check.
	// TLSConfig.ServerName stays the hostname (set above) so SNI/cert verification
	// still validates against the name, not the dialed IP.
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rcancel()
	ips, rerr := net.DefaultResolver.LookupIPAddr(rctx, tb.serverHost)
	if rerr != nil {
		return fmt.Errorf("resolve IRC server %q: %w", tb.serverHost, rerr)
	}
	// Pin ONE validated IP (go-ircevent has no dialer hook to try-each, so we can
	// only hand it a single address). Prefer a non-blocked IPv4 first — a
	// dual-stack host advertising an unreachable AAAA shouldn't fail the test —
	// then fall back to any non-blocked IP.
	var dialIP net.IP
	for _, ipa := range ips {
		if ipa.IP.To4() != nil && !httputil.IsBlockedIP(ipa.IP) {
			dialIP = ipa.IP
			break
		}
	}
	if dialIP == nil {
		for _, ipa := range ips {
			if !httputil.IsBlockedIP(ipa.IP) {
				dialIP = ipa.IP
				break
			}
		}
	}
	if dialIP == nil {
		return fmt.Errorf("refusing to connect: %q resolves only to blocked/internal addresses", tb.serverHost)
	}
	addr := net.JoinHostPort(dialIP.String(), strconv.Itoa(tb.serverPort))
	if err := conn.Connect(addr); err != nil {
		// AUDIT-325: the same unwind hazard as AUDIT-319, and this path is
		// where it bites hardest — testing credentials is precisely how a SASL
		// negotiation gets rejected. Gated on ErrorChan for the same reason: a
		// pre-dial failure has nothing to unwind, and Disconnect would block
		// forever on the nil Error channel. Off the request goroutine so a
		// server that ignores our QUIT cannot stall the admin handler.
		if conn.ErrorChan() != nil {
			logging.SafeGo("irc-testconn-teardown", func() { // REL-01
				teardownConn(conn)
			})
		}
		return err
	}
	tb.conn = conn
	return nil
}

func (tb *TestBot) Disconnect() {
	if tb.conn == nil {
		return
	}
	// AUDIT-325: this used to send QUIT and stop there. QUIT never closes the
	// library's `end` channel, so writeLoop and pingLoop kept running and the
	// socket was never closed — one stranded set per admin test-connection
	// click, on the SUCCESS path. Full teardown, off the request goroutine so
	// a server that ignores the QUIT cannot stall the admin handler.
	conn := tb.conn
	tb.conn = nil
	logging.SafeGo("irc-testconn-teardown", func() { // REL-01
		teardownConn(conn)
	})
}

// ircSendTimeout bounds every write into go-ircevent's internal pwrite
// channel. A var (not const) only so the parked-send regression tests can
// shorten it; production code never mutates it. 15s is far beyond any healthy
// drain of the 10-slot buffer, far under the ~16min read-deadline teardown of
// a half-open socket.
var ircSendTimeout = 15 * time.Second

// errSendTimedOut is the sentinel a timed-out sendWithTimeout wraps, so callers
// can distinguish "connection wedged" from a panic/torn-down error without
// string matching. The user-visible message still contains "timed out".
var errSendTimedOut = errors.New("send timed out")

// writeDeadConns latches connections whose writeLoop is presumed dead. AUDIT-314:
// once a send to a conn times out, the goroutine parked on that conn's full
// (or pre-Connect nil) pwrite can NEVER be reclaimed with this library —
// Disconnect's irc.Wait() deadlocks on the library's own pingLoop parked on the
// same full channel, so close(pwrite) is unreachable. Rather than spawn a fresh
// doomed goroutine on every subsequent send (statusLoop fires one per 30s tick;
// the pre-fix code leaked them monotonically for the process lifetime), the
// first timeout latches the conn here and every later send to it short-circuits
// with an error. The leak is thereby bounded to ONE parked sender per wedged
// connection. Entries are removed by forgetConn when the conn is torn down or
// replaced, so the map only ever holds currently-wedged connections.
var writeDeadConns sync.Map // *irc.Connection -> struct{}

func connWriteDead(conn *irc.Connection) bool {
	_, dead := writeDeadConns.Load(conn)
	return dead
}

func markConnWriteDead(conn *irc.Connection) { writeDeadConns.Store(conn, struct{}{}) }

// forgetConn drops any write-dead latch for conn. Called wherever a conn is
// abandoned — Stop, the error-watcher, onQuit, DISCONNECTED, and teardownConn
// (which covers the AUDIT-206 stop-race and the AUDIT-319/325 failed-connect
// paths) — so a superseded conn's entry does not linger. Idempotent.
func forgetConn(conn *irc.Connection) {
	if conn != nil {
		writeDeadConns.Delete(conn)
	}
}

// teardownConn fully unwinds a connection this package owns: QUIT, drop any
// write-dead latch, then Disconnect. It must be the SOLE Disconnect caller for
// that conn — a second call panics on the already-closed pwrite — which holds
// because every caller drops its reference before invoking this.
//
// AUDIT-319/325: the library spawns its three loops and opens the socket
// BEFORE capability/SASL negotiation, and a QUIT on its own never closes
// `end`, so neither a failed negotiation nor a bare QUIT unwinds anything.
//
// QUIT goes first so the server drops us and readLoop's blocking read returns
// promptly. Disconnect waits on all three loops BEFORE it closes the socket,
// so without the QUIT it would stall for readLoop's full
// Timeout+PingFreq read deadline — ~16 min for a bot conn (library defaults
// 1m+15m), 15m10s for a TestBot conn, which lowers Timeout to 10s. safeQuit is timeout-bounded and
// latches a wedged conn, so it always returns; the caller runs this on its own
// goroutine so a server that ignores the QUIT delays nothing but this cleanup.
//
// The QUIT must also actually reach the wire before Disconnect runs. safeQuit
// only queues it on the library's buffered pwrite channel, and Disconnect
// closes `end` before it waits; writeLoop selects between `end` and pwrite,
// so if it has not yet woken for the QUIT when `end` closes, Go picks between
// the two ready cases at random and the QUIT is dropped half the time —
// leaving exactly the stall above. Locally writeLoop nearly always wakes
// first; under the race detector on a loaded CI runner it often does not
// (TestTeardownConn_UnwindsLoops_AUDIT319 timed out on two of the six
// race-lane runs on 2026-09-06). So after a queued QUIT, wait for the server to drop the
// session — readLoop reports that on ErrorChan, which nothing else reads for
// a conn being torn down here — bounded so a server that ignores the QUIT
// still only delays this cleanup goroutine.
func teardownConn(conn *irc.Connection) {
	if err := safeQuit(conn); err == nil {
		select {
		case <-conn.ErrorChan():
		case <-time.After(teardownQuitDrain):
		}
	}
	forgetConn(conn)
	conn.Disconnect()
}

// teardownQuitDrain bounds how long teardownConn waits for the server to drop
// the session after a QUIT before it disconnects regardless. A real ircd
// closes within milliseconds; the bound only matters for one that ignores QUIT.
const teardownQuitDrain = 2 * time.Second

// sendVia wraps sendWithTimeout with the per-connection write-dead latch
// (AUDIT-314). A conn already latched dead never spawns another sender; the
// first timeout latches it. Every production send routes through here via the
// safe* wrappers; sendWithTimeout stays latch-free so the raw
// timeout/panic-contract tests exercise it directly.
func sendVia(conn *irc.Connection, desc string, send func()) error {
	if connWriteDead(conn) {
		return fmt.Errorf("%s skipped: connection write-dead", desc)
	}
	err := sendWithTimeout(desc, send)
	if errors.Is(err, errSendTimedOut) {
		markConnWriteDead(conn)
	}
	return err
}

// sendWithTimeout runs one library write with both guards every send needs:
//
//   - Panic → error: the error watcher's conn.Disconnect() closes the
//     library's pwrite channel, so a caller holding a pre-teardown snapshot
//     of the conn would otherwise panic on an unrecovered goroutine.
//   - Parked send → timeout error: pwrite is a 10-slot buffered channel with
//     no timeout API, and once writeLoop dies its buffer fills and a bare
//     send parks FOREVER — Disconnect() cannot free it, because its
//     irc.Wait() deadlocks on the library's own pingLoop parked on the same
//     full channel, so close(pwrite) is never reached. A parked send in
//     statusLoop wedged prod auto-status permanently (2026-08); a parked
//     send in a callback freezes that conn's read loop (RunCallbacks waits
//     unboundedly). On timeout the sender goroutine is abandoned. That
//     abandoned goroutine genuinely cannot be reclaimed in the wedge (the
//     library exposes no cancellable send and close(pwrite) is unreachable —
//     the earlier "self-reclaiming" claim here was wrong, AUDIT-314), so
//     sendVia latches the conn write-dead on the first timeout: every later
//     send to it short-circuits, bounding the leak to ONE parked sender per
//     wedged connection instead of one per 30s status tick.
//
// This is the raw guard; production sends go through sendVia (the latch).
// desc must be verb + target only, never message content — NickServ/ChanServ
// IDENTIFY sends carry passwords and must not reach logs.
func sendWithTimeout(desc string, send func()) error {
	done := make(chan error, 1) // buffered: an abandoned sender can still finish and exit
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("connection torn down mid-send: %v", r)
			}
		}()
		send()
		done <- nil
	}()
	t := time.NewTimer(ircSendTimeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		log.Printf("IRC: %s timed out after %v; abandoning parked sender (connection presumed dead)", desc, ircSendTimeout)
		return fmt.Errorf("%s timed out after %v: %w", desc, ircSendTimeout, errSendTimedOut)
	}
}

func safePrivmsg(conn *irc.Connection, target, message string) error {
	return sendVia(conn, "PRIVMSG to "+target, func() { conn.Privmsg(target, message) })
}

func safeNotice(conn *irc.Connection, target, message string) error {
	return sendVia(conn, "NOTICE to "+target, func() { conn.Notice(target, message) })
}

// safeJoin takes the loggable channel name separately: channelSpec may carry
// a channel key, which must never reach logs — and deriving the name from the
// spec would log the key itself on a whitespace-only channel name.
func safeJoin(conn *irc.Connection, channelSpec, logName string) error {
	return sendVia(conn, "JOIN "+logName, func() { conn.Join(channelSpec) })
}

func safeNick(conn *irc.Connection, nick string) error {
	return sendVia(conn, "NICK "+nick, func() { conn.Nick(nick) })
}

func safeQuit(conn *irc.Connection) error {
	return sendVia(conn, "QUIT", conn.Quit)
}

func (b *Bot) SendMessage(channel, message string) error {
	b.mu.RLock()
	conn := b.Conn
	b.mu.RUnlock()

	if conn == nil || !conn.Connected() {
		return fmt.Errorf("not connected")
	}

	return safePrivmsg(conn, channel, message)
}

func (b *Bot) SendAlert(channel, alertMsg string) error {
	return b.SendMessage(channel, fmt.Sprintf("[ALERT] %s", alertMsg))
}

func (m *Manager) GetBot(serverID uint) *Bot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bots[serverID]
}

func (m *Manager) SendToChannel(serverID uint, channel, message string) error {
	m.mu.RLock()
	bot := m.bots[serverID]
	m.mu.RUnlock()

	if bot == nil {
		return fmt.Errorf("bot not found for server %d", serverID)
	}

	return bot.SendMessage(channel, message)
}

func (m *Manager) SendAlertToChannel(serverID uint, channel, alertMsg string) error {
	m.mu.RLock()
	bot := m.bots[serverID]
	m.mu.RUnlock()

	if bot == nil {
		return fmt.Errorf("bot not found for server %d", serverID)
	}

	return bot.SendAlert(channel, alertMsg)
}

func (m *Manager) ReloadCommands() {
	m.loadCommands()
}

func (m *Manager) RestartBot(serverID uint) error {
	m.mu.RLock()
	bot := m.bots[serverID]
	m.mu.RUnlock()

	if bot != nil {
		bot.Stop()
		time.Sleep(jitter(1 * time.Second)) // AUDIT-088: jittered reconnect delay
	}

	var server models.IRCServer
	if err := m.db.Preload("Channels").First(&server, serverID).Error; err != nil {
		return err
	}

	m.decryptServerSecrets(&server)
	newBot := m.createBot(&server)
	m.mu.Lock()
	m.bots[serverID] = newBot
	m.mu.Unlock()

	if server.Enabled {
		m.launchBot(newBot) // AUDIT-315: same panic-recovered launch path as the siblings
	}

	return nil
}
