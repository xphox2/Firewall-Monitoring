package irc

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
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
// this bot now: auto-reconnect enabled, not connected, and past the backoff.
func (b *Bot) reconnectDue(now time.Time) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Server.AutoReconnect && b.Conn == nil && now.After(b.nextAttempt)
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
	m.mu.RLock()
	for _, bot := range m.bots {
		bot.Stop()
	}
	m.mu.RUnlock()
	m.wg.Wait()
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
			m.wg.Add(1)
			go func(b *Bot) {
				defer logging.Recover("irc-bot") // REL-01
				defer m.wg.Done()
				b.Start()
			}(bot)
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
					m.wg.Add(1)
					go func(b *Bot) {
						defer logging.Recover("irc-bot") // REL-01
						defer m.wg.Done()
						b.Start()
					}(bot)
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
				m.sendAutoStatus()
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
// the lock is released, and sends happen lock-free — a parked send can still
// stall THIS loop (auto-status stops until reconnect churn frees it), but it
// can no longer wedge the rest of the process.
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
	conn := irc.IRC(server.Nick, server.Username)
	if server.Username == "" {
		conn = irc.IRC(server.Nick, server.Nick)
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
		conn.Nick(newNick)
	})

	b.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", server.ServerHost, server.ServerPort)
	if err := conn.Connect(addr); err != nil {
		log.Printf("IRC: Failed to connect to %s: %v", addr, err)
		b.updateStatus("error", err.Error())
		b.mu.Lock()
		b.Conn = nil
		b.mu.Unlock()
		b.noteConnectFailure()
		return
	}

	// Deliberately NOT conn.Loop(): the library's loop reconnects internally
	// with ZERO delay whenever the TCP dial succeeds but the connection dies
	// right after — this go-ircevent version defers the TLS handshake to the
	// read loop (tls.Client, no explicit Handshake), so an expired/bad server
	// cert becomes an infinite dial→fail hot loop (~3,500 log lines/min in
	// prod). Instead: consume the FIRST error, tear the connection down, and
	// hand reconnection to the manager's 30s sweep, which honors AutoReconnect
	// and this bot's exponential backoff. conn.Quit() is avoided on purpose —
	// its SendRaw can park forever on the dead write loop (the H5 hazard).
	logging.SafeGo("irc-conn-loop", func() { // REL-01
		err := <-conn.ErrorChan()
		log.Printf("IRC: Connection to %s lost: %v", addr, err)
		b.mu.Lock()
		b.Conn = nil
		b.mu.Unlock()
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
	b.mu.Lock()
	select {
	case <-b.quit:
		// already closed
	default:
		close(b.quit)
	}
	if b.Conn != nil {
		b.Conn.Quit()
		b.Conn = nil
	}
	b.mu.Unlock()
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
		conn.Privmsg("NickServ", "IDENTIFY "+b.Server.NickServPassword)
	}

	for _, ch := range b.Server.Channels {
		if ch.Enabled && ch.AutoJoin {
			chanName := ch.ChannelName
			if ch.ChannelKey != "" {
				chanName += " " + ch.ChannelKey
			}
			conn.Join(chanName)
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

	if !exists {
		conn.Notice(target, fmt.Sprintf("Unknown command: %s", parts[0]))
		return
	}

	if cmd.AdminOnly && !b.isAdmin(target, nick) {
		conn.Notice(target, "This command is admin only")
		return
	}

	b.handleCommand(target, cmd, parts[1:])
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
				conn.Privmsg(target, line)
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
				if ch.ChanServName != "" && ch.ChanServPass != "" {
					conn.Privmsg(ch.ChanServName, "IDENTIFY "+ch.ChanServPass)
				}
				if ch.ChanOperPass != "" {
					conn.Privmsg(ch.ChanServName, "OP "+channel+" "+ch.ChanOperPass)
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

	tb.conn = conn

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
	return conn.Connect(addr)
}

func (tb *TestBot) Disconnect() {
	if tb.conn != nil {
		tb.conn.Quit()
		tb.conn = nil
	}
}

// safePrivmsg sends one PRIVMSG, converting the send-on-closed-channel panic
// into an error. The error watcher's conn.Disconnect() closes the library's
// pwrite channel, so any caller holding a pre-teardown snapshot of the conn
// (SendMessage, sendAutoStatus's lock-free send window) would otherwise panic
// — and a panic inside statusLoop's SafeGo would kill auto-status for the
// process lifetime (SafeGo contains, it does not restart).
func safePrivmsg(conn *irc.Connection, target, message string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("connection torn down mid-send: %v", r)
		}
	}()
	conn.Privmsg(target, message)
	return nil
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
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			newBot.Start()
		}()
	}

	return nil
}
