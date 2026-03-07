package irc

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/models"

	"github.com/thoj/go-ircevent"
	"gorm.io/gorm"
)

type Bot struct {
	ID       uint
	Server   *models.IRCServer
	Conn     *irc.Connection
	db       *gorm.DB
	manager  *Manager
	channels map[string]bool
	mu       sync.RWMutex
	quit     chan struct{}
}

type Manager struct {
	db       *gorm.DB
	bots     map[uint]*Bot
	mu       sync.RWMutex
	commands map[string]*models.IRCCommand
	wg       sync.WaitGroup
	quit     chan struct{}
	statusFn func() (map[string]interface{}, error)
	statsFn  func() (map[string]interface{}, error)
}

func NewManager(db *gorm.DB) *Manager {
	return &Manager{
		db:       db,
		bots:     make(map[uint]*Bot),
		commands: make(map[string]*models.IRCCommand),
		quit:     make(chan struct{}),
	}
}

func (m *Manager) SetStatusProvider(fn func() (map[string]interface{}, error)) {
	m.statusFn = fn
}

func (m *Manager) SetStatsProvider(fn func() (map[string]interface{}, error)) {
	m.statsFn = fn
}

func (m *Manager) Start() {
	go m.loadAndStartBots()
	go m.reconnectLoop()
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
			bot := m.createBot(&server)
			m.bots[server.ID] = bot
			m.wg.Add(1)
			go func(b *Bot) {
				defer m.wg.Done()
				b.Start()
			}(bot)
		}
	}
	m.mu.Unlock()

	m.loadCommands()
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

func (m *Manager) reconnectLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.quit:
			return
		case <-ticker.C:
			m.mu.RLock()
			for _, bot := range m.bots {
				if bot.Server.AutoReconnect && bot.Conn == nil {
					bot.Start()
				}
			}
			m.mu.RUnlock()
		}
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
	conn.Password = server.Password

	if server.SASLEnabled {
		conn.UseSASL = true
		conn.SASLLogin = server.SASLUsername
		conn.SASLPassword = server.SASLPassword
	}

	b.Conn = conn

	conn.AddCallback("001", func(e *irc.Event) {
		b.onConnected()
	})

	conn.AddCallback("PRIVMSG", func(e *irc.Event) {
		b.onPrivmsg(e)
	})

	conn.AddCallback("JOIN", func(e *irc.Event) {
		b.onJoin(e)
	})

	conn.AddCallback("PART", func(e *irc.Event) {
		b.onPart(e)
	})

	conn.AddCallback("QUIT", func(e *irc.Event) {
		b.onQuit(e)
	})

	conn.AddCallback("NOTICE", func(e *irc.Event) {
		b.onNotice(e)
	})

	conn.AddCallback("433", func(e *irc.Event) {
		newNick := server.Nick + "_"
		conn.Nick(newNick)
	})

	conn.AddCallback("NICK", func(e *irc.Event) {
		if e.Nick == conn.GetNick() && len(e.Arguments) > 0 {
			conn.Nick(e.Arguments[0])
		}
	})

	b.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", server.ServerHost, server.ServerPort)
	if err := conn.Connect(addr); err != nil {
		log.Printf("IRC: Failed to connect to %s: %v", addr, err)
		b.updateStatus("error", err.Error())
		b.mu.Lock()
		b.Conn = nil
		b.mu.Unlock()
		return
	}

	go conn.Loop()
}

func (b *Bot) Stop() {
	close(b.quit)
	b.mu.Lock()
	if b.Conn != nil {
		b.Conn.Quit()
		b.Conn = nil
	}
	b.mu.Unlock()
}

func (b *Bot) onConnected() {
	log.Printf("IRC: Connected to %s as %s", b.Server.ServerHost, b.Conn.GetNick())

	if b.Server.NickServIdentify && b.Server.NickServPassword != "" {
		b.Conn.Privmsg("NickServ", "IDENTIFY "+b.Server.NickServPassword)
	}

	for _, ch := range b.Server.Channels {
		if ch.Enabled && ch.AutoJoin {
			chanName := ch.ChannelName
			if ch.ChannelKey != "" {
				chanName += " " + ch.ChannelKey
			}
			b.Conn.Join(chanName)
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

	cmdStr := strings.ToLower(parts[0])
	b.mu.RLock()
	cmd, exists := b.manager.commands[cmdStr]
	b.mu.RUnlock()

	if !exists {
		b.Conn.Notice(target, fmt.Sprintf("Unknown command: %s", parts[0]))
		return
	}

	if cmd.AdminOnly && !b.isAdmin(nick) {
		b.Conn.Notice(target, "This command is admin only")
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
	default:
		response = cmd.Response
	}

	if response != "" {
		b.Conn.Privmsg(target, response)
	}
}

func (b *Bot) isAdmin(nick string) bool {
	// TODO: Implement proper admin verification via channel mode (op/voice)
	// For now, all users can run admin-only commands
	// To implement: check if nick has +o or +v mode in the channel
	return true
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

			if ch.ChanServName != "" && ch.ChanServPass != "" {
				b.Conn.Privmsg(ch.ChanServName, "IDENTIFY "+ch.ChanServPass)
			}
			if ch.ChanOperPass != "" {
				b.Conn.Privmsg(ch.ChanServName, "OP "+channel+" "+ch.ChanOperPass)
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

func formatStatusResponse(status map[string]interface{}) string {
	var parts []string

	if v, ok := status["device_count"].(int); ok {
		parts = append(parts, fmt.Sprintf("Devices: %d", v))
	}
	if v, ok := status["online_devices"].(int); ok {
		parts = append(parts, fmt.Sprintf("Online: %d", v))
	}
	if v, ok := status["offline_devices"].(int); ok {
		parts = append(parts, fmt.Sprintf("Offline: %d", v))
	}
	if v, ok := status["alert_count"].(int); ok {
		parts = append(parts, fmt.Sprintf("Alerts: %d", v))
	}

	if len(parts) == 0 {
		return "No status data available"
	}
	return strings.Join(parts, " | ")
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
		password:    password,
		saslEnabled: saslEnabled,
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

	addr := fmt.Sprintf("%s:%d", tb.serverHost, tb.serverPort)
	return conn.Connect(addr)
}

func (tb *TestBot) Disconnect() {
	if tb.conn != nil {
		tb.conn.Quit()
		tb.conn = nil
	}
}

func (b *Bot) SendMessage(channel, message string) error {
	b.mu.RLock()
	conn := b.Conn
	b.mu.RUnlock()

	if conn == nil || conn.Connected() == false {
		return fmt.Errorf("not connected")
	}

	conn.Privmsg(channel, message)
	return nil
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
		time.Sleep(1 * time.Second)
	}

	var server models.IRCServer
	if err := m.db.Preload("Channels").First(&server, serverID).Error; err != nil {
		return err
	}

	newBot := m.createBot(&server)
	m.mu.Lock()
	m.bots[serverID] = newBot
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		newBot.Start()
	}()

	return nil
}
