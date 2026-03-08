package irc

import (
	"crypto/tls"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	conn.Password = server.ServerPassword

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
	case "help":
		b.manager.mu.RLock()
		var cmds []string
		for name, c := range b.manager.commands {
			if c.Enabled {
				desc := c.Description
				if desc == "" {
					desc = c.CommandType
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
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if line != "" {
				b.Conn.Privmsg(target, line)
			}
		}
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

// IRC formatting constants
// Strategy: use setC() to change colors inline without \x0F reset.
// Only one \x0F at the very end of each line. This prevents mid-line
// resets from breaking alignment or killing monospace mode.
const (
	ircColor  = "\x03"
	ircReset  = "\x0F"
	cWhite    = "00"
	cBlack    = "01"
	cGreen    = "03"
	cRed      = "04"
	cYellow   = "08"
	cGrey     = "14"
	boxH      = "-"
	boxV      = "|"
	boxTL     = "+"
	boxTR     = "+"
	boxBL     = "+"
	boxBR     = "+"
	blockFull = "|"
	statusDot = "*"
	boxW      = 30 // total visible width per device box
	barW      = 16 // progress bar character width
	contentW  = 26 // boxW - 4: usable between "| " and " |"
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
	if filled > 0 {
		bar += setCBg(barColor(pct), cBlack) + strings.Repeat(blockFull, filled)
	}
	if empty > 0 {
		bar += setCBg(cBlack, cBlack) + strings.Repeat(blockFull, empty)
	}
	// Reset bg by setting fg only — next setC() call will clear bg context
	bar += setC(cWhite)
	return bar
}

func formatUptime(seconds uint64) string {
	if seconds == 0 {
		return "N/A"
	}
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
	return setC(cGrey) + boxV + setC(cWhite) + " " + ircContent + strings.Repeat(" ", pad) + " " + setC(cGrey) + boxV + ircReset
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

	// Line 1: header +- NAME ---- (Up: Xd Xh) -+
	// visible = +(1) + -(1) + " "(1) + name + " "(1) + dashes + uptimePart + " "(1) + -(1) + +(1) = 7 + name + dashes + uptime
	maxName := boxW - 7 - 1 - len(uptimePart)
	if maxName < 3 {
		maxName = 3
	}
	dispName := truncStr(name, maxName)
	dashFill := boxW - 7 - visLen(dispName) - len(uptimePart)
	if dashFill < 1 {
		dashFill = 1
	}
	header := setC(cGrey) + boxTL + boxH + setC(cWhite) + " " + dispName + " " +
		setC(cGrey) + strings.Repeat(boxH, dashFill) + uptimePart + " " + boxH + boxTR + ircReset

	// Line 2: CPU [||||||||||||||||]  42%
	// visible: "CPU [" (5) + barW (16) + "]" (1) + "%4s" (4) = 26 = contentW
	cpuPct := fmt.Sprintf("%3.0f%%", cpu)
	cpuContent := "CPU [" + makeColorBar(cpu) + "]" + cpuPct
	line2 := boxLine(cpuContent, 5+barW+1+4)

	// Line 3: MEM [||||||||||||||||]  62%
	memPct := fmt.Sprintf("%3.0f%%", mem)
	memContent := "MEM [" + makeColorBar(mem) + "]" + memPct
	line3 := boxLine(memContent, 5+barW+1+4)

	// Line 4: VPN: 4/5 up  Alerts: 1
	vpnText := fmt.Sprintf("VPN:%d/%d", vpnUp, vpnTot)
	alertText := fmt.Sprintf("Alrt:%d", alerts)
	l4plain := vpnText + "  " + alertText
	l4irc := "VPN:" + setC(cGreen) + fmt.Sprintf("%d", vpnUp) + setC(cWhite) + fmt.Sprintf("/%d", vpnTot) +
		"  Alrt:" + setC(cRed) + fmt.Sprintf("%d", alerts) + setC(cWhite)
	line4 := boxLine(l4irc, visLen(l4plain))

	// Line 5: Sess: 5.2k  * online
	sessStr := formatSessions(sess)
	var sColor string
	if status == "online" {
		sColor = cGreen
	} else {
		sColor = cRed
	}
	l5plain := fmt.Sprintf("Sess:%s  %s %s", sessStr, statusDot, status)
	l5irc := fmt.Sprintf("Sess:%s  ", sessStr) + setC(sColor) + statusDot + " " + status + setC(cWhite)
	line5 := boxLine(l5irc, visLen(l5plain))

	// Line 6: footer +----------------------------+
	footer := setC(cGrey) + boxBL + strings.Repeat(boxH, boxW-2) + boxBR + ircReset

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
