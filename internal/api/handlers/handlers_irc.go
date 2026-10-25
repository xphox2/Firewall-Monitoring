package handlers

import (
	"log"
	"math"
	"net/http"
	"strconv"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/irc"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// Client-editable columns for the IRC update handlers (M-12). Server-owned
// state — id, timestamps, connection status, last_connected/last_error,
// joined_at — is never writable through an update.
var (
	ircServerUpdateFields = map[string]bool{
		"name": true, "server_host": true, "server_port": true, "use_tls": true,
		"nick": true, "username": true, "real_name": true,
		"server_password": true, "nickserv_password": true, "nickserv_identify": true,
		"sasl_enabled": true, "sasl_username": true, "sasl_password": true,
		"enabled": true, "auto_reconnect": true, "reconnect_delay": true,
	}
	ircChannelUpdateFields = map[string]bool{
		"server_id": true, "channel_name": true, "channel_key": true,
		"chanserv_name": true, "chanserv_password": true, "chan_oper_pass": true,
		"auto_join": true, "send_alerts": true, "send_status": true,
		"status_interval": true, "enabled": true, "admin_nicks": true,
	}
	ircCommandUpdateFields = map[string]bool{
		"command": true, "description": true, "response": true,
		"command_type": true, "enabled": true, "admin_only": true,
	}
)

// validIntUpdate reports whether updates[field], when present, is a whole
// number in [lo, hi] (JSON numbers decode as float64). A null value — what an
// emptied number input serialises to — is dropped as "unchanged" first.
func validIntUpdate(updates map[string]interface{}, field string, lo, hi float64) bool {
	raw, has := updates[field]
	if !has {
		return true
	}
	if raw == nil {
		delete(updates, field)
		return true
	}
	f, ok := raw.(float64)
	return ok && f >= lo && f <= hi && f == math.Trunc(f)
}

func (h *Handler) GetIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	// Defensive cap (v0.10.217, bundle D3). IRC config rarely exceeds
	// a handful of servers; 200 leaves headroom for accidental dupes.
	var servers []models.IRCServer
	if err := db.Gorm().Preload("Channels").Limit(200).Find(&servers).Error; err != nil {
		httputil.InternalError(c, "Failed to get IRC servers", err)
		return
	}
	// Never return IRC secrets to the browser. The values are encrypted at rest;
	// GET responses show the mask (Connect/Test read plaintext server-side).
	httputil.RedactIRCServers(servers)
	c.JSON(http.StatusOK, response.Success(servers))
}

func (h *Handler) GetIRCServerByID(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := db.Gorm().Preload("Channels").First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Server not found"))
		return
	}
	httputil.RedactIRCServer(&server)
	c.JSON(http.StatusOK, response.Success(server))
}

func (h *Handler) CreateIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	var server models.IRCServer
	if err := c.ShouldBindJSON(&server); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if server.Nick == "" || server.ServerHost == "" {
		c.JSON(http.StatusBadRequest, response.Error("Nick and server host are required"))
		return
	}

	// D-24: validate the server host like the "test connection" endpoint, so an
	// admin (or a stolen session) can't point the bot at a loopback/private/
	// link-local address (SSRF).
	if !isValidExternalIP(server.ServerHost) {
		c.JSON(http.StatusBadRequest, response.Error("Server host resolves to a blocked address"))
		return
	}

	if server.ServerPort == 0 {
		server.ServerPort = 6667
	}

	// H-11: zero server-owned fields so a client cannot mass-assign them (id,
	// timestamps, runtime status, or the channels association).
	server.ID = 0
	server.CreatedAt = time.Time{}
	server.UpdatedAt = time.Time{}
	server.Status = ""
	server.LastConnected = nil
	server.LastError = ""
	server.Channels = nil

	if err := db.EncryptIRCServerSecrets(&server); err != nil {
		// D-12: never store the IRC credentials as plaintext.
		httputil.InternalError(c, "Failed to encrypt server credentials", err)
		return
	}

	if err := db.Gorm().Create(&server).Error; err != nil {
		httputil.InternalError(c, "Failed to create server", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	httputil.RedactIRCServer(&server)
	c.JSON(http.StatusOK, response.Success(server))
}

func (h *Handler) UpdateIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := db.Gorm().First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Server not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// M-12: allow-list, not a deny-list. Anything not named here (id,
	// timestamps, runtime status, last_error, the preloaded channels
	// association, unknown columns) is dropped silently — the UIs send the
	// whole row back on edit.
	updates = httputil.FilterAllowedFields(updates, ircServerUpdateFields)

	// Skip empty strings for required fields to avoid NOT NULL constraint errors
	if v, ok := updates["name"].(string); ok && v == "" {
		delete(updates, "name")
	}
	if v, ok := updates["server_host"].(string); ok && v == "" {
		delete(updates, "server_host")
	}
	if v, ok := updates["nick"].(string); ok && v == "" {
		delete(updates, "nick")
	}

	// D-24: validate the server host (if changed) like the "test connection"
	// endpoint, so an admin can't point the bot at a loopback/private/link-local
	// address.
	if host, ok := updates["server_host"].(string); ok && host != "" && !isValidExternalIP(host) {
		c.JSON(http.StatusBadRequest, response.Error("Server host resolves to a blocked address"))
		return
	}

	if !validIntUpdate(updates, "server_port", 1, 65535) {
		c.JSON(http.StatusBadRequest, response.Error("Server port must be between 1 and 65535"))
		return
	}
	if !validIntUpdate(updates, "reconnect_delay", 0, 86400) {
		c.JSON(http.StatusBadRequest, response.Error("Reconnect delay must be between 0 and 86400 seconds"))
		return
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("No valid fields to update"))
		return
	}

	// Encrypt password fields before saving. A value equal to the redaction mask
	// means "unchanged" (the client GETs masked secrets now) — drop it so we
	// never encrypt "********" over the real stored secret.
	for _, field := range []string{"server_password", "nickserv_password", "sasl_password"} {
		if v, ok := updates[field].(string); ok {
			if v == httputil.RedactedMask {
				delete(updates, field)
			} else if v != "" {
				ct, err := db.EncryptField(v)
				if err != nil {
					httputil.InternalError(c, "Failed to encrypt credentials", err)
					return
				}
				updates[field] = ct
			}
		}
	}

	if err := db.Gorm().Model(&server).Updates(updates).Error; err != nil {
		log.Printf("Failed to update IRC server %d: %v", id, err)
		httputil.InternalError(c, "Failed to update server", err)
		return
	}

	// Re-fetch to return current state
	db.Gorm().Preload("Channels").First(&server, id)

	if mgr := h.GetIRCManager(); mgr != nil {
		if server.Enabled {
			mgr.RestartBot(uint(id))
		} else {
			if bot := mgr.GetBot(uint(id)); bot != nil {
				bot.Stop()
			}
		}
		mgr.ReloadCommands()
	}

	// Mask secrets before returning — never echo plaintext (or ciphertext) back.
	httputil.RedactIRCServer(&server)
	c.JSON(http.StatusOK, response.Success(server))
}

func (h *Handler) DeleteIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid server ID"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		if bot := mgr.GetBot(uint(id)); bot != nil {
			bot.Stop()
		}
	}

	if err := db.Gorm().Delete(&models.IRCServer{}, id).Error; err != nil {
		httputil.InternalError(c, "Failed to delete server", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Server deleted"))
}

func (h *Handler) ConnectIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := db.Gorm().First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Server not found"))
		return
	}

	if !server.Enabled {
		db.Gorm().Model(&server).Update("enabled", true)
		server.Enabled = true
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		if err := mgr.RestartBot(uint(id)); err != nil {
			httputil.InternalError(c, "Failed to connect", err)
			return
		}
	}

	c.JSON(http.StatusOK, response.Message("Connecting to server..."))
}

func (h *Handler) DisconnectIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid server ID"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		if bot := mgr.GetBot(uint(id)); bot != nil {
			bot.Stop()
		}
	}

	db.Gorm().Model(&models.IRCServer{}).Where("id = ?", id).Update("status", "disconnected")

	c.JSON(http.StatusOK, response.Message("Disconnected"))
}

func (h *Handler) GetIRCChannels(c *gin.Context) {
	db := h.reqDB(c)
	serverID := c.Query("server_id")
	var channels []models.IRCChannel

	// Defensive cap (v0.10.217, bundle D3). IRC channels per fleet are
	// typically under 100; 500 is comfortable headroom.
	if serverID != "" {
		if err := db.Gorm().Where("server_id = ?", serverID).Limit(500).Find(&channels).Error; err != nil {
			httputil.InternalError(c, "Failed to get channels", err)
			return
		}
	} else {
		if err := db.Gorm().Limit(500).Find(&channels).Error; err != nil {
			httputil.InternalError(c, "Failed to get channels", err)
			return
		}
	}
	for i := range channels {
		httputil.RedactIRCChannel(&channels[i])
	}
	c.JSON(http.StatusOK, response.Success(channels))
}

func (h *Handler) CreateIRCChannel(c *gin.Context) {
	db := h.reqDB(c)
	var channel models.IRCChannel
	if err := c.ShouldBindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if channel.ChannelName == "" || channel.ServerID == 0 {
		c.JSON(http.StatusBadRequest, response.Error("Channel name and server ID are required"))
		return
	}

	// H-11: zero server-owned fields so a client cannot mass-assign them.
	channel.ID = 0
	channel.CreatedAt = time.Time{}
	channel.UpdatedAt = time.Time{}
	channel.Status = ""
	channel.JoinedAt = nil
	channel.Server = nil

	if err := db.EncryptIRCChannelSecrets(&channel); err != nil {
		// D-12: never store the channel credentials as plaintext.
		httputil.InternalError(c, "Failed to encrypt channel credentials", err)
		return
	}

	if err := db.Gorm().Create(&channel).Error; err != nil {
		httputil.InternalError(c, "Failed to create channel", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(channel.ServerID)
	}

	httputil.RedactIRCChannel(&channel)
	c.JSON(http.StatusOK, response.Success(channel))
}

func (h *Handler) UpdateIRCChannel(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid channel ID"))
		return
	}

	var channel models.IRCChannel
	if err := db.Gorm().First(&channel, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Channel not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// M-12: allow-list (see UpdateIRCServer).
	updates = httputil.FilterAllowedFields(updates, ircChannelUpdateFields)
	if v, ok := updates["channel_name"].(string); ok && v == "" {
		delete(updates, "channel_name")
	}

	if !validIntUpdate(updates, "status_interval", 0, 7*86400) {
		c.JSON(http.StatusBadRequest, response.Error("Status interval must be between 0 and 604800 seconds"))
		return
	}

	// A channel may be moved to another server, but only to one that exists.
	// null (an emptied select) means "unchanged", as for the number fields.
	if raw, has := updates["server_id"]; has && raw == nil {
		delete(updates, "server_id")
	}
	oldServerID := channel.ServerID
	newServerID := oldServerID
	if raw, has := updates["server_id"]; has {
		f, ok := raw.(float64)
		if !ok || f < 1 || f > math.MaxUint32 || f != math.Trunc(f) {
			c.JSON(http.StatusBadRequest, response.Error("Invalid server ID"))
			return
		}
		newServerID = uint(f)
		var n int64
		if err := db.Gorm().Model(&models.IRCServer{}).Where("id = ?", newServerID).Count(&n).Error; err != nil {
			httputil.InternalError(c, "Failed to update channel", err)
			return
		}
		if n == 0 {
			c.JSON(http.StatusBadRequest, response.Error("Server not found"))
			return
		}
		updates["server_id"] = newServerID
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("No valid fields to update"))
		return
	}

	// Encrypt password fields before saving. Mask == "unchanged": drop it so we
	// never encrypt "********" over the real stored secret.
	for _, field := range []string{"chanserv_password", "chan_oper_pass", "channel_key"} {
		if v, ok := updates[field].(string); ok {
			if v == httputil.RedactedMask {
				delete(updates, field)
			} else if v != "" {
				ct, err := db.EncryptField(v)
				if err != nil {
					httputil.InternalError(c, "Failed to encrypt credentials", err)
					return
				}
				updates[field] = ct
			}
		}
	}

	if err := db.Gorm().Model(&channel).Updates(updates).Error; err != nil {
		httputil.InternalError(c, "Failed to update channel", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(newServerID)
		if oldServerID != newServerID {
			mgr.RestartBot(oldServerID)
		}
	}

	// Re-fetch and mask for response.
	db.Gorm().First(&channel, id)
	httputil.RedactIRCChannel(&channel)
	c.JSON(http.StatusOK, response.Success(channel))
}

func (h *Handler) DeleteIRCChannel(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid channel ID"))
		return
	}

	var channel models.IRCChannel
	if err := db.Gorm().First(&channel, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Channel not found"))
		return
	}

	serverID := channel.ServerID

	if err := db.Gorm().Delete(&channel).Error; err != nil {
		httputil.InternalError(c, "Failed to delete channel", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(serverID)
	}

	c.JSON(http.StatusOK, response.Message("Channel deleted"))
}

func (h *Handler) GetIRCCommands(c *gin.Context) {
	db := h.reqDB(c)
	// Defensive cap (v0.10.217, bundle D3).
	var commands []models.IRCCommand
	if err := db.Gorm().Limit(500).Find(&commands).Error; err != nil {
		httputil.InternalError(c, "Failed to get commands", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(commands))
}

func (h *Handler) CreateIRCCommand(c *gin.Context) {
	db := h.reqDB(c)
	var cmd models.IRCCommand
	if err := c.ShouldBindJSON(&cmd); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if cmd.Command == "" {
		c.JSON(http.StatusBadRequest, response.Error("Command is required"))
		return
	}

	if cmd.CommandType == "" {
		cmd.CommandType = "static"
	}

	// H-11: zero server-owned fields so a client cannot mass-assign them.
	cmd.ID = 0
	cmd.CreatedAt = time.Time{}
	cmd.UpdatedAt = time.Time{}

	if err := db.Gorm().Create(&cmd).Error; err != nil {
		httputil.InternalError(c, "Failed to create command", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, response.Success(cmd))
}

func (h *Handler) UpdateIRCCommand(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid command ID"))
		return
	}

	var cmd models.IRCCommand
	if err := db.Gorm().First(&cmd, id).Error; err != nil {
		c.JSON(http.StatusNotFound, response.Error("Command not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// M-12: allow-list (see UpdateIRCServer).
	updates = httputil.FilterAllowedFields(updates, ircCommandUpdateFields)
	if v, ok := updates["command"].(string); ok && v == "" {
		delete(updates, "command")
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("No valid fields to update"))
		return
	}

	if err := db.Gorm().Model(&cmd).Updates(updates).Error; err != nil {
		httputil.InternalError(c, "Failed to update command", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	db.Gorm().First(&cmd, id)
	c.JSON(http.StatusOK, response.Success(cmd))
}

func (h *Handler) DeleteIRCCommand(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid command ID"))
		return
	}

	if err := db.Gorm().Delete(&models.IRCCommand{}, id).Error; err != nil {
		httputil.InternalError(c, "Failed to delete command", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, response.Message("Command deleted"))
}

func (h *Handler) TestIRCServer(c *gin.Context) {
	var req struct {
		ServerHost   string `json:"server_host" binding:"required"`
		ServerPort   int    `json:"server_port"`
		UseTLS       bool   `json:"use_tls"`
		Nick         string `json:"nick" binding:"required"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		SASLEnabled  bool   `json:"sasl_enabled"`
		SASLUsername string `json:"sasl_username"`
		SASLPassword string `json:"sasl_password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if req.ServerPort == 0 {
		req.ServerPort = 6667
	}
	if req.ServerPort < 1 || req.ServerPort > 65535 {
		c.JSON(http.StatusBadRequest, response.Error("Invalid server port"))
		return
	}

	// AUDIT-013: validate the server host against the SSRF allow-list before
	// dialing. Without this, an admin (or anyone who phished an admin
	// session) can use this endpoint to probe internal services on the
	// monitor's LAN (loopback / RFC 1918 / link-local). Same check that
	// TestProbeConnection (handlers_probes.go:351) and TestEmail
	// (handlers_settings.go:667) have used since v0.10.140.
	if !isValidExternalIP(req.ServerHost) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid or disallowed server host"))
		return
	}

	bot := irc.NewTestBot(req.ServerHost, req.ServerPort, req.Nick, req.Username, req.UseTLS, req.Password, req.SASLEnabled, req.SASLUsername, req.SASLPassword)

	err := bot.Connect()
	if err != nil {
		// L-11: the error can carry text the remote ircd chose (SASL/
		// registration failures) — strip control bytes and cap it before it
		// is echoed to the browser.
		c.JSON(http.StatusOK, response.Success(gin.H{
			"success": false,
			"message": "Failed to connect: " + irc.SanitizeErrorText(err.Error()),
		}))
		return
	}

	bot.Disconnect()

	c.JSON(http.StatusOK, response.Success(gin.H{
		"success": true,
		"message": "Connection successful",
	}))
}

// maxIRCMessageBytes leaves ~110 bytes of the 512-byte IRC line for the
// prefix the server prepends when relaying (nick!user@host + channel name).
const maxIRCMessageBytes = 400

func (h *Handler) SendIRCMessage(c *gin.Context) {
	var req struct {
		ServerID uint   `json:"server_id" binding:"required"`
		Channel  string `json:"channel" binding:"required"`
		Message  string `json:"message" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	// L-15: an IRC line is at most 512 bytes INCLUDING the relayed
	// ":nick!user@host PRIVMSG #chan :" prefix and CRLF, and ircds silently
	// truncate (or reject) anything longer. Reject up front rather than let a
	// message be cut mid-word — or let an oversized body queue on the bot.
	if len(req.Message) > maxIRCMessageBytes {
		c.JSON(http.StatusBadRequest, response.Error("Message too long (max "+strconv.Itoa(maxIRCMessageBytes)+" bytes)"))
		return
	}

	mgr := h.GetIRCManager()
	if mgr == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("IRC manager not available"))
		return
	}

	err := mgr.SendToChannel(req.ServerID, req.Channel, req.Message)
	if err != nil {
		httputil.InternalError(c, "Failed to send message", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Message sent"))
}
