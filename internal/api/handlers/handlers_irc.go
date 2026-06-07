package handlers

import (
	"log"
	"net/http"
	"strconv"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/irc"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	// Defensive cap (v0.10.217, bundle D3). IRC config rarely exceeds
	// a handful of servers; 200 leaves headroom for accidental dupes.
	var servers []models.IRCServer
	if err := db.Gorm().Preload("Channels").Limit(200).Find(&servers).Error; err != nil {
		httputil.InternalError(c, "Failed to get IRC servers", err)
		return
	}
	for i := range servers {
		db.DecryptIRCServerSecrets(&servers[i])
		for j := range servers[i].Channels {
			db.DecryptIRCChannelSecrets(&servers[i].Channels[j])
		}
	}
	c.JSON(http.StatusOK, models.SuccessResponse(servers))
}

func (h *Handler) GetIRCServerByID(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := db.Gorm().Preload("Channels").First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Server not found"))
		return
	}
	db.DecryptIRCServerSecrets(&server)
	for i := range server.Channels {
		db.DecryptIRCChannelSecrets(&server.Channels[i])
	}
	c.JSON(http.StatusOK, models.SuccessResponse(server))
}

func (h *Handler) CreateIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	var server models.IRCServer
	if err := c.ShouldBindJSON(&server); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if server.Nick == "" || server.ServerHost == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Nick and server host are required"))
		return
	}

	if server.ServerPort == 0 {
		server.ServerPort = 6667
	}

	db.EncryptIRCServerSecrets(&server)

	if err := db.Gorm().Create(&server).Error; err != nil {
		httputil.InternalError(c, "Failed to create server", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	// Decrypt before returning so client sees plaintext, not ciphertext
	db.DecryptIRCServerSecrets(&server)
	c.JSON(http.StatusOK, models.SuccessResponse(server))
}

func (h *Handler) UpdateIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := db.Gorm().First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Server not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	// Remove fields that should not be updated
	skipFields := []string{"id", "created_at", "updated_at", "status", "last_connected", "last_error"}
	for _, f := range skipFields {
		delete(updates, f)
	}

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

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No valid fields to update"))
		return
	}

	// Encrypt password fields before saving
	for _, field := range []string{"server_password", "nickserv_password", "sasl_password"} {
		if v, ok := updates[field].(string); ok && v != "" {
			updates[field] = db.EncryptField(v)
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

	// Decrypt before returning so client sees plaintext, not ciphertext
	db.DecryptIRCServerSecrets(&server)
	for i := range server.Channels {
		db.DecryptIRCChannelSecrets(&server.Channels[i])
	}
	c.JSON(http.StatusOK, models.SuccessResponse(server))
}

func (h *Handler) DeleteIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
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

	c.JSON(http.StatusOK, models.MessageResponse("Server deleted"))
}

func (h *Handler) ConnectIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := db.Gorm().First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Server not found"))
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

	c.JSON(http.StatusOK, models.MessageResponse("Connecting to server..."))
}

func (h *Handler) DisconnectIRCServer(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		if bot := mgr.GetBot(uint(id)); bot != nil {
			bot.Stop()
		}
	}

	db.Gorm().Model(&models.IRCServer{}).Where("id = ?", id).Update("status", "disconnected")

	c.JSON(http.StatusOK, models.MessageResponse("Disconnected"))
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
		db.DecryptIRCChannelSecrets(&channels[i])
	}
	c.JSON(http.StatusOK, models.SuccessResponse(channels))
}

func (h *Handler) CreateIRCChannel(c *gin.Context) {
	db := h.reqDB(c)
	var channel models.IRCChannel
	if err := c.ShouldBindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if channel.ChannelName == "" || channel.ServerID == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Channel name and server ID are required"))
		return
	}

	db.EncryptIRCChannelSecrets(&channel)

	if err := db.Gorm().Create(&channel).Error; err != nil {
		httputil.InternalError(c, "Failed to create channel", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(channel.ServerID)
	}

	db.DecryptIRCChannelSecrets(&channel)
	c.JSON(http.StatusOK, models.SuccessResponse(channel))
}

func (h *Handler) UpdateIRCChannel(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid channel ID"))
		return
	}

	var channel models.IRCChannel
	if err := db.Gorm().First(&channel, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Channel not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	delete(updates, "id")
	delete(updates, "created_at")

	// Encrypt password fields before saving
	for _, field := range []string{"chanserv_password", "chan_oper_pass", "channel_key"} {
		if v, ok := updates[field].(string); ok && v != "" {
			updates[field] = db.EncryptField(v)
		}
	}

	if err := db.Gorm().Model(&channel).Updates(updates).Error; err != nil {
		httputil.InternalError(c, "Failed to update channel", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(channel.ServerID)
	}

	// Re-fetch and decrypt for response
	db.Gorm().First(&channel, id)
	db.DecryptIRCChannelSecrets(&channel)
	c.JSON(http.StatusOK, models.SuccessResponse(channel))
}

func (h *Handler) DeleteIRCChannel(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid channel ID"))
		return
	}

	var channel models.IRCChannel
	if err := db.Gorm().First(&channel, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Channel not found"))
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

	c.JSON(http.StatusOK, models.MessageResponse("Channel deleted"))
}

func (h *Handler) GetIRCCommands(c *gin.Context) {
	db := h.reqDB(c)
	// Defensive cap (v0.10.217, bundle D3).
	var commands []models.IRCCommand
	if err := db.Gorm().Limit(500).Find(&commands).Error; err != nil {
		httputil.InternalError(c, "Failed to get commands", err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(commands))
}

func (h *Handler) CreateIRCCommand(c *gin.Context) {
	db := h.reqDB(c)
	var cmd models.IRCCommand
	if err := c.ShouldBindJSON(&cmd); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if cmd.Command == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Command is required"))
		return
	}

	if cmd.CommandType == "" {
		cmd.CommandType = "static"
	}

	if err := db.Gorm().Create(&cmd).Error; err != nil {
		httputil.InternalError(c, "Failed to create command", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cmd))
}

func (h *Handler) UpdateIRCCommand(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid command ID"))
		return
	}

	var cmd models.IRCCommand
	if err := db.Gorm().First(&cmd, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Command not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	delete(updates, "id")
	delete(updates, "created_at")

	if err := db.Gorm().Model(&cmd).Updates(updates).Error; err != nil {
		httputil.InternalError(c, "Failed to update command", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cmd))
}

func (h *Handler) DeleteIRCCommand(c *gin.Context) {
	db := h.reqDB(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid command ID"))
		return
	}

	if err := db.Gorm().Delete(&models.IRCCommand{}, id).Error; err != nil {
		httputil.InternalError(c, "Failed to delete command", err)
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, models.MessageResponse("Command deleted"))
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if req.ServerPort == 0 {
		req.ServerPort = 6667
	}
	if req.ServerPort < 1 || req.ServerPort > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server port"))
		return
	}

	// AUDIT-013: validate the server host against the SSRF allow-list before
	// dialing. Without this, an admin (or anyone who phished an admin
	// session) can use this endpoint to probe internal services on the
	// monitor's LAN (loopback / RFC 1918 / link-local). Same check that
	// TestProbeConnection (handlers_probes.go:351) and TestEmail
	// (handlers_settings.go:667) have used since v0.10.140.
	if !isValidExternalIP(req.ServerHost) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid or disallowed server host"))
		return
	}

	bot := irc.NewTestBot(req.ServerHost, req.ServerPort, req.Nick, req.Username, req.UseTLS, req.Password, req.SASLEnabled, req.SASLUsername, req.SASLPassword)

	err := bot.Connect()
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"success": false,
			"message": "Failed to connect: " + err.Error(),
		}))
		return
	}

	bot.Disconnect()

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"success": true,
		"message": "Connection successful",
	}))
}

func (h *Handler) SendIRCMessage(c *gin.Context) {
	var req struct {
		ServerID uint   `json:"server_id" binding:"required"`
		Channel  string `json:"channel" binding:"required"`
		Message  string `json:"message" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	mgr := h.GetIRCManager()
	if mgr == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("IRC manager not available"))
		return
	}

	err := mgr.SendToChannel(req.ServerID, req.Channel, req.Message)
	if err != nil {
		httputil.InternalError(c, "Failed to send message", err)
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Message sent"))
}
