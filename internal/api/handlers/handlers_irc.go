package handlers

import (
	"log"
	"net/http"
	"strconv"

	"firewall-mon/internal/irc"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetIRCServer(c *gin.Context) {
	var servers []models.IRCServer
	if err := h.db.Gorm().Preload("Channels").Find(&servers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get IRC servers"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(servers))
}

func (h *Handler) GetIRCServerByID(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := h.db.Gorm().Preload("Channels").First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Server not found"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(server))
}

func (h *Handler) CreateIRCServer(c *gin.Context) {
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

	if err := h.db.Gorm().Create(&server).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create server"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, models.SuccessResponse(server))
}

func (h *Handler) UpdateIRCServer(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := h.db.Gorm().First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Server not found"))
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	delete(updates, "id")
	delete(updates, "created_at")

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

	if err := h.db.Gorm().Model(&server).Updates(updates).Error; err != nil {
		log.Printf("Failed to update IRC server %d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update server: " + err.Error()))
		return
	}

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

	c.JSON(http.StatusOK, models.SuccessResponse(server))
}

func (h *Handler) DeleteIRCServer(c *gin.Context) {
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

	if err := h.db.Gorm().Delete(&models.IRCServer{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete server"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Server deleted"))
}

func (h *Handler) ConnectIRCServer(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid server ID"))
		return
	}

	var server models.IRCServer
	if err := h.db.Gorm().First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Server not found"))
		return
	}

	if !server.Enabled {
		h.db.Gorm().Model(&server).Update("enabled", true)
		server.Enabled = true
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		if err := mgr.RestartBot(uint(id)); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to connect: "+err.Error()))
			return
		}
	}

	c.JSON(http.StatusOK, models.MessageResponse("Connecting to server..."))
}

func (h *Handler) DisconnectIRCServer(c *gin.Context) {
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

	h.db.Gorm().Model(&models.IRCServer{}).Where("id = ?", id).Update("status", "disconnected")

	c.JSON(http.StatusOK, models.MessageResponse("Disconnected"))
}

func (h *Handler) GetIRCChannels(c *gin.Context) {
	serverID := c.Query("server_id")
	var channels []models.IRCChannel

	if serverID != "" {
		if err := h.db.Gorm().Where("server_id = ?", serverID).Find(&channels).Error; err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get channels"))
			return
		}
	} else {
		if err := h.db.Gorm().Find(&channels).Error; err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get channels"))
			return
		}
	}
	c.JSON(http.StatusOK, models.SuccessResponse(channels))
}

func (h *Handler) CreateIRCChannel(c *gin.Context) {
	var channel models.IRCChannel
	if err := c.ShouldBindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if channel.ChannelName == "" || channel.ServerID == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Channel name and server ID are required"))
		return
	}

	if err := h.db.Gorm().Create(&channel).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create channel"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(channel.ServerID)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(channel))
}

func (h *Handler) UpdateIRCChannel(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid channel ID"))
		return
	}

	var channel models.IRCChannel
	if err := h.db.Gorm().First(&channel, id).Error; err != nil {
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

	if err := h.db.Gorm().Model(&channel).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update channel"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(channel.ServerID)
	}

	c.JSON(http.StatusOK, models.SuccessResponse(channel))
}

func (h *Handler) DeleteIRCChannel(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid channel ID"))
		return
	}

	var channel models.IRCChannel
	if err := h.db.Gorm().First(&channel, id).Error; err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Channel not found"))
		return
	}

	serverID := channel.ServerID

	if err := h.db.Gorm().Delete(&channel).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete channel"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.RestartBot(serverID)
	}

	c.JSON(http.StatusOK, models.MessageResponse("Channel deleted"))
}

func (h *Handler) GetIRCCommands(c *gin.Context) {
	var commands []models.IRCCommand
	if err := h.db.Gorm().Find(&commands).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to get commands"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(commands))
}

func (h *Handler) CreateIRCCommand(c *gin.Context) {
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

	if err := h.db.Gorm().Create(&cmd).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create command"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cmd))
}

func (h *Handler) UpdateIRCCommand(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid command ID"))
		return
	}

	var cmd models.IRCCommand
	if err := h.db.Gorm().First(&cmd, id).Error; err != nil {
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

	if err := h.db.Gorm().Model(&cmd).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update command"))
		return
	}

	if mgr := h.GetIRCManager(); mgr != nil {
		mgr.ReloadCommands()
	}

	c.JSON(http.StatusOK, models.SuccessResponse(cmd))
}

func (h *Handler) DeleteIRCCommand(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid command ID"))
		return
	}

	if err := h.db.Gorm().Delete(&models.IRCCommand{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete command"))
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to send message: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Message sent"))
}
