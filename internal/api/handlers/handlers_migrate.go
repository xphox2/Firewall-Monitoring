package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// GetMigrationPrecheck returns whether the server is running on PostgreSQL
// and the default SQLite path from config.
func (h *Handler) GetMigrationPrecheck(c *gin.Context) {
	isPostgres := h.db != nil && h.db.IsPostgres()
	defaultPath := h.config.Database.FilePath
	if defaultPath == "" {
		defaultPath = "/data/firewall-mon.db"
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"is_postgres":         isPostgres,
		"default_sqlite_path": defaultPath,
	}))
}

// StartMigration launches a background SQLite→PostgreSQL data migration.
func (h *Handler) StartMigration(c *gin.Context) {
	if h.db == nil || !h.db.IsPostgres() {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Migration is only available when running with PostgreSQL"))
		return
	}

	snap := h.migrateState.Snapshot()
	if snap.Running {
		c.JSON(http.StatusConflict, models.ErrorResponse("A migration is already running"))
		return
	}

	var req struct {
		SourcePath string `json:"source_path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.SourcePath == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("source_path is required"))
		return
	}

	// Basic path traversal protection
	cleaned := filepath.Clean(req.SourcePath)
	if strings.Contains(cleaned, "..") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid path"))
		return
	}

	// Verify file exists
	if _, err := os.Stat(cleaned); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Source database file not found"))
		return
	}

	go h.db.MigrateFromSQLite(cleaned, h.migrateState)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": "Migration started"}))
}

// GetMigrationStatus returns the current migration progress.
func (h *Handler) GetMigrationStatus(c *gin.Context) {
	c.JSON(http.StatusOK, models.SuccessResponse(h.migrateState.Snapshot()))
}
