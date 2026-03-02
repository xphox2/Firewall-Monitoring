package httputil

import (
	"net/http"
	"strconv"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// ParsePagination extracts limit and offset from query parameters.
// Default limit is 100, max is 500. Default offset is 0.
func ParsePagination(c *gin.Context) (limit, offset int) {
	limit = 100
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}
	offset = 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return
}

// ParseID extracts a uint ID from the "id" URL parameter.
// Returns (id, true) on success, or writes a 400 error and returns (0, false).
func ParseID(c *gin.Context) (uint, bool) {
	id := c.Param("id")
	idUint, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid ID format"))
		return 0, false
	}
	return uint(idUint), true
}

// ParseHours extracts hours from the "hours" query parameter.
// Default is 24, max is 168.
func ParseHours(c *gin.Context) int {
	hours := 24
	if hq := c.Query("hours"); hq != "" {
		if parsed, err := strconv.Atoi(hq); err == nil && parsed > 0 && parsed <= 168 {
			hours = parsed
		}
	}
	return hours
}

// RequireDB checks that db is non-nil. If nil, writes a 503 error and returns false.
func RequireDB(c *gin.Context, db *database.Database) bool {
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Database not available"))
		return false
	}
	return true
}

// FilterAllowedFields returns a copy of updates containing only keys present in allowed.
func FilterAllowedFields(updates map[string]interface{}, allowed map[string]bool) map[string]interface{} {
	filtered := make(map[string]interface{})
	for key, value := range updates {
		if allowed[key] {
			filtered[key] = value
		}
	}
	return filtered
}
