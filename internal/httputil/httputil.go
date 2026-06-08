package httputil

import (
	"log/slog"
	"net/http"
	"strconv"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// InternalError writes the standard HTTP 500 response (models.ErrorResponse(msg))
// and — unlike the bare `c.JSON(500, models.ErrorResponse(...))` it replaces —
// LOGS the underlying err with operation context, so a 500 leaves an
// operator-visible trail instead of vanishing (AUDIT-071). The audit found 134
// handler sites that returned a 500 without logging the cause, so production
// failures were invisible in the server log.
//
// The client still sees only msg; err (which may carry internal detail — SQL
// text, file paths) is never written to the response body, so this is safe to
// pass a raw db/driver error. err may be nil for 500s that have no underlying
// Go error, in which case only msg is logged.
//
// The record carries status=500 plus the request method, matched route, and the
// X-Request-ID set by the RequestID middleware (AUDIT-135) when present, so a
// logged 500 correlates with the access-log line for the same request.
//
// AUDIT-076: emitted as a native slog.Error record (was log.Printf) — the
// operation msg becomes the record message and the rest are queryable
// attributes (status=500, method, route, req, err) instead of a flat string.
func InternalError(c *gin.Context, msg string, err error) {
	attrs := []slog.Attr{
		slog.Int("status", http.StatusInternalServerError),
		slog.String("method", c.Request.Method),
		slog.String("route", c.FullPath()),
	}
	if reqID := c.Writer.Header().Get("X-Request-ID"); reqID != "" {
		attrs = append(attrs, slog.String("req", reqID))
	}
	if err != nil {
		attrs = append(attrs, slog.Any("err", err))
	}
	slog.LogAttrs(c.Request.Context(), slog.LevelError, msg, attrs...)
	c.JSON(http.StatusInternalServerError, models.ErrorResponse(msg))
}

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
// Default is 24, max is 8760 (1 year).
func ParseHours(c *gin.Context) int {
	hours := 24
	if hq := c.Query("hours"); hq != "" {
		if parsed, err := strconv.Atoi(hq); err == nil && parsed > 0 && parsed <= 8760 {
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
