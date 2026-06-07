package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// clientErrorReport is the payload a browser sends to /api/client-error when an
// uncaught JS error or unhandled promise rejection fires (AUDIT-129).
type clientErrorReport struct {
	Message string `json:"message"`
	Source  string `json:"source"`
	Line    int    `json:"line"`
	Col     int    `json:"col"`
	Stack   string `json:"stack"`
	URL     string `json:"url"`
}

// truncateField bounds an attacker- or bug-controlled string before it reaches
// the log, so a runaway error can't flood the log with one giant line.
func truncateField(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…(truncated)"
	}
	return s
}

// ReportClientError ingests a browser-side JS error and writes it to the server
// log (AUDIT-129). Before this, a frontend failure only flashed a 5-second
// toast and then vanished — the operator had no visibility into client errors
// happening in production. There is no DB write (kept cheap and unbounded-growth
// free) and no auth (so the public dashboard can report too); the route lives
// under the rate-limited /api group, and every field is truncated here as a
// second line of defence regardless of what the client sent.
//
// It's a best-effort beacon: a malformed body is a 400, but anything with a
// usable message is logged and acked with 204. The log line carries the
// request's X-Request-ID (AUDIT-135) and client IP so a reported client error
// can be correlated with the corresponding server-side request.
func (h *Handler) ReportClientError(c *gin.Context) {
	var r clientErrorReport
	if err := c.ShouldBindJSON(&r); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(r.Message) == "" {
		// Nothing actionable — drop quietly rather than log an empty line.
		c.Status(http.StatusNoContent)
		return
	}

	reqID := c.Writer.Header().Get("X-Request-ID")
	stack := truncateField(r.Stack, 2000)
	stackSuffix := ""
	if stack != "" {
		stackSuffix = "\n  stack: " + stack
	}
	log.Printf("client-error [req=%s ip=%s ua=%q] %s @ %s:%d:%d url=%s%s",
		reqID, c.ClientIP(), truncateField(c.Request.UserAgent(), 200),
		truncateField(r.Message, 500), truncateField(r.Source, 300), r.Line, r.Col,
		truncateField(r.URL, 300), stackSuffix)

	c.Status(http.StatusNoContent)
}
