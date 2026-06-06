// Package audit records privileged admin mutations to a tamper-resistant,
// append-only trail (AUDIT-078). Before this, the server logged authentication
// attempts (login_attempts) but kept no record of who reset uptime, changed an
// alert threshold, deleted a device, approved a probe, or snoozed an alert.
package audit

import (
	"log"
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// auditedMethods are the mutating HTTP verbs worth a record. GETs are read-only
// and far too high-volume to audit.
var auditedMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodDelete: true,
	http.MethodPatch:  true,
}

// Middleware records every authenticated admin mutation. Register it on the
// /admin group AFTER the auth + CSRF middleware, so:
//   - it only fires for requests that already passed authentication and CSRF
//     (i.e. genuine admin actions, not rejected/forged ones), and
//   - the actor (username/user_id) the auth middleware set is on the context.
//
// It records AFTER the handler runs (post-c.Next), so the row captures the final
// HTTP status — including failed (5xx) and forbidden (4xx) attempts, which are
// exactly the ones an operator investigating an incident wants to see. A failed
// audit write is logged but never blocks the request.
func Middleware(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if db == nil || !auditedMethods[c.Request.Method] {
			return
		}

		actor, _ := c.Get("username")
		actorStr, _ := actor.(string)
		var actorID uint
		if v, ok := c.Get("user_id"); ok {
			actorID, _ = v.(uint)
		}

		// target = the route's concrete path params (e.g. id=5;revId=9), which
		// names *what* the action operated on. Action stores the route template
		// so it stays low-cardinality and filterable.
		var parts []string
		for _, p := range c.Params {
			parts = append(parts, p.Key+"="+p.Value)
		}
		route := c.FullPath()
		if route == "" {
			route = c.Request.URL.Path
		}

		entry := &models.AuditLog{
			CreatedAt: time.Now(),
			Actor:     actorStr,
			ActorID:   actorID,
			Method:    c.Request.Method,
			Action:    route,
			Target:    strings.Join(parts, ";"),
			Status:    c.Writer.Status(),
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		}
		if err := db.SaveAuditLog(entry); err != nil {
			log.Printf("audit log: failed to record %s %s by %q: %v",
				entry.Method, entry.Action, entry.Actor, err)
		}
	}
}
