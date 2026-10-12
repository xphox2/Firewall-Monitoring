package handlers

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// TestGetSyslogMessage_TsParam covers the raw-syslog deep-link behind PR 8's
// event detail view. The syslog PK is (id, timestamp) on partitioned installs,
// so the event detail link passes raw_ts as ?ts=<RFC3339> to let the lookup
// prune to one partition. This test pins the three outcomes: id-only (best
// effort) and (id, ts) both resolve; a wrong ts misses (404); a malformed ts is
// a 400, never a 500.
func TestGetSyslogMessage_TsParam(t *testing.T) {
	h, db := setupTestHandler(t)
	ts := time.Date(2026, 10, 1, 10, 5, 0, 0, time.UTC)
	msg := &models.SyslogMessage{Timestamp: ts, Severity: 5, Message: "raw line"}
	if err := db.Gorm().Create(msg).Error; err != nil {
		t.Fatalf("seed syslog: %v", err)
	}

	// By id alone — the pre-existing best-effort path.
	c, rec := jsonReq(http.MethodGet, "/x", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(msg.ID))}}
	h.GetSyslogMessage(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("id-only = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// By (id, ts) — the partition-pruning form the event detail link uses.
	c, rec = jsonReq(http.MethodGet, "/x?ts="+ts.Format(time.RFC3339Nano), "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(msg.ID))}}
	h.GetSyslogMessage(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("(id, ts) = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// A wrong ts must miss (404), not silently return the row by id alone.
	c, rec = jsonReq(http.MethodGet, "/x?ts="+ts.Add(time.Hour).Format(time.RFC3339Nano), "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(msg.ID))}}
	h.GetSyslogMessage(c)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("wrong ts = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}

	// A malformed ts is a 400 — never a 500 from a bogus timestamp parse.
	c, rec = jsonReq(http.MethodGet, "/x?ts=not-a-time", "")
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(msg.ID))}}
	h.GetSyslogMessage(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed ts = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
