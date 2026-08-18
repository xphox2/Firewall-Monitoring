package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/database"

	"github.com/gin-gonic/gin"
)

// newHubTestHandler builds a Handler whose Store is a TYPED-NIL *database.Database.
//
// That is deliberate, and it is the whole point of these tests: the interface is
// non-nil so the handler's "is a database configured" guard passes, but the
// underlying pointer is nil, so any actual query would panic. The handler
// therefore cannot pass these tests unless it genuinely serves without touching
// the database.
func newHubTestHandler(t *testing.T) *Handler {
	t.Helper()
	var typedNil *database.Database
	h := &Handler{db: typedNil}
	h.dashHub = newDashboardHealthHub(h)
	return h
}

func doDashboardHealthRequest(t *testing.T, h *Handler) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/dashboard/health", nil)
	h.GetDashboardHealth(c)

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body %q)", err, w.Body.String())
	}
	return w.Code, body
}

// TestDashboardHealth_ServesWithoutComputing is the load-bearing guarantee of
// this endpoint: it answers from whatever the background refresher last
// published and never computes on the request.
//
// Before this, the handler computed lazily on a cache miss. With a 10s TTL and a
// 30s client poll, a single operator missed on every poll and paid the whole
// aggregation — 32.57s measured on production, longer than the 30s write
// timeout, so the browser's connection died and the page sat on
// "Loading system health…" indefinitely.
//
// h.db is nil here, so if this handler ever reaches for the database again the
// test panics rather than quietly regressing.
func TestDashboardHealth_ServesWithoutComputing(t *testing.T) {
	h := newHubTestHandler(t)

	// Publish a snapshot the way the refresher would, aged so age_seconds is
	// distinguishable from zero.
	h.dashHub.mu.Lock()
	h.dashHub.snap = gin.H{"fleet": gin.H{"total": 7}}
	h.dashHub.generatedAt = time.Now().Add(-90 * time.Second)
	h.dashHub.mu.Unlock()

	code, body := doDashboardHealthRequest(t, h)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	data, _ := body["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("no data in response: %#v", body)
	}
	fleet, _ := data["fleet"].(map[string]interface{})
	if fleet == nil || fleet["total"] != float64(7) {
		t.Errorf("snapshot payload not served intact: %#v", data)
	}
	age, ok := data["age_seconds"].(float64)
	if !ok || age < 80 {
		t.Errorf("age_seconds = %v, want ~90 — the UI needs it to report staleness honestly", data["age_seconds"])
	}
}

// TestDashboardHealth_ComputingSentinel pins the shape the browser branches on.
// The frontend must be able to distinguish "no snapshot yet" from real data:
// every module body defaults its missing keys to zero, so rendering this as data
// reports the database unreachable and the fleet empty — a false outage on every
// restart and every idle-wake.
func TestDashboardHealth_ComputingSentinel(t *testing.T) {
	h := newHubTestHandler(t) // hub has no snapshot yet

	code, body := doDashboardHealthRequest(t, h)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a pre-first-compute request is not an error", code)
	}
	data, _ := body["data"].(map[string]interface{})
	if data == nil || data["status"] != "computing" {
		t.Errorf("pre-compute payload = %#v, want {\"status\":\"computing\"} — the frontend branches on this exact value", data)
	}
	// It must not carry anything that could be mistaken for real module data.
	if _, present := data["platform"]; present {
		t.Error("the computing sentinel carries module keys; the UI would render them as a real (and wrong) system state")
	}
}

// TestDashboardHealthHub_RequestWakesRefresher covers the cold-start hole that
// activity gating creates. The refresher idles while nobody is looking, so the
// first visitor after an idle period finds a missing or stale snapshot. That
// visitor must not wait — but the refresher does have to be nudged, or the
// dashboard shows hours-old numbers until the next tick.
func TestDashboardHealthHub_RequestWakesRefresher(t *testing.T) {
	h := &Handler{}
	hub := newDashboardHealthHub(h)

	// No snapshot at all: must signal.
	hub.request()
	select {
	case <-hub.wake:
	default:
		t.Error("a request with no snapshot did not wake the refresher; the first visitor after a restart would wait for a full tick")
	}

	// Fresh snapshot: must NOT signal, or every poll forces a recompute and the
	// background refresher becomes the request-path cost it replaced.
	hub.mu.Lock()
	hub.snap = gin.H{}
	hub.generatedAt = time.Now()
	hub.mu.Unlock()
	hub.request()
	select {
	case <-hub.wake:
		t.Error("a request against a fresh snapshot woke the refresher anyway")
	default:
	}

	// Stale snapshot: must signal again.
	hub.mu.Lock()
	hub.generatedAt = time.Now().Add(-2 * time.Hour)
	hub.mu.Unlock()
	hub.request()
	select {
	case <-hub.wake:
	default:
		t.Error("a request against a stale snapshot did not wake the refresher")
	}
}

// TestDashboardHealthHub_IntervalClamped keeps an operator from turning the
// refresh setting into a self-inflicted outage (or parking it for a day).
func TestDashboardHealthHub_IntervalClamped(t *testing.T) {
	hub := newDashboardHealthHub(&Handler{}) // nil db → default path
	if got := hub.refreshInterval(); got != dashboardHealthRefreshDefault*time.Second {
		t.Errorf("refreshInterval with no store = %v, want the %ds default", got, dashboardHealthRefreshDefault)
	}
	if dashboardHealthRefreshMin >= dashboardHealthRefreshDefault {
		t.Error("the clamp floor must be below the default, or the default is unreachable")
	}
}
