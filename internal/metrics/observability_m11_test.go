package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestObservabilityHandler_M11 covers the daemon observability mux added for the
// 2026-06-23 audit M11 (poller/trap-receiver were black boxes): /metrics serves
// Prometheus output, /healthz is always live, and /readyz reflects the probe.
func TestObservabilityHandler_M11(t *testing.T) {
	// readiness toggles via this flag.
	rdy := true
	h := ObservabilityHandler(func() bool { return rdy })

	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}

	// /metrics → 200 with Prometheus runtime collectors.
	if w := get("/metrics"); w.Code != http.StatusOK {
		t.Errorf("/metrics = %d, want 200", w.Code)
	} else if !strings.Contains(w.Body.String(), "go_goroutines") {
		t.Error("/metrics missing go_goroutines (runtime collectors not registered)")
	}

	// /healthz → always 200.
	if w := get("/healthz"); w.Code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", w.Code)
	}

	// /readyz → 200 when ready.
	if w := get("/readyz"); w.Code != http.StatusOK {
		t.Errorf("/readyz (ready) = %d, want 200", w.Code)
	}

	// /readyz → 503 when not ready.
	rdy = false
	if w := get("/readyz"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz (not ready) = %d, want 503", w.Code)
	}
}

// TestObservabilityHandler_NilReady_AlwaysReady covers the idling trap-receiver
// path (nil readiness probe ⇒ /readyz is always 200).
func TestObservabilityHandler_NilReady_AlwaysReady(t *testing.T) {
	h := ObservabilityHandler(nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("/readyz with nil probe = %d, want 200", w.Code)
	}
}
