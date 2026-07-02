package notifier

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firewall-mon/internal/config"
)

// TestPostJSON_RedactsWebhookSecret_M14 pins the 2026-07-01 audit M14 fix:
// Slack/Discord webhook URLs carry their auth token in the PATH, so no error
// from postJSON may contain the full URL — only the host. Covers both the
// non-2xx path and the transport-error path (Go's *url.Error stringifies the
// whole URL).
func TestPostJSON_RedactsWebhookSecret_M14(t *testing.T) {
	n := NewNotifier(&config.Config{})
	const secret = "SUPERSECRETTOKEN123"

	// Non-2xx: server returns 500; the secret is in the path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	url := srv.URL + "/services/T000/B000/" + secret
	err := n.postJSON(url, map[string]any{"x": 1})
	if err == nil {
		t.Fatal("expected an error on 500")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("non-2xx error leaked the webhook secret: %q", err.Error())
	}

	// Transport error: point at a closed port so client.Do fails with a
	// *url.Error that would otherwise stringify the full URL (token included).
	badURL := "http://127.0.0.1:1/services/T000/B000/" + secret
	err = n.postJSON(badURL, map[string]any{"x": 1})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("transport error leaked the webhook secret: %q", err.Error())
	}
}
