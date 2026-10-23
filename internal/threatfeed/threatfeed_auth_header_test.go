package threatfeed

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFetch_StripsAuthHeaderOnNonHTTPS pins D-21: an auth header (a bearer
// credential) must never be sent to a non-HTTPS feed.
func TestFetch_StripsAuthHeaderOnNonHTTPS(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "1.2.3.4\n")
	}))
	defer srv.Close()

	feed := Feed{Name: "x", URL: srv.URL, Category: "custom", Severity: "warning", Kind: FeedKindIP}
	if _, err := Fetch(context.Background(), srv.Client(), feed, "Authorization: Bearer secret"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotHeader != "" {
		t.Errorf("auth header was sent to a non-HTTPS feed: %q", gotHeader)
	}
}
