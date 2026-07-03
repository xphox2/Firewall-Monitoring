package notifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSignWebhookPayload_Golden pins the F18 signature format so receiver
// implementations written against the docs never break silently:
// sig = "sha256=" + hex(HMAC-SHA256(secret, ts + "." + body)).
func TestSignWebhookPayload_Golden(t *testing.T) {
	body := []byte(`{"type":"test"}`)
	got := SignWebhookPayload(body, "topsecret", "1719990000")

	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write([]byte("1719990000." + `{"type":"test"}`))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestPostJSONSigned_HeadersOnWire: with a secret the request carries both F18
// headers and the signature verifies against the received body+timestamp;
// without a secret neither header is present.
func TestPostJSONSigned_HeadersOnWire(t *testing.T) {
	type seen struct {
		ts, sig string
		body    []byte
	}
	var last seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		last = seen{r.Header.Get("X-FirewallMon-Timestamp"), r.Header.Get("X-FirewallMon-Signature"), buf}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// NewNotifier's SSRF guard (correctly) refuses loopback, and httptest
	// servers are loopback — inject a plain client for the wire test.
	n := &Notifier{client: srv.Client()}
	payload := map[string]string{"hello": "world"}

	// Signed.
	if err := n.PostJSONSigned(srv.URL, payload, "s3cret"); err != nil {
		t.Fatalf("PostJSONSigned: %v", err)
	}
	if last.ts == "" || last.sig == "" {
		t.Fatalf("signed request missing headers: ts=%q sig=%q", last.ts, last.sig)
	}
	if want := SignWebhookPayload(last.body, "s3cret", last.ts); last.sig != want {
		t.Errorf("wire signature doesn't verify: got %s want %s", last.sig, want)
	}
	var roundtrip map[string]string
	if err := json.Unmarshal(last.body, &roundtrip); err != nil || roundtrip["hello"] != "world" {
		t.Errorf("body mangled: %s (err=%v)", last.body, err)
	}

	// Unsigned when no secret.
	if err := n.PostJSONSigned(srv.URL, payload, ""); err != nil {
		t.Fatalf("PostJSONSigned unsigned: %v", err)
	}
	if last.ts != "" || last.sig != "" {
		t.Errorf("unsigned request must carry no F18 headers: ts=%q sig=%q", last.ts, last.sig)
	}
}
