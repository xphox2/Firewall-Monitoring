package shell

import (
	"os"
	"strings"
	"testing"
)

// TestBackoffJitter_CallSites_AUDIT088 pins that the retry/reconnect
// backoffs the audit named now go through the jitter() helper, and that the
// old deterministic `time.Sleep(time.Duration(retries+1) * time.Second)`
// form (which makes every probe retry in lock-step) is gone from relay.go.
// The jitter math itself is unit-tested in internal/relay; this is the
// cheap static guard against a future edit reintroducing the un-jittered
// sleep at the call sites.
func TestBackoffJitter_CallSites_AUDIT088(t *testing.T) {
	cases := []struct {
		path        string
		mustContain string
		mustNot     string
		why         string
	}{
		// The bundled probe's relay client (and its jittered sendBatch) was
		// removed with cmd/probe; the production probe is the Firewall-Collector
		// repo, which has its own AUDIT-088 guard. Only the in-repo IRC backoff
		// remains to pin here.
		{
			path:        "../irc/bot.go",
			mustContain: "jitter(1 * time.Second)",
			mustNot:     "time.Sleep(1 * time.Second)",
			why:         "irc bot restart/reconnect must use a jittered delay (AUDIT-088).",
		},
	}
	for _, c := range cases {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Errorf("cannot read %s: %v", c.path, err)
			continue
		}
		body := string(data)
		if !strings.Contains(body, c.mustContain) {
			t.Errorf("%s is missing %q: %s", c.path, c.mustContain, c.why)
		}
		if strings.Contains(body, c.mustNot) {
			t.Errorf("%s still contains the un-jittered backoff %q: %s", c.path, c.mustNot, c.why)
		}
	}
}
