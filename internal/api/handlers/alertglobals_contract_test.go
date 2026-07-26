package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The alerting page's "save global defaults" posts EVERY field in its
// GLOBAL_FIELDS map unconditionally, using whatever the input currently holds.
// So a key that the save path validates but the read path never returns renders
// as an empty input, posts "", and is rejected — and because UpdateSettings
// returns on the first bad value before persisting anything, THE ENTIRE BATCH
// IS ABANDONED.
//
// That shipped in v0.11.178 with syslog_critical_below_severity: every save
// 400'd, the field could never be cleared, and it blocked the server_disk_*
// knobs that ride the same batch. This pins the contract so the next key added
// to the alerting page cannot repeat it.
func TestAlertGlobals_EveryPostedFieldIsAlsoReturned(t *testing.T) {
	js, err := os.ReadFile("../../../cmd/api/static/js/admin-alerting.js")
	if err != nil {
		js, err = os.ReadFile("../../../../cmd/api/static/js/admin-alerting.js")
	}
	if err != nil {
		t.Skipf("cannot locate admin-alerting.js: %v", err)
	}
	handler, err := os.ReadFile("handlers_alert_policies.go")
	if err != nil {
		t.Fatalf("read handler: %v", err)
	}

	// Keys the page pushes on save: pushNum('<key>', ...)
	pushRe := regexp.MustCompile(`pushNum\(\s*'([a-z0-9_]+)'`)
	var pushed []string
	for _, m := range pushRe.FindAllStringSubmatch(string(js), -1) {
		pushed = append(pushed, m[1])
	}
	if len(pushed) == 0 {
		t.Fatal("found no pushNum() keys — the parser broke, not the code")
	}

	src := string(handler)
	var missing []string
	for _, key := range pushed {
		// Must appear in alertGlobalDefaults: both the defaults map and the
		// key IN ? list live in that function.
		if !strings.Contains(src, `"`+key+`"`) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("alerting page posts %v on save, but alertGlobalDefaults never returns them — "+
			"the inputs render empty, the save posts \"\", validation rejects it, and "+
			"UpdateSettings abandons the WHOLE batch including every other alert default", missing)
	}
}
