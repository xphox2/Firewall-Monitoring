package report

import (
	"strings"
	"testing"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// TestBuildDailyWeeklyReturnAttachments (AUDIT-291): BuildDailyReport /
// BuildWeeklyReport render the email variant, which embeds cid: chart images.
// They MUST return the PNG attachments alongside the html so the send path can
// attach them — previously the wrappers discarded them, leaving every cid:
// image broken. A fleet with alerts + drawable devices guarantees at least the
// alert-timeline attachment.
func TestBuildDailyWeeklyReturnAttachments(t *testing.T) {
	t.Parallel()
	devices, dd := makeFleet(6) // device 1 has 5 critical alerts + CPU/Mem history

	check := func(t *testing.T, html string, atts []notifier.Attachment, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if len(atts) == 0 {
			t.Fatal("no attachments returned — cid: chart images would be broken")
		}
		for _, a := range atts {
			if len(a.Data) == 0 {
				t.Errorf("attachment %s has no data", a.ContentID)
			}
			if !strings.Contains(html, "cid:"+a.ContentID) {
				t.Errorf("attachment %s has no matching cid: anchor in html", a.ContentID)
			}
		}
	}

	run := func(name string, fn func([]models.Device, []*DeviceReportData, string) (string, string, []notifier.Attachment, error)) {
		t.Run(name, func(t *testing.T) {
			_, html, atts, err := fn(devices, dd, "UTC")
			check(t, html, atts, err)
		})
	}
	run("daily", BuildDailyReport)
	run("weekly", BuildWeeklyReport)
}
