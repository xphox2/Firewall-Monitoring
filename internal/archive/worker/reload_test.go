package worker

import (
	"context"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/database"
)

// TestReloader_HotReload (A-10): the poller's archive worker follows the
// admin page's settings without a restart. The environment leaves both
// streams off: ticks make no request. An admin switches syslog on: the next
// tick builds the worker, passes the preflight and archives. The prefix
// changes: the next tick rebuilds it (a new preflight under the new prefix).
// Switched off: no further request. A setting the configuration refuses:
// no worker, and the reason recorded for the status page.
func TestReloader_HotReload(t *testing.T) {
	ctx := context.Background()
	srv := s3test.NewB2Strict(t, testBucket)
	env := testConfig(srv, t.TempDir())
	env.SyslogEnabled, env.FlowsEnabled = false, false
	env.SealGraceHours, env.SealReverify = 48, "head" // as Load defaults them; the reloader runs Validate
	db := database.NewDatabaseForTesting(t)
	db.SetEncryptionKeyForTesting("reload-test-key")
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	seedSyslog(t, db, time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC), time.Date(2026, 9, 2, 1, 0, 0, 0, time.UTC))

	r := NewReloader(db, env, s3.WithRootCAs(pool), s3.WithMaxAttempts(1))
	save := func(set map[string]string, revert ...string) {
		t.Helper()
		if err := db.SaveArchiveSettings(ctx, set, revert, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	listsUnder := func(prefix string) int {
		n := 0
		for _, q := range srv.Requests() {
			if q.Op == s3test.OpListObjects && strings.Contains(q.Query, "prefix="+url.QueryEscape(prefix+"/")) {
				n++
			}
		}
		return n
	}

	r.Tick(ctx)
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("both streams off: %d requests", n)
	}

	save(map[string]string{"ARCHIVE_SYSLOG_ENABLED": "true"})
	r.Tick(ctx)
	var chunks []string
	if err := db.Gorm().Table("archive_chunks").Where("table_name = ?", export.TableSyslog).Pluck("status", &chunks).Error; err != nil {
		t.Fatal(err)
	}
	if listsUnder(testPrefix) != 1 || len(chunks) == 0 {
		t.Fatalf("after switching syslog on: %d preflights, chunks %v", listsUnder(testPrefix), chunks)
	}

	r.Tick(ctx) // unchanged: the same worker, no second preflight
	if n := listsUnder(testPrefix); n != 1 {
		t.Fatalf("an unchanged configuration rebuilt the worker (%d preflights)", n)
	}

	save(map[string]string{"ARCHIVE_S3_PREFIX": "fwmon-test/moved"})
	r.Tick(ctx)
	if n := listsUnder("fwmon-test/moved"); n != 1 {
		t.Fatalf("after the prefix changed: %d preflights under it, want 1", n)
	}

	save(map[string]string{"ARCHIVE_SYSLOG_ENABLED": "false"})
	before := len(srv.Requests())
	r.Tick(ctx)
	r.Tick(ctx)
	if n := len(srv.Requests()); n != before {
		t.Fatalf("switched off: %d more requests", n-before)
	}

	save(map[string]string{"ARCHIVE_SYSLOG_ENABLED": "true", "ARCHIVE_MIN_AGE_HOURS": "0"})
	r.Tick(ctx)
	if n := len(srv.Requests()); n != before {
		t.Fatalf("a refused configuration ran the worker: %d requests", n-before)
	}
	raw, ok, err := db.ArchiveWorkerState(ctx)
	if err != nil || !ok {
		t.Fatalf("worker state: %v %v", ok, err)
	}
	rt, err := status.ParseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := rt.Stages["config"]; !ok || !strings.Contains(e.Error, "ARCHIVE_MIN_AGE_HOURS") {
		t.Fatalf("config problem not recorded: %+v", rt.Stages)
	}
	if strings.Contains(raw, "not-a-real-secret-archive-test-fixture") {
		t.Fatal("the worker state carries the secret")
	}
}
