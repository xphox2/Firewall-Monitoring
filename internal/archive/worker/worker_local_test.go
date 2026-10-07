package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/archive/local"
	"firewall-mon/internal/archive/status"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The worker, the seal, VerifyMonth and the restore against a LOCAL target
// (ARCHIVE_TARGET=local): a directory under a temporary allowed root, read
// back from the filesystem directly. The same code paths as against the S3
// fake; only the target differs. Synthetic data only.

// newLocalHarness is newHarness with a local target at <root>/archive.
func newLocalHarness(t *testing.T, start time.Time, mod func(*config.ArchiveConfig)) *harness {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "archive")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := config.ArchiveConfig{
		SyslogEnabled: true, FlowsEnabled: true, Target: config.ArchiveTargetLocal, LocalDir: dir, AllowedRoot: root,
		Prefix: testPrefix, MinAgeHours: 2, SyslogRateRowsPerSec: 100000, FlowRateRowsPerSec: 100000,
		SealGraceHours: 48, SealReverify: config.SealReverifyHead, StagingDir: t.TempDir(),
	}
	if mod != nil {
		mod(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the local test configuration does not validate: %v", err)
	}
	stubLocalVolume(t, root)
	st, err := local.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: database.NewDatabaseForTesting(t), cfg: cfg, store: st, clk: &clock{t: start}}
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	h.w = h.restart()
	return h
}

// stubLocalVolume makes root an ext4 mount point (a temporary directory is
// neither a mount point nor, on some CI runners, off tmpfs).
func stubLocalVolume(t *testing.T, root string) {
	t.Helper()
	origFS, origMount := local.StatFS, local.IsMountPoint
	local.StatFS = func(string) (local.FSInfo, error) {
		return local.FSInfo{Type: "ext4", Device: 1, FreeBytes: 1 << 40, TotalBytes: 1 << 41}, nil
	}
	local.IsMountPoint = func(d string) (bool, error) { return d == root, nil }
	t.Cleanup(func() { local.StatFS, local.IsMountPoint = origFS, origMount })
}

// file is the path of an object key of the local target.
func (h *harness) file(key string) string {
	return filepath.Join(h.cfg.LocalDir, filepath.FromSlash(key))
}

// localLines gunzips a local object and decodes its NDJSON lines.
func (h *harness) localLines(key string) []map[string]any {
	h.t.Helper()
	b, err := os.ReadFile(h.file(key))
	if err != nil {
		h.t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	var out []map[string]any
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// files lists every regular file under the local target (relative paths).
func (h *harness) files() []string {
	h.t.Helper()
	var out []string
	err := filepath.WalkDir(h.cfg.LocalDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(h.cfg.LocalDir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

// TestWorker_LocalTarget_EndToEnd: on a local target the worker initialises
// the directory (its marker) on the first pass, then exports, writes, reads
// back, counts and verifies the due days exactly as against S3: the objects
// and chunk.json at <dir>/<prefix>/syslog/v2/<month>/<day>/, version 1,
// read-only; a later tick writes nothing.
func TestWorker_LocalTarget_EndToEnd(t *testing.T) {
	h := newLocalHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	ids := seedSyslog(t, h.db, day(10, 3, 1, 0), day(10, 3, 2, 0), day(10, 4, 12, 0), day(10, 5, 9, 0))
	h.tick(ctx)

	cs := h.chunks(export.TableSyslog)
	if len(cs) != 2 {
		t.Fatalf("%d chunks, want 2 (3 and 4 Oct)", len(cs))
	}
	var got []int64
	for _, c := range cs {
		if c.Status != models.ArchiveChunkVerified {
			t.Fatalf("chunk %d: %s %s", c.Seq, c.Status, c.Error)
		}
		for _, o := range h.objects(c.ID) {
			if o.Status != models.ArchiveObjectVerified || o.VersionID != "1" || o.ETag == "" || o.LockUntil != nil {
				t.Fatalf("object %+v", o)
			}
			fi, err := os.Stat(h.file(o.ObjectKey))
			if err != nil || fi.Size() != o.ObjectBytes || fi.Mode().Perm()&0o222 != 0 {
				t.Fatalf("%s on disk: %v %v", o.ObjectKey, fi, err)
			}
			for _, l := range h.localLines(o.ObjectKey) {
				got = append(got, int64(l["id"].(float64)))
			}
		}
		folder := export.FolderRel(export.StreamSyslog, export.SyslogSchemaV2, c.PeriodStart, false)
		b, err := os.ReadFile(h.file(testPrefix + "/" + folder + "/" + export.ChunkManifestName))
		if err != nil {
			t.Fatal(err)
		}
		var m chunkManifest
		if err := json.Unmarshal(b, &m); err != nil || m.Seq != c.Seq || m.Rows != c.RowCount {
			t.Fatalf("chunk.json %+v %v", m, err)
		}
	}
	if !reflect.DeepEqual(got, ids[:3]) {
		t.Fatalf("the directory holds ids %v, want %v", got, ids[:3])
	}
	if _, err := os.Stat(filepath.Join(h.cfg.LocalBase(), local.MarkerName)); err != nil {
		t.Fatalf("the first pass did not write the marker: %v", err)
	}
	before := h.files()
	h.tick(ctx)
	if after := h.files(); !reflect.DeepEqual(before, after) {
		t.Fatalf("a second tick wrote files: %v -> %v", before, after)
	}
}

// TestWorker_LocalTarget_ShareGoneWaits: once the archive holds chunks, a
// target directory without its marker — the empty mount point of a share
// that is not mounted — is never initialised again nor written. The running
// worker's writes fail (an upload failure, not a mismatch); a new worker's
// preflight fails, recorded for the status. No chunk advances, the retention
// gate's verified-through id stays, and the mount point stays empty. When
// the share is back the same worker catches up.
func TestWorker_LocalTarget_ShareGoneWaits(t *testing.T) {
	h := newLocalHarness(t, day(10, 5, 11, 50), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	seedSyslog(t, h.db, day(10, 3, 1, 0), day(10, 4, 1, 0))
	h.tick(ctx)
	if n := len(h.chunks(export.TableSyslog)); n != 2 {
		t.Fatalf("%d chunks before the outage", n)
	}
	vBefore, err := h.db.ArchiveTableProgress(ctx, export.TableSyslog)
	if err != nil {
		t.Fatal(err)
	}

	// The share is unmounted; the container sees its empty mount point.
	dir := h.cfg.LocalDir
	if err := os.Rename(dir, dir+"-share"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	seedSyslog(t, h.db, day(10, 5, 1, 0))
	h.clk.add(24 * time.Hour)
	h.tick(ctx) // the running worker (its preflight passed before the outage)
	cs := h.chunks(export.TableSyslog)
	if len(cs) != 3 || cs[2].Status == models.ArchiveChunkVerified || cs[2].Mismatches != 0 || !strings.Contains(cs[2].Error, local.MarkerName) {
		t.Fatalf("the chunk cut during the outage: %+v", cs[len(cs)-1])
	}
	h.restart() // a new worker (a settings save, a poller restart) runs the preflight again
	h.clk.add(time.Hour)
	h.tick(ctx)
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the worker wrote onto the empty mount point: %v", ents)
	}
	if c := h.chunks(export.TableSyslog)[2]; c.Status == models.ArchiveChunkVerified || c.Mismatches != 0 {
		t.Fatalf("chunk 3 during the outage: %+v", c)
	}
	vDuring, _ := h.db.ArchiveTableProgress(ctx, export.TableSyslog)
	if vDuring.VerifiedThroughID != vBefore.VerifiedThroughID {
		t.Fatalf("verified-through moved from %d to %d without the share", vBefore.VerifiedThroughID, vDuring.VerifiedThroughID)
	}
	raw, _, err := h.db.ArchiveWorkerState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := status.ParseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pf, ok := rt.Stages["preflight"]; rt.PreflightOK || !ok || !strings.Contains(pf.Error, "the archive holds chunks") || !strings.Contains(pf.Error, local.MarkerName) {
		t.Fatalf("runtime state during the outage: %+v", rt)
	}

	// The share is back: the same worker passes its preflight on the next
	// tick and verifies the waiting chunk.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir+"-share", dir); err != nil {
		t.Fatal(err)
	}
	h.clk.add(3 * time.Hour) // past the chunk's retry backoff
	h.tick(ctx)
	cs = h.chunks(export.TableSyslog)
	if len(cs) != 3 || cs[2].Status != models.ArchiveChunkVerified {
		t.Fatalf("after the share came back: %d chunks, last %+v", len(cs), cs[len(cs)-1])
	}
}

// TestSeal_LocalTarget_VerifyMonth: on a local target September is sealed
// (partial) once its grace has passed, its _MONTH.json written once and
// read-only, and --verify-month passes from the directory alone; an object
// changed on disk afterwards is reported.
func TestSeal_LocalTarget_VerifyMonth(t *testing.T) {
	h := newLocalHarness(t, day(10, 2, 22, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	syslogMonths(t, h)
	h.tickAt(day(10, 3, 0, 0))
	sep := h.month(export.StreamSyslog, "2026-09")
	if sep == nil || sep.Status != models.ArchiveMonthSealed || !sep.Partial || sep.ChunkCount != 26 ||
		sep.ManifestKey != testPrefix+"/syslog/v1/2026-09/_MONTH.json" {
		t.Fatalf("September: %+v", sep)
	}
	fi, err := os.Stat(h.file(sep.ManifestKey))
	if err != nil || fi.Mode().Perm()&0o222 != 0 {
		t.Fatalf("_MONTH.json on disk: %v %v", fi, err)
	}
	rep, err := VerifyMonth(ctx, h.store.(MonthReader), export.StreamSyslog, "2026-09", nil)
	if err != nil || !rep.OK() || !rep.Partial || rep.Rows != 52 || rep.Chunks != 26 {
		t.Fatalf("verify-month September: %+v %v", rep, err)
	}
	before := h.files()
	h.tickAt(day(10, 3, 0, 10))
	if after := h.files(); !reflect.DeepEqual(before, after) {
		t.Fatal("a pass after the seal wrote into the directory")
	}

	// Someone changes an archived object on the share.
	objs := h.objects(h.chunks(export.TableSyslog)[3].ID)
	p := h.file(objs[0].ObjectKey)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0xFF
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err = VerifyMonth(ctx, h.store.(MonthReader), export.StreamSyslog, "2026-09", nil)
	if err != nil || rep.OK() || !strings.Contains(strings.Join(rep.Problems, "\n"), "sha256") {
		t.Fatalf("verify-month after a change on disk: %+v %v", rep, err)
	}
}

// TestRestore_LocalTarget: a restore reads the archived day from the local
// target, verifies each object and stages exactly that day's rows; an object
// changed on disk is refused.
func TestRestore_LocalTarget(t *testing.T) {
	h := newLocalHarness(t, day(10, 3, 3, 0), func(c *config.ArchiveConfig) { c.FlowsEnabled = false })
	orig, late := restoreFixture(t, h)
	job := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 30, 0, 0), To: day(9, 30, 0, 0)})
	h.newRestore().Tick(ctx)
	j := h.restoreJob(job.ID)
	if j.Status != models.ArchiveRestoreDone || j.ObjectsDone != 3 || j.RowsLoaded != 3 || j.Error != "" {
		t.Fatalf("job: %+v", j)
	}
	got := stagedSyslog(t, h.db, job.StagingTable)
	for id, m := range orig {
		if m.Timestamp.Format(time.DateOnly) != "2026-09-30" {
			continue
		}
		g, ok := got[id]
		if !ok || g.Message != m.Message || g.DeviceID != m.DeviceID {
			t.Fatalf("row %d staged as %+v", id, g)
		}
	}
	if _, ok := got[late]; !ok || len(got) != 3 {
		t.Fatalf("staged %d rows (late row %v)", len(got), ok)
	}

	// A changed object is refused.
	objs, _ := h.db.ArchiveRestoreObjects(ctx, job.ID)
	p := h.file(objs[0].ObjectKey)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0xFF
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	job2 := h.queueRestore(database.ArchiveRestoreRequest{Stream: export.StreamSyslog, From: day(9, 30, 0, 0), To: day(9, 30, 0, 0)})
	h.newRestore().Tick(ctx)
	if j := h.restoreJob(job2.ID); j.Status != models.ArchiveRestoreFailed || !strings.Contains(j.Error, "REFUSED") {
		t.Fatalf("restore of a changed object: %+v", j)
	}
}

// TestWorker_LocalTarget_EnvOnlyVolumeChecks: configured from the
// environment alone (no admin page, no Test), the worker built by New still
// refuses a local directory on the container's overlay or tmpfs, or with no
// mount point between it and the allowed root: its preflight fails, recorded
// for the status, and nothing is written.
func TestWorker_LocalTarget_EnvOnlyVolumeChecks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "archive")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"ARCHIVE_SYSLOG_ENABLED": "true", "ARCHIVE_TARGET": "local", "ARCHIVE_LOCAL_DIR": dir, "ARCHIVE_ALLOWED_ROOT": root,
		"ARCHIVE_S3_PREFIX": testPrefix, "ARCHIVE_STAGING_DIR": t.TempDir(),
	} {
		t.Setenv(k, v)
	}
	cfg := config.Load().Archive
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	orig := stagingFree
	stagingFree = func(context.Context, string) (uint64, error) { return 1 << 40, nil }
	t.Cleanup(func() { stagingFree = orig })
	db := database.NewDatabaseForTesting(t)
	seedSyslog(t, db, day(10, 3, 1, 0))
	origFS, origMount := local.StatFS, local.IsMountPoint
	t.Cleanup(func() { local.StatFS, local.IsMountPoint = origFS, origMount })
	for _, c := range []struct {
		fs      string
		mounted bool
		want    string
	}{
		{"overlay", true, "overlay"},
		{"tmpfs", true, "tmpfs"},
		{"ext4", false, "mount point"},
	} {
		local.StatFS = func(string) (local.FSInfo, error) { return local.FSInfo{Type: c.fs, Device: 1}, nil }
		local.IsMountPoint = func(string) (bool, error) { return c.mounted, nil }
		w, err := New(db, cfg)
		if err != nil {
			t.Fatal(err)
		}
		w.now = func() time.Time { return day(10, 5, 12, 0) }
		w.Tick(ctx)
		raw, _, err := db.ArchiveWorkerState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rt, err := status.ParseRuntime(raw)
		if err != nil {
			t.Fatal(err)
		}
		if pf, ok := rt.Stages["preflight"]; rt.PreflightOK || !ok || !strings.Contains(pf.Error, c.want) {
			t.Fatalf("%s mounted=%v: runtime %+v", c.fs, c.mounted, rt)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Fatalf("%s mounted=%v: the worker wrote %v", c.fs, c.mounted, ents)
		}
	}
}
