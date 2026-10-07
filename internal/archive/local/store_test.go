package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"firewall-mon/internal/archive/objstore"
	"firewall-mon/internal/archive/objstore/objstoretest"
	"firewall-mon/internal/config"
)

// The local target on a temporary directory. Synthetic data only.

const testPrefix = "fwmon-test/archive"

var ctx = context.Background()

// testCfg is a local target at root/target (created) under root.
func testCfg(t *testing.T) config.ArchiveConfig {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "target")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return config.ArchiveConfig{Target: config.ArchiveTargetLocal, LocalDir: dir, AllowedRoot: root, Prefix: testPrefix}
}

// newStore is a ready (initialised) target.
func newStore(t *testing.T) (*Store, config.ArchiveConfig) {
	t.Helper()
	cfg := testCfg(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	return s, cfg
}

// corrupt flips a byte of a file in place, keeping its length (the owner
// can still change a read-only file: chmod first, as anyone with the share
// could).
func corrupt(t *testing.T, p string) {
	t.Helper()
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xFF
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestConformance runs the targets' shared suite (the S3 client runs it
// against the B2-strict fake).
func TestConformance(t *testing.T) {
	objstoretest.Run(t, func(t *testing.T) objstoretest.Harness {
		s, _ := newStore(t)
		return objstoretest.Harness{
			Store:  s,
			Prefix: testPrefix,
			Corrupt: func(t *testing.T, rel string) {
				v, err := latestVersion(s.file(rel))
				if err != nil || v == 0 {
					t.Fatalf("no version of %s: %v", rel, err)
				}
				corrupt(t, versionFile(s.file(rel), v))
			},
			Versioned: true,
		}
	})
}

func put(t *testing.T, s *Store, rel string, body []byte, meta map[string]string) objstore.PutResult {
	t.Helper()
	r, err := s.Put(ctx, rel, bytes.NewReader(body), int64(len(body)), meta)
	if err != nil {
		t.Fatalf("Put %s: %v", rel, err)
	}
	return r
}

// TestPut_LayoutAndReadOnly: the object lands at <dir>/<prefix>/<rel> (the
// S3 key, as a path), with its sidecar, both read-only, and no temporary
// file left.
func TestPut_LayoutAndReadOnly(t *testing.T) {
	s, cfg := newStore(t)
	body := []byte(`{"kind":"fwmon-archive-chunk"}` + "\n")
	r := put(t, s, "syslog/v2/2026-10/03/chunk.json", body, map[string]string{"fwmon-archive-stream": "syslog"})
	p := filepath.Join(cfg.LocalDir, "fwmon-test", "archive", "syslog", "v2", "2026-10", "03", "chunk.json")
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("%s: %q %v", p, got, err)
	}
	if r.VersionID != "1" || r.Key != testPrefix+"/syslog/v2/2026-10/03/chunk.json" {
		t.Fatalf("PutResult %+v", r)
	}
	for _, f := range []string{p, p + metaSuffix} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != objectMode {
			t.Errorf("%s has mode %v, want %v (read-only)", f, fi.Mode().Perm(), objectMode)
		}
	}
	var sc sidecar
	b, _ := os.ReadFile(p + metaSuffix)
	if err := json.Unmarshal(b, &sc); err != nil || sc.SHA256 != r.SHA256 || sc.MD5 != r.ETag || sc.Version != 1 || sc.Metadata["fwmon-archive-stream"] != "syslog" {
		t.Fatalf("sidecar %s: %+v %v", b, sc, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "chunk.json,chunk.json.fwmeta" {
		t.Fatalf("directory holds %v, want the object and its sidecar only", names)
	}
}

// TestPut_NeverOverwrites: a second write with other bytes keeps the first
// file byte for byte and writes chunk.json.v2; each version verifies by its
// id. Also through the no-hard-link path (SMB): the checked rename refuses
// an existing name.
func TestPut_NeverOverwrites(t *testing.T) {
	for _, noLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "link", true: "rename"}[noLink], func(t *testing.T) {
			if noLink {
				orig := linkFile
				linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }
				t.Cleanup(func() { linkFile = orig })
			}
			s, _ := newStore(t)
			rel := "syslog/v2/2026-10/03/chunk.json"
			a, b := []byte("first manifest\n"), []byte("second manifest, longer\n")
			ra := put(t, s, rel, a, nil)
			rb := put(t, s, rel, b, nil)
			if ra.VersionID != "1" || rb.VersionID != "2" {
				t.Fatalf("versions %q, %q", ra.VersionID, rb.VersionID)
			}
			if got, _ := os.ReadFile(s.file(rel)); !bytes.Equal(got, a) {
				t.Fatalf("the first version was overwritten: %q", got)
			}
			if got, _ := os.ReadFile(s.file(rel) + ".v2"); !bytes.Equal(got, b) {
				t.Fatalf("version 2: %q", got)
			}
			for _, r := range []objstore.PutResult{ra, rb} {
				if err := s.VerifyFull(ctx, r, nil); err != nil {
					t.Fatalf("version %s: %v", r.VersionID, err)
				}
			}
			// The commit itself refuses an existing name.
			tmp := filepath.Join(filepath.Dir(s.file(rel)), ".probe-tmp")
			if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := commitNoReplace(tmp, s.file(rel)); !errors.Is(err, errExists) {
				t.Fatalf("commitNoReplace onto an object = %v, want errExists", err)
			}
			if got, _ := os.ReadFile(s.file(rel)); !bytes.Equal(got, a) {
				t.Fatalf("the commit replaced the object: %q", got)
			}
		})
	}
}

// TestPut_SameBytesReusesTheVersion: a retry with the same bytes and
// metadata returns the stored version (no new file); other metadata, or a
// stored copy whose bytes no longer match its sidecar, gets a new version.
func TestPut_SameBytesReusesTheVersion(t *testing.T) {
	s, _ := newStore(t)
	rel := "flows/v1/2026-10/03/10/sflow.ndjson.gz"
	body := []byte("same bytes")
	meta := map[string]string{"fwmon-archive-schema": "1"}
	r1 := put(t, s, rel, body, meta)
	if r2 := put(t, s, rel, body, meta); r2.VersionID != "1" {
		t.Fatalf("a retry with the same bytes wrote version %s", r2.VersionID)
	}
	if _, err := os.Stat(s.file(rel) + ".v2"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a retry left %s.v2: %v", rel, err)
	}
	if r3 := put(t, s, rel, body, map[string]string{"fwmon-archive-schema": "2"}); r3.VersionID != "2" {
		t.Fatalf("other metadata reused version %s", r3.VersionID)
	}
	corrupt(t, s.file(rel)+".v2")
	if r4 := put(t, s, rel, body, map[string]string{"fwmon-archive-schema": "2"}); r4.VersionID != "3" {
		t.Fatalf("a corrupted stored copy was reused (version %s)", r4.VersionID)
	}
	if err := s.VerifyFull(ctx, r1, nil); err != nil {
		t.Fatal(err)
	}
}

// TestPut_CrashBeforeCommit: a write killed after its temporary file was
// written and fsynced (and its sidecar placed) but before the rename leaves
// no object — Head says not found, nothing has the final name — and the next
// process's write of the key succeeds as version 1, sweeping the leftovers.
// Simulated by copying the temporary file aside under the same pattern (as
// the kill leaves it), then failing the write there.
func TestPut_CrashBeforeCommit(t *testing.T) {
	s, cfg := newStore(t)
	rel := "syslog/v2/2026-10/05/device-7.ndjson.gz"
	body := bytes.Repeat([]byte("row\n"), 4096)
	crash := errors.New("killed before the rename")
	beforeCommit = func(tmp, final string) error {
		b, err := os.ReadFile(tmp)
		if err != nil {
			return err
		}
		left := filepath.Join(filepath.Dir(tmp), "."+filepath.Base(final)+tmpInfix+"crashed")
		if err := os.WriteFile(left, b[:len(b)/2], 0o600); err != nil { // a torn copy, too
			return err
		}
		return crash
	}
	t.Cleanup(func() { beforeCommit = nil })
	if _, err := s.Put(ctx, rel, bytes.NewReader(body), int64(len(body)), nil); !errors.Is(err, crash) {
		t.Fatalf("Put = %v, want the simulated crash", err)
	}
	beforeCommit = nil
	dir := filepath.Dir(s.file(rel))
	if _, err := os.Stat(s.file(rel)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a crashed write left the object's name: %v", err)
	}
	if _, err := os.Stat(s.file(rel) + metaSuffix); err != nil {
		t.Fatalf("the crash should have left the sidecar it wrote first: %v", err)
	}
	if _, err := s.Head(ctx, rel, ""); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("Head after the crash = %v, want ErrNotFound", err)
	}

	s2, err := New(cfg) // the restarted process
	if err != nil {
		t.Fatal(err)
	}
	r := put(t, s2, rel, body, nil)
	if r.VersionID != "1" {
		t.Fatalf("after the crash the write is version %s, want 1", r.VersionID)
	}
	if err := s2.VerifyFull(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	if err := s2.VerifyHead(ctx, r); err != nil {
		t.Fatalf("VerifyHead (the orphaned sidecar must have been replaced): %v", err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), tmpInfix) {
			t.Fatalf("leftover temporary file %s", e.Name())
		}
	}
}

// TestPut_RequiresTheMarker: a directory without the marker — never
// initialised, or the empty mount point of a share that is not mounted — is
// never written, and a missing object there is ErrUninitialized, not
// ErrNotFound (so a verify does not count it as lost).
func TestPut_RequiresTheMarker(t *testing.T) {
	cfg := testCfg(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "syslog/v2/2026-10/03/chunk.json", bytes.NewReader([]byte("x")), 1, nil); !errors.Is(err, objstore.ErrUninitialized) {
		t.Fatalf("Put without the marker = %v", err)
	}
	if ents, _ := os.ReadDir(cfg.LocalDir); len(ents) != 0 {
		t.Fatalf("a write without the marker created %v", ents)
	}
	if err := s.Preflight(ctx); !errors.Is(err, objstore.ErrUninitialized) {
		t.Fatalf("Preflight without the marker = %v", err)
	}
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	r := put(t, s, "syslog/v2/2026-10/03/chunk.json", []byte("x"), nil)
	if err := s.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	// The share goes away: its mount point is an empty directory again.
	if err := os.Rename(cfg.LocalDir, cfg.LocalDir+"-unmounted"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfg.LocalDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Head(ctx, r.Rel, ""); !errors.Is(err, objstore.ErrUninitialized) || errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("Head on the unmounted share = %v, want ErrUninitialized", err)
	}
	if err := s.VerifyFull(ctx, r, nil); errors.Is(err, objstore.ErrMismatch) || !errors.Is(err, objstore.ErrUninitialized) {
		t.Fatalf("VerifyFull on the unmounted share = %v: must not be a mismatch", err)
	}
	if _, err := s.Put(ctx, "syslog/v2/2026-10/04/chunk.json", bytes.NewReader([]byte("y")), 1, nil); !errors.Is(err, objstore.ErrUninitialized) {
		t.Fatalf("Put on the unmounted share = %v", err)
	}
	if ents, _ := os.ReadDir(cfg.LocalDir); len(ents) != 0 {
		t.Fatalf("a write landed on the empty mount point: %v", ents)
	}
}

// TestKey_ReservedNames: the names the package keeps for itself are refused
// as keys.
func TestKey_ReservedNames(t *testing.T) {
	s, _ := newStore(t)
	for _, rel := range []string{"syslog/.hidden", "syslog/chunk.json.v2", "syslog/chunk.json.fwmeta", ".fwmon-archive-target"} {
		if _, err := s.Key(rel); err == nil {
			t.Errorf("Key(%q) accepted a reserved name", rel)
		}
	}
	if _, err := s.Key("syslog/v2/2026-10/03/device-1.ndjson.gz"); err != nil {
		t.Fatal(err)
	}
}

// TestHead_ObjectWithoutSidecar: an object copied in by hand (no sidecar)
// reads, its ETag the MD5 of its bytes.
func TestHead_ObjectWithoutSidecar(t *testing.T) {
	s, _ := newStore(t)
	p := s.file("syslog/v2/2026-10/03/chunk.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("abc"), 0o444); err != nil {
		t.Fatal(err)
	}
	info, err := s.Head(ctx, "syslog/v2/2026-10/03/chunk.json", "")
	if err != nil || info.ETag != "900150983cd24fb0d6963f7d28e17f72" || info.Size != 3 || info.VersionID != "1" {
		t.Fatalf("Head %+v %v", info, err)
	}
}

// TestNew_PathEscapes: a local directory outside the allowed root, with
// '..', relative, on the database volume, or a root of "/" is refused by the
// configuration; a symbolic link that leads out of the root is refused by
// the preflight and Init.
func TestNew_PathEscapes(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	base := config.ArchiveConfig{Target: config.ArchiveTargetLocal, AllowedRoot: root, Prefix: testPrefix}
	for name, mod := range map[string]func(*config.ArchiveConfig){
		"outside":   func(c *config.ArchiveConfig) { c.LocalDir = outside },
		"dotdot":    func(c *config.ArchiveConfig) { c.LocalDir = root + "/../" + filepath.Base(outside) },
		"relative":  func(c *config.ArchiveConfig) { c.LocalDir = "target" },
		"prefix":    func(c *config.ArchiveConfig) { c.LocalDir = root + "x" },
		"slashroot": func(c *config.ArchiveConfig) { c.LocalDir, c.AllowedRoot = "/srv/archive", "/" },
		"lock":      func(c *config.ArchiveConfig) { c.LocalDir, c.ObjectLockDays, c.ObjectLockMode = root, 30, "GOVERNANCE" },
		"noprefix":  func(c *config.ArchiveConfig) { c.LocalDir, c.Prefix = root, "" },
		"badprefix": func(c *config.ArchiveConfig) { c.LocalDir, c.Prefix = root, "../x" },
	} {
		c := base
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: New accepted %+v", name, c)
		}
	}
	origDB := config.ArchiveDatabaseDir
	config.ArchiveDatabaseDir = filepath.Join(root, "db")
	t.Cleanup(func() { config.ArchiveDatabaseDir = origDB })
	c := base
	c.LocalDir = filepath.Join(root, "db", "archive")
	if _, err := New(c); err == nil || !strings.Contains(err.Error(), "database volume") {
		t.Errorf("a directory on the database volume: %v", err)
	}
	c.AllowedRoot = filepath.Join(root, "db")
	if err := c.ValidateAllowedRoot(); err == nil {
		t.Error("a root on the database volume was accepted")
	}
	config.ArchiveDatabaseDir = origDB

	// A link inside the root that leads out of it.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	c = base
	c.LocalDir = link
	s, err := New(c) // the text is under the root: only the filesystem knows
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx); err == nil || !strings.Contains(err.Error(), "outside ARCHIVE_ALLOWED_ROOT") {
		t.Fatalf("Init through a link out of the root = %v", err)
	}
	if err := s.Preflight(ctx); err == nil || !strings.Contains(err.Error(), "outside ARCHIVE_ALLOWED_ROOT") {
		t.Fatalf("Preflight through a link out of the root = %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("something was written outside the root: %v", ents)
	}
	// A link that stays inside the root is fine.
	in := filepath.Join(root, "real")
	if err := os.Mkdir(in, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(in, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveUnderRoot(root, filepath.Join(root, "alias")); err != nil {
		t.Fatalf("a link inside the root: %v", err)
	}
	if _, err := ResolveUnderRoot(root, filepath.Join(root, "missing")); err == nil || !strings.Contains(err.Error(), "mounted") {
		t.Fatalf("a missing directory: %v", err)
	}
}

// TestHint: permission, stale-handle and unreachable-share errors say what
// to do (uid/gid mapping, remount).
func TestHint(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{&fs.PathError{Op: "open", Path: "/archive/x", Err: syscall.EACCES}, "uid 100, gid 101"},
		{&fs.PathError{Op: "open", Path: "/archive/x", Err: syscall.EPERM}, "anonuid=100"},
		{&fs.PathError{Op: "stat", Path: "/archive/x", Err: syscall.ESTALE}, "stale file handle"},
		{&fs.PathError{Op: "stat", Path: "/archive/x", Err: syscall.ENOTCONN}, "unreachable"},
		{&fs.PathError{Op: "write", Path: "/archive/x", Err: syscall.ENOSPC}, "no space"},
		{&fs.PathError{Op: "write", Path: "/archive/x", Err: syscall.EROFS}, "read-only"},
	} {
		if got := describe("op", "/archive/x", c.err); !strings.Contains(got.Error(), c.want) || !errors.Is(got, c.err.(*fs.PathError).Err) {
			t.Errorf("%v: %q, want it to mention %q and keep the errno", c.err, got, c.want)
		}
	}
}

// TestVerifyFull_SidecarETag: like the S3 GET's ETag, a sidecar whose MD5
// is not the recorded ETag fails the read-back even when the bytes hash
// right (the object's metadata was changed behind the archive's back).
func TestVerifyFull_SidecarETag(t *testing.T) {
	s, _ := newStore(t)
	r := put(t, s, "syslog/v2/2026-10/03/chunk.json", []byte("manifest\n"), nil)
	mp := s.file(r.Rel) + metaSuffix
	b, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mp, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, bytes.Replace(b, []byte(r.ETag), []byte(strings.Repeat("0", 32)), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyFull(ctx, r, nil); !errors.Is(err, objstore.ErrMismatch) || !strings.Contains(err.Error(), "ETag") {
		t.Fatalf("VerifyFull with a changed sidecar = %v", err)
	}
}
