package local

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"firewall-mon/internal/archive/objstore"
)

// Review fixes of 0.11.315: unmount during a write, the base never created by
// a write, symbolic links inside the archive, uncached read-back on a network
// share, the three commit paths, sidecar read errors, durability of a reused
// copy, the volume checks of the preflight, and the install id.

// TestPut_UnmountDuringWrite: the share goes away (its device changes, or
// its marker disappears) between the start of a Put and its commit: the Put
// fails, so the chunk is not verified against files that are not on it.
func TestPut_UnmountDuringWrite(t *testing.T) {
	for name, gone := range map[string]func(t *testing.T, s *Store){
		"device changed": func(t *testing.T, s *Store) {
			orig := deviceOf
			deviceOf = func(string) (uint64, error) { return 42, nil }
			t.Cleanup(func() { deviceOf = orig })
		},
		"marker gone": func(t *testing.T, s *Store) {
			mp := filepath.Join(s.base, MarkerName)
			if err := os.Chmod(mp, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(mp); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := newStore(t)
			beforeCommit = func(string, string) error { gone(t, s); return nil }
			t.Cleanup(func() { beforeCommit = nil })
			_, err := s.Put(ctx, "syslog/v2/2026-10/03/device-1.ndjson.gz", bytes.NewReader([]byte("rows\n")), 5, nil)
			if err == nil || !strings.Contains(err.Error(), "during the write") {
				t.Fatalf("Put across an unmount = %v, want a failure", err)
			}
		})
	}
}

// TestDirs_NeverCreatesTheBase: a write creates the directories below the
// base, never the base itself (a missing base is a volume that is not there).
func TestDirs_NeverCreatesTheBase(t *testing.T) {
	s, _ := newStore(t)
	if err := os.Rename(s.base, s.base+"-away"); err != nil {
		t.Fatal(err)
	}
	if err := s.dirs(filepath.Join(s.base, "syslog", "v2"), true); err == nil {
		t.Fatal("dirs created a tree under a missing base")
	}
	if _, err := os.Stat(s.base); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the base was created: %v", err)
	}
}

// TestSymlinksInsideTheArchive: a directory or an object replaced by a
// symbolic link (to somewhere else) is neither written through nor read
// through.
func TestSymlinksInsideTheArchive(t *testing.T) {
	s, _ := newStore(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(s.base, "syslog")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "syslog/v2/2026-10/03/chunk.json", bytes.NewReader([]byte("x")), 1, nil); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Put through a linked directory = %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("a write went through the link: %v", ents)
	}

	body := []byte("the object\n")
	r := put(t, s, "sflow/v1/2026-10/03/10/sflow.ndjson.gz", body, nil)
	p := s.file(r.Rel)
	copyOut := filepath.Join(outside, "copy")
	if err := os.WriteFile(copyOut, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(copyOut, p); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyFull(ctx, r, nil); err == nil {
		t.Fatal("VerifyFull read an object through a symbolic link")
	}
}

// TestReadBack_UncachedOnNetworkShare: on a network filesystem every
// read-back (VerifyFull, GetBytes, the reuse hash) opens the file uncached;
// on a local one it does not.
func TestReadBack_UncachedOnNetworkShare(t *testing.T) {
	for _, typ := range []string{"nfs", "ext4"} {
		t.Run(typ, func(t *testing.T) {
			s, _ := newStore(t)
			StatFS = func(string) (FSInfo, error) { return FSInfo{Type: typ, Device: 1}, nil }
			orig := openUncached
			calls := 0
			openUncached = func(p string) (*os.File, bool, error) { calls++; return orig(p) }
			t.Cleanup(func() { openUncached = orig })
			body := bytes.Repeat([]byte("0123456789"), 300000) // 3 MB: several direct-I/O buffers
			r := put(t, s, "syslog/v2/2026-10/03/device-1.ndjson.gz", body, nil)
			var got bytes.Buffer
			if err := s.VerifyFull(ctx, r, &got); err != nil || !bytes.Equal(got.Bytes(), body) {
				t.Fatalf("VerifyFull: %v (%d bytes)", err, got.Len())
			}
			if b, _, err := s.GetBytes(ctx, r.Rel, r.VersionID, 1<<23); err != nil || !bytes.Equal(b, body) {
				t.Fatalf("GetBytes: %v", err)
			}
			if typ == "nfs" && calls < 2 || typ == "ext4" && calls != 0 {
				t.Fatalf("%s: %d uncached opens", typ, calls)
			}
		})
	}
}

// TestDirectReader: the aligned reader returns exactly the file's bytes,
// across buffer boundaries and at a size that is not a block multiple.
func TestDirectReader(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	body := payloadBytes(directBuf*2 + 123)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	f, direct, err := openUncachedSys(p)
	if err != nil {
		t.Fatal(err)
	}
	var r io.ReadCloser = f
	if direct {
		r = newDirectReader(f)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("read %d of %d bytes: %v", len(got), len(body), err)
	}
	f2, _ := os.Open(p)
	got, err = io.ReadAll(newDirectReader(f2)) // the buffering logic on any descriptor
	f2.Close()
	if err != nil || sha256.Sum256(got) != sha256.Sum256(body) {
		t.Fatalf("directReader: %d bytes, %v", len(got), err)
	}
}

func payloadBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/4096)
	}
	return b
}

// TestCommitNoReplace_Paths: each commit path refuses an existing name and
// says which it took: the hard link, RENAME_NOREPLACE where links are
// refused, the checked (non-atomic) rename where neither works.
func TestCommitNoReplace_Paths(t *testing.T) {
	noLink := func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }
	noRename := func(string, string) error { return errNoReplaceUnsupported }
	for _, c := range []struct {
		name         string
		link, rename func(string, string) error
		want         string
	}{
		{"link", nil, nil, commitLink},
		{"renameat2", noLink, nil, commitRenameNoRepl},
		{"checked", noLink, noRename, commitCheckedRename},
	} {
		t.Run(c.name, func(t *testing.T) {
			ol, or := linkFile, renameNoReplace
			t.Cleanup(func() { linkFile, renameNoReplace = ol, or })
			if c.link != nil {
				linkFile = c.link
			}
			if c.rename != nil {
				renameNoReplace = c.rename
			}
			dir := t.TempDir()
			final := filepath.Join(dir, "obj")
			mk := func(body string) string {
				p := filepath.Join(dir, ".obj.tmp-"+body)
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			how, err := commitNoReplace(mk("first"), final)
			if err != nil {
				t.Fatal(err)
			}
			if how != c.want && !(c.name == "renameat2" && how == commitCheckedRename && renameNoReplaceSys("x", "y") == errNoReplaceUnsupported) {
				t.Fatalf("committed by %q, want %q", how, c.want)
			}
			if _, err := commitNoReplace(mk("second"), final); !errors.Is(err, errExists) {
				t.Fatalf("a second commit = %v, want errExists", err)
			}
			if b, _ := os.ReadFile(final); string(b) != "first" {
				t.Fatalf("the object was replaced: %q", b)
			}
		})
	}
	// The probe says when the commit is not atomic.
	ol, or := linkFile, renameNoReplace
	linkFile, renameNoReplace = noLink, noRename
	t.Cleanup(func() { linkFile, renameNoReplace = ol, or })
	stubVolume(t)
	root := t.TempDir()
	r := Probe(ctx, root, root, 0)
	if c := checkNamed(r, "no-replace"); c == nil || !c.Warn || !strings.Contains(c.Detail, "not atomic") {
		t.Fatalf("probe on a filesystem without an atomic commit: %+v", r.Checks)
	}
}

// TestSidecarReadErrors: a sidecar that exists but cannot be parsed is an
// error for Head and VerifyFull, never a guess from the bytes.
func TestSidecarReadErrors(t *testing.T) {
	s, _ := newStore(t)
	r := put(t, s, "syslog/v2/2026-10/03/chunk.json", []byte("manifest\n"), nil)
	mp := s.file(r.Rel) + metaSuffix
	if err := os.Chmod(mp, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Head(ctx, r.Rel, ""); err == nil {
		t.Fatal("Head guessed past an unreadable sidecar")
	}
	if err := s.VerifyFull(ctx, r, nil); err == nil {
		t.Fatal("VerifyFull passed with an unreadable sidecar")
	}
}

// TestPut_ReuseIsMadeDurable: a retry that reuses the stored copy fsyncs its
// directories first (the copy may be the one a crash left before its
// directory fsync).
func TestPut_ReuseIsMadeDurable(t *testing.T) {
	s, _ := newStore(t)
	rel := "syslog/v2/2026-10/03/device-1.ndjson.gz"
	put(t, s, rel, []byte("same"), nil)
	orig := syncDir
	var synced []string
	syncDir = func(d string) (bool, error) { synced = append(synced, d); return orig(d) }
	t.Cleanup(func() { syncDir = orig })
	if r := put(t, s, rel, []byte("same"), nil); r.VersionID != "1" {
		t.Fatalf("version %s", r.VersionID)
	}
	if len(synced) == 0 || synced[0] != filepath.Dir(s.file(rel)) {
		t.Fatalf("the reused copy's directories were not fsynced: %v", synced)
	}
}

// TestPreflight_VolumeChecks: the worker's preflight and Init (whatever set
// the configuration) refuse the container's overlay or tmpfs, and a
// directory with no mount point between it and the allowed root; a mount
// point above the directory is enough.
func TestPreflight_VolumeChecks(t *testing.T) {
	cfg := testCfg(t)
	s := openStore(t, cfg)
	StatFS = func(string) (FSInfo, error) { return FSInfo{Type: "overlay", Device: 1}, nil }
	if err := s.Init(ctx); err == nil || !strings.Contains(err.Error(), "overlay") {
		t.Fatalf("Init on overlay = %v", err)
	}
	StatFS = func(string) (FSInfo, error) { return FSInfo{Type: "tmpfs", Device: 1}, nil }
	if err := s.Preflight(ctx); err == nil || !strings.Contains(err.Error(), "tmpfs") {
		t.Fatalf("Preflight on tmpfs = %v", err)
	}
	StatFS = func(string) (FSInfo, error) { return FSInfo{Type: "ext4", Device: 1}, nil }
	IsMountPoint = func(string) (bool, error) { return false, nil }
	if err := s.Init(ctx); err == nil || !strings.Contains(err.Error(), "mount point") {
		t.Fatalf("Init with no mount point = %v", err)
	}
	if _, err := os.Stat(cfg.LocalBase()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a refused Init created the directory")
	}
	IsMountPoint = func(d string) (bool, error) { return d == cfg.AllowedRoot, nil }
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init under a mounted root: %v", err)
	}
	if err := s.Preflight(ctx); err != nil {
		t.Fatalf("Preflight under a mounted root: %v", err)
	}
}

// TestMarker_InstallID: Init writes this install's id; another install's
// marker is refused by the preflight, Init and every write; a reader without
// an id (--verify-month) still reads.
func TestMarker_InstallID(t *testing.T) {
	s, cfg := newStore(t)
	var m marker
	b, _ := os.ReadFile(filepath.Join(s.base, MarkerName))
	if err := json.Unmarshal(b, &m); err != nil || m.InstallID != testInstallID {
		t.Fatalf("marker %s: %v", b, err)
	}
	r := put(t, s, "syslog/v2/2026-10/03/chunk.json", []byte("x"), nil)

	other := openStore(t, cfg)
	other.SetInstallID("fedcba9876543210fedcba9876543210")
	for name, err := range map[string]error{
		"Preflight": other.Preflight(ctx),
		"Init":      other.Init(ctx),
	} {
		if !errors.Is(err, ErrForeignMarker) {
			t.Errorf("%s by another install = %v", name, err)
		}
	}
	if _, err := other.Put(ctx, "syslog/v2/2026-10/04/chunk.json", bytes.NewReader([]byte("y")), 1, nil); !errors.Is(err, ErrForeignMarker) {
		t.Fatalf("Put by another install = %v", err)
	}
	reader := openStore(t, cfg)
	if err := reader.VerifyFull(ctx, r, nil); err != nil {
		t.Fatalf("a reader without an install id: %v", err)
	}
	if !errors.Is(other.Preflight(ctx), ErrForeignMarker) || errors.Is(other.Preflight(ctx), objstore.ErrUninitialized) {
		t.Fatal("a foreign marker must not look uninitialised (the worker would initialise over it)")
	}
}
