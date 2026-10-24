package local

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// D-10: a directory of the archive swapped for a symbolic link AFTER dirs()
// checked it must not lead any operation out of the archive. The pre-fix
// code re-walked the path on every call, so the swap took effect.

// swapForLink moves dir aside and puts a link to outside in its place, the
// way someone who can write the share would between two calls.
func swapForLink(t *testing.T, dir, outside string) {
	t.Helper()
	if err := os.Rename(dir, dir+"-real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
}

// TestPut_DirectorySwappedMidWrite: the object's directory becomes a link to
// a directory outside the archive just before the commit, with the temporary
// file staged there under the same name. The commit must not create the
// object (or chmod anything) outside, and the Put must fail.
func TestPut_DirectorySwappedMidWrite(t *testing.T) {
	s, _ := newStore(t)
	outside := t.TempDir()
	rel := "syslog/v2/2026-10/03/device-1.ndjson.gz"
	body := []byte("rows\n")
	var staged string
	beforeCommit = func(tmp, final string) error {
		dir := filepath.Dir(final)
		b, err := os.ReadFile(tmp)
		if err != nil {
			return err
		}
		staged = filepath.Join(outside, filepath.Base(tmp))
		if err := os.WriteFile(staged, b, 0o600); err != nil {
			return err
		}
		swapForLink(t, dir, outside)
		return nil
	}
	t.Cleanup(func() { beforeCommit = nil })

	if _, err := s.Put(ctx, rel, bytes.NewReader(body), int64(len(body)), nil); err == nil {
		t.Fatal("Put committed through a directory swapped for a link")
	}
	if _, err := os.Lstat(filepath.Join(outside, filepath.Base(s.file(rel)))); err == nil {
		t.Fatal("the object was created outside the archive")
	}
	if fi, err := os.Stat(staged); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("a file outside the archive was touched: %v %v", fi, err)
	}
}

// TestRoot_NothingEscapes drives the primitives every read and write uses
// through a directory link that points out of the archive: the sweep removes
// nothing outside, a leaf open, a stat and a sidecar read find nothing, a
// temporary file is not created there.
func TestRoot_NothingEscapes(t *testing.T) {
	s, _ := newStore(t)
	r := put(t, s, "syslog/v2/2026-10/03/chunk.json", []byte("x\n"), nil)
	dir := filepath.Dir(s.file(r.Rel))

	outside := t.TempDir()
	victim := filepath.Join(outside, ".chunk.json"+tmpInfix+"keep")
	if err := os.WriteFile(victim, []byte("not the archive's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "chunk.json"), []byte("forged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	swapForLink(t, dir, outside)

	f := testFS(t, s.dir)
	sweepTemps(f, dir, "chunk.json")
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the sweep removed a file outside the archive: %v", err)
	}
	if _, err := f.openLeaf(filepath.Join(dir, "chunk.json"), os.O_RDONLY, 0); err == nil {
		t.Fatal("a read opened a file outside the archive")
	}
	if _, err := f.Lstat(filepath.Join(dir, "chunk.json")); err == nil {
		t.Fatal("a stat reached a file outside the archive")
	}
	if _, err := readSidecar(f, filepath.Join(dir, "chunk.json")); err == nil {
		t.Fatal("a sidecar was read outside the archive")
	}
	if _, _, _, err := writeTemp(ctx, f, dir, "chunk.json", bytes.NewReader([]byte("y")), 1); err == nil {
		t.Fatal("a temporary file was created outside the archive")
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 2 {
		t.Fatalf("the directory outside the archive changed: %v", ents)
	}
	if _, _, err := s.GetBytes(ctx, r.Rel, r.VersionID, 1<<20); err == nil {
		t.Fatal("GetBytes read through the link")
	}
}

// TestHead_ObjectLinkNotFollowed: an object replaced by a link to another
// file inside the archive is not reported (the pre-fix Head stat'ed through
// it and returned the target's size).
func TestHead_ObjectLinkNotFollowed(t *testing.T) {
	s, _ := newStore(t)
	a := put(t, s, "syslog/v2/2026-10/03/a.json", []byte("aaaa\n"), nil)
	b := put(t, s, "syslog/v2/2026-10/03/b.json", []byte("b\n"), nil)
	pb := s.file(b.Rel)
	if err := os.Chmod(pb, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pb); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(s.file(a.Rel)), pb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Head(ctx, b.Rel, ""); err == nil {
		t.Fatal("Head followed an object link")
	}
	if err := s.VerifyFull(ctx, b, nil); err == nil {
		t.Fatal("VerifyFull followed an object link")
	}
}
