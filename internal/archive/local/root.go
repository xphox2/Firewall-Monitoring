package local

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// D-10: every file operation of the target goes through an os.Root opened on
// ARCHIVE_LOCAL_DIR (the mount point the operator configured). dirs() checks
// each directory below it with Lstat, but a path-based call made afterwards
// walks the path again, so a directory swapped for a symbolic link in between
// (by anyone who can write the share) could lead a read, a write, a remove or
// a chmod out of the archive. An os.Root resolves every name with openat
// below its directory and refuses any that escapes it, links included, at
// the moment of the call. The prefix directory is inside the share, so it is
// resolved through the root too. Leaf opens additionally never follow a link
// (openLeaf): os.Root follows one that stays inside the root, and the
// archive's rule is that an object is never read through a link at all.

// fsys is an os.Root plus the path it was opened on. Its methods take the
// absolute paths the package works with and refuse one that is not at or
// below top.
type fsys struct {
	root *os.Root
	top  string
}

// openFS opens dir as the root of every following operation.
func openFS(dir string) (*fsys, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &fsys{root: r, top: filepath.Clean(dir)}, nil
}

func (f *fsys) Close() error { return f.root.Close() }

// rel is p relative to the root ("." for the root itself).
func (f *fsys) rel(p string) (string, error) {
	r, err := filepath.Rel(f.top, filepath.Clean(p))
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", fmt.Errorf("archive local: %s is not below %s", p, f.top)
	}
	return r, nil
}

func (f *fsys) Lstat(p string) (fs.FileInfo, error) {
	r, err := f.rel(p)
	if err != nil {
		return nil, err
	}
	return f.root.Lstat(r)
}

// Stat follows a link only while it stays inside the root.
func (f *fsys) Stat(p string) (fs.FileInfo, error) {
	r, err := f.rel(p)
	if err != nil {
		return nil, err
	}
	return f.root.Stat(r)
}

func (f *fsys) Remove(p string) error {
	r, err := f.rel(p)
	if err != nil {
		return err
	}
	return f.root.Remove(r)
}

func (f *fsys) Chmod(p string, mode fs.FileMode) error {
	r, err := f.rel(p)
	if err != nil {
		return err
	}
	return f.root.Chmod(r, mode)
}

func (f *fsys) Mkdir(p string, mode fs.FileMode) error {
	r, err := f.rel(p)
	if err != nil {
		return err
	}
	return f.root.Mkdir(r, mode)
}

func (f *fsys) MkdirAll(p string, mode fs.FileMode) error {
	r, err := f.rel(p)
	if err != nil {
		return err
	}
	return f.root.MkdirAll(r, mode)
}

func (f *fsys) Link(oldp, newp string) error {
	o, err := f.rel(oldp)
	if err != nil {
		return err
	}
	n, err := f.rel(newp)
	if err != nil {
		return err
	}
	return f.root.Link(o, n)
}

func (f *fsys) Rename(oldp, newp string) error {
	o, err := f.rel(oldp)
	if err != nil {
		return err
	}
	n, err := f.rel(newp)
	if err != nil {
		return err
	}
	return f.root.Rename(o, n)
}

// OpenDir opens directory p (inside the root) for its descriptor: listing it,
// fsyncing it, or as the dirfd of a leaf operation.
func (f *fsys) OpenDir(p string) (*os.File, error) {
	r, err := f.rel(p)
	if err != nil {
		return nil, err
	}
	return f.root.Open(r)
}

// openLeaf opens p and never follows a symbolic link at its last name: the
// directory is resolved by the root, the last name by openat with
// O_NOFOLLOW on that directory's descriptor (openLeafSys, per platform).
func (f *fsys) openLeaf(p string, flag int, perm fs.FileMode) (*os.File, error) {
	return f.openLeafSys(p, flag, perm)
}

// sameDir splits two names that must be in one directory (a commit renames
// within the object's directory).
func sameDir(from, to string) (dir, a, b string, err error) {
	if filepath.Dir(from) != filepath.Dir(to) {
		return "", "", "", fmt.Errorf("archive local: %s and %s are not in one directory", from, to)
	}
	return filepath.Dir(from), filepath.Base(from), filepath.Base(to), nil
}

// ReadFile reads p whole (never through a link).
func (f *fsys) ReadFile(p string) ([]byte, error) {
	fh, err := f.openLeaf(p, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return io.ReadAll(fh)
}
