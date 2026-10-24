//go:build linux || darwin

package local

import (
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openLeafSys opens the last name of p with openat(O_NOFOLLOW) on the
// descriptor of its directory, which the root resolved (D-10).
func (f *fsys) openLeafSys(p string, flag int, perm fs.FileMode) (*os.File, error) {
	d, err := f.OpenDir(filepath.Dir(p))
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fd, err := unix.Openat(int(d.Fd()), filepath.Base(p), flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm())) // #nosec G115 -- a descriptor / a permission
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), nil // #nosec G115 -- a descriptor
}
