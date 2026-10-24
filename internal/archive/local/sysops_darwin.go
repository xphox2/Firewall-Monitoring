//go:build darwin

package local

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplaceSys is renameatx_np(RENAME_EXCL) on the descriptor of the
// directory both names are in (the root resolved it, D-10): refused
// atomically when to exists (EEXIST); ENOTSUP where the filesystem lacks it.
func renameNoReplaceSys(f *fsys, from, to string) error {
	dir, a, b, err := sameDir(from, to)
	if err != nil {
		return err
	}
	d, err := f.OpenDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	err = unix.RenameatxNp(int(d.Fd()), a, int(d.Fd()), b, unix.RENAME_EXCL)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS) {
		return errNoReplaceUnsupported
	}
	return err
}

// openUncachedSys opens p with F_NOCACHE (macOS has no O_DIRECT): reads of
// the descriptor bypass the unified buffer cache. Through the root and never
// through a link (openLeaf, D-10).
func openUncachedSys(f *fsys, p string) (*os.File, bool, error) {
	fh, err := f.openLeaf(p, os.O_RDONLY, 0)
	if err != nil {
		return nil, false, err
	}
	if _, err := unix.FcntlInt(fh.Fd(), unix.F_NOCACHE, 1); err != nil {
		fh.Close()
		return nil, false, err
	}
	return fh, false, nil
}

func deviceOfSys(p string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil // #nosec G115 -- a device number, compared only
}
