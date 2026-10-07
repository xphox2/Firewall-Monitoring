//go:build darwin

package local

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const oNoFollow = unix.O_NOFOLLOW

// renameNoReplaceSys is renamex_np(RENAME_EXCL): refused atomically when to
// exists (EEXIST); ENOTSUP where the filesystem lacks it.
func renameNoReplaceSys(from, to string) error {
	err := unix.RenamexNp(from, to, unix.RENAME_EXCL)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS) {
		return errNoReplaceUnsupported
	}
	return err
}

// openUncachedSys opens p with F_NOCACHE (macOS has no O_DIRECT): reads of
// the descriptor bypass the unified buffer cache.
func openUncachedSys(p string) (*os.File, bool, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0) // #nosec G304 -- an object below the archive's directory
	if err != nil {
		return nil, false, err
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_NOCACHE, 1); err != nil {
		f.Close()
		return nil, false, err
	}
	return f, false, nil
}

func deviceOfSys(p string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil // #nosec G115 -- a device number, compared only
}
