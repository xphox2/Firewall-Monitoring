//go:build linux

package local

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const oNoFollow = unix.O_NOFOLLOW

// renameNoReplaceSys is renameat2(RENAME_NOREPLACE): the kernel refuses
// atomically when to exists (EEXIST). Filesystems that do not implement the
// flag answer EINVAL (NFS before 4.x servers that support it, CIFS, FUSE);
// an old kernel ENOSYS.
func renameNoReplaceSys(from, to string) error {
	err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return errNoReplaceUnsupported
	}
	return err
}

// openUncachedSys opens p so that reading it asks the server, not this
// client's page cache (the read-back after a write on a network share).
//
// O_DIRECT first: the Linux NFS client then sends every READ to the server
// and keeps nothing in the page cache, and the CIFS client opens an uncached
// handle (cache=strict mounts, the default, support it on current kernels).
// Where the open is refused (EINVAL: a CIFS mount or kernel without direct
// I/O, a FUSE share) the fallback is posix_fadvise(POSIX_FADV_DONTNEED) on
// the whole file: after the writer's fsync every cached page of the file is
// clean, and DONTNEED drops clean pages (invalidate_mapping_pages), so the
// read that follows is served by the server. fadvise alone is the weaker of
// the two — advisory, and it cannot drop a page another reader holds mapped
// — which is why it is only the fallback.
func openUncachedSys(p string) (f *os.File, direct bool, err error) {
	f, err = os.OpenFile(p, os.O_RDONLY|unix.O_DIRECT|unix.O_NOFOLLOW, 0) // #nosec G304 -- an object below the archive's directory
	if err == nil {
		return f, true, nil
	}
	if !errors.Is(err, unix.EINVAL) {
		return nil, false, err
	}
	f, err = os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0) // #nosec G304 -- an object below the archive's directory
	if err != nil {
		return nil, false, err
	}
	if err := unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED); err != nil { // #nosec G115 -- a file descriptor
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
