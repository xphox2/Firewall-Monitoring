//go:build linux

package local

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplaceSys is renameat2(RENAME_NOREPLACE) on the descriptor of
// the directory both names are in (the root resolved it, D-10): the kernel
// refuses atomically when to exists (EEXIST). Filesystems that do not
// implement the flag answer EINVAL (NFS before 4.x servers that support it,
// CIFS, FUSE); an old kernel ENOSYS.
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
	err = unix.Renameat2(int(d.Fd()), a, int(d.Fd()), b, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return errNoReplaceUnsupported
	}
	return err
}

// openUncachedSys opens p so that reading it asks the server, not this
// client's page cache (the read-back after a write on a network share).
// Through the root and never through a link (openLeaf, D-10).
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
func openUncachedSys(f *fsys, p string) (fh *os.File, direct bool, err error) {
	fh, err = f.openLeaf(p, os.O_RDONLY|unix.O_DIRECT, 0)
	if err == nil {
		return fh, true, nil
	}
	if !errors.Is(err, unix.EINVAL) {
		return nil, false, err
	}
	fh, err = f.openLeaf(p, os.O_RDONLY, 0)
	if err != nil {
		return nil, false, err
	}
	if err := unix.Fadvise(int(fh.Fd()), 0, 0, unix.FADV_DONTNEED); err != nil { // #nosec G115 -- a file descriptor
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
