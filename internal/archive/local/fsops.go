package local

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// The crash-safe write: the bytes go to a temporary file in the object's own
// directory, which is fsynced, then given its final name without ever
// replacing an existing file, then the directory is fsynced so the new name
// survives a power cut. A crash at any point leaves either no object (a
// temporary file, swept by the next write in that directory) or the whole
// object; never a partial one under the final name.

// errExists: the final name is taken (an object is never overwritten).
var errExists = errors.New("already exists")

// errNoReplaceUnsupported: the filesystem has no atomic no-replace rename.
var errNoReplaceUnsupported = errors.New("no-replace rename not supported")

// The primitives commitNoReplace uses, variables so tests can take every
// path: os.Link, renameat2(RENAME_NOREPLACE) (renamex_np(RENAME_EXCL) on
// macOS).
var (
	linkFile        = os.Link
	renameNoReplace = renameNoReplaceSys
)

// How commitNoReplace committed (Probe reports it).
const (
	commitLink          = "hard link"
	commitRenameNoRepl  = "rename with RENAME_NOREPLACE"
	commitCheckedRename = "checked rename (not atomic)"
)

// commitNoReplace gives tmp the name final unless final exists (errExists),
// tmp and final in the same directory. In order:
//
//  1. a hard link, which the kernel (and an NFS server, LINK) refuses
//     atomically when final exists; tmp is then removed;
//  2. where there are no hard links (an SMB share without the Unix
//     extensions, some FUSE mounts): renameat2(RENAME_NOREPLACE), refused
//     atomically when final exists — on the filesystems that implement it;
//  3. where neither is supported (EINVAL / ENOSYS / EOPNOTSUPP): an Lstat
//     that final does not exist, then a plain rename. That is NOT atomic: a
//     file created between the check and the rename would be replaced. The
//     protection then rests on the check and on a single writer per archive
//     directory — the archive's advisory lock allows one archive writer per
//     database, and the install id in the marker refuses a directory another
//     install initialised.
func commitNoReplace(tmp, final string) (how string, err error) {
	err = linkFile(tmp, final)
	if err == nil {
		// The object is committed; a temporary name left behind (the
		// remove failed) is swept by the next write in the directory.
		_ = os.Remove(tmp)
		return commitLink, nil
	}
	if errors.Is(err, fs.ErrExist) {
		return "", errExists
	}
	if !linkUnsupported(err) {
		return "", err
	}
	switch err := renameNoReplace(tmp, final); {
	case err == nil:
		return commitRenameNoRepl, nil
	case errors.Is(err, fs.ErrExist):
		return "", errExists
	case !errors.Is(err, errNoReplaceUnsupported):
		return "", err
	}
	if _, err := os.Lstat(final); err == nil {
		return "", errExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return commitCheckedRename, os.Rename(tmp, final)
}

// linkUnsupported reports a link(2) failure that means "no hard links here".
func linkUnsupported(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EMLINK) || errors.Is(err, syscall.EXDEV)
}

// syncDir fsyncs a directory so the names created in it are durable.
// unsupported is true when the filesystem refuses to fsync a directory
// (CIFS answers EINVAL; the server's rename is then durable on its own
// terms) — not an error.
// syncDir is syncDirSys; a variable so tests can see which directories a
// write makes durable.
var syncDir = syncDirSys

func syncDirSys(dir string) (unsupported bool, err error) {
	d, err := os.Open(dir) // #nosec G304 -- a directory below the archive's configured root
	if err != nil {
		return false, err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EBADF) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// describe wraps a filesystem error with what it usually means for an
// archive directory on a local disk or a share, keeping the chain for
// errors.Is.
func describe(op, path string, err error) error {
	if err == nil {
		return nil
	}
	hint := Hint(err)
	if hint == "" {
		return fmt.Errorf("archive local: %s %s: %w", op, path, err)
	}
	return fmt.Errorf("archive local: %s %s: %w (%s)", op, path, err, hint)
}

// Hint says what a filesystem error usually means for an archive directory
// ("" when there is nothing to add).
func Hint(err error) string {
	switch {
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "permission denied: the server runs as uid 100, gid 101 in the container; on the host make the directory writable by them " +
			"(chown 100:101), or map them on the share — NFS: an export with all_squash,anonuid=100,anongid=101 or a directory owned by 100:101 " +
			"(root_squash maps root, not uid 100); SMB: mount with uid=100,gid=101,file_mode=0640,dir_mode=0750"
	case errors.Is(err, syscall.EROFS):
		return "the filesystem is mounted read-only"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "no space left on the archive volume (or its quota is exhausted)"
	case errors.Is(err, syscall.ESTALE):
		return "stale file handle: the NFS export or the directory was replaced under the mount; remount the share on the host, then restart the container"
	case errors.Is(err, syscall.ENOTCONN), errors.Is(err, syscall.EHOSTDOWN), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return "the network share is unreachable: check the mount on the host (the archive waits and retries; no unarchived row is deleted meanwhile)"
	case errors.Is(err, syscall.EIO):
		return "I/O error: a failing disk, or a share that dropped; check the host's kernel log and the mount"
	case errors.Is(err, fs.ErrNotExist):
		return "it does not exist: is the partition or share mounted on the host, and bind-mounted into the container?"
	}
	return ""
}

// sweepTemps removes the temporary files a crashed write of name left in dir
// (".<name>.tmp-*"): only names this package creates.
func sweepTemps(dir, name string) {
	matches, _ := filepath.Glob(filepath.Join(dir, "."+globEscape(name)+tmpInfix+"*"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

// globEscape escapes the glob metacharacters of a file name (an archive key
// segment has none; this keeps the sweep exact if one ever does).
func globEscape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '*', '?', '[', ']', '\\':
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}

// directReader reads an O_DIRECT descriptor through a buffer aligned to
// 4 KiB, a multiple of the block size, as direct I/O requires on most
// filesystems (the NFS client does not; the alignment costs nothing there).
type directReader struct {
	f        *os.File
	buf      []byte
	off, end int
	eof      bool
}

const directAlign = 4096
const directBuf = 1 << 20

func newDirectReader(f *os.File) *directReader {
	raw := make([]byte, directBuf+directAlign)
	shift := 0
	if r := int(uintptr(unsafe.Pointer(&raw[0])) % directAlign); r != 0 { // #nosec G103 -- alignment arithmetic only
		shift = directAlign - r
	}
	return &directReader{f: f, buf: raw[shift : shift+directBuf]}
}

func (d *directReader) Read(p []byte) (int, error) {
	if d.off == d.end {
		if d.eof {
			return 0, io.EOF
		}
		n, err := d.f.Read(d.buf)
		d.off, d.end = 0, n
		if err == io.EOF {
			d.eof = true
			err = nil
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
	}
	n := copy(p, d.buf[d.off:d.end])
	d.off += n
	return n, nil
}

func (d *directReader) Close() error { return d.f.Close() }
