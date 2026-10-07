// Package local is the archive's local target (ARCHIVE_TARGET=local): the
// objects are files under ARCHIVE_LOCAL_DIR, a directory on a local
// partition or on a network share (NFS, SMB) that the HOST mounts and
// bind-mounts into the container below ARCHIVE_ALLOWED_ROOT. The application
// never mounts anything and needs no extra privilege.
//
// It keeps the S3 target's contract (internal/archive/objstore):
//
//   - the same layout: "<ARCHIVE_LOCAL_DIR>/<prefix>/<stream>/v<schema>/<YYYY-MM>/…",
//     chunk.json and _MONTH.json, keys "<prefix>/<rel>" as in the manifest;
//   - write once: a file is never overwritten. A write of a key that holds
//     the same bytes and metadata returns the stored version (a retry after a
//     crash); other bytes become a new version, "<name>.v<N>" beside the
//     first ("<name>" is version 1), and the version id ("1", "2", …) is
//     what the manifest records, so a verify of a version reads exactly the
//     bytes that were written then;
//   - every write is crash-safe on a local disk and on NFS/SMB: a temporary
//     file in the same directory, fsync, a commit to a name that does not
//     exist (hard link or RENAME_NOREPLACE, atomic; a checked rename, not
//     atomic, only where neither works: commitNoReplace), fsync of the
//     directories; the volume must be the same after the commit as before
//     (stillMounted), and on a network share the read-back bypasses the
//     client's page cache (openRead);
//   - finished objects are made read-only (0444). That only stops an
//     accident: whoever owns the files can change them back. Real
//     immutability is the storage's — ZFS snapshots, a WORM / snapshot-
//     protected share — since a directory has no Object Lock
//     (docs/OPERATIONS.md);
//   - the metadata the S3 target keeps in object headers (the ETag, the
//     seal's sha256 of _MONTH.json) is a sidecar "<object>.fwmeta" written
//     before the object; an object without one (copied in by hand) still
//     reads, its MD5 computed from its bytes;
//   - a marker file, "<ARCHIVE_LOCAL_DIR>/<prefix>/.fwmon-archive-target",
//     written once by the archive worker while the archive holds no chunk
//     (Init). Every write requires it, and a read of a missing object
//     without it is ErrUninitialized, not ErrNotFound: an unmounted share
//     shows the empty directory below the mount point, and the archive must
//     neither write its objects there (they would vanish under the share
//     when it comes back) nor count them as lost. Without the marker the
//     archive waits; the retention gate keeps every unarchived row.
//
// There is no delete of an object; the package removes only the temporary
// files it created.
package local

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- the S3-compatible ETag of a single-part object
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/archive/objstore"
	"firewall-mon/internal/config"
)

const (
	// MarkerName is the marker file in "<ARCHIVE_LOCAL_DIR>/<prefix>".
	MarkerName = ".fwmon-archive-target"
	metaSuffix = ".fwmeta"
	tmpInfix   = ".tmp-"

	objectMode fs.FileMode = 0o444
	dirMode    fs.FileMode = 0o750
	// sidecarLimit bounds a sidecar read.
	sidecarLimit = 1 << 20
)

// reservedName matches the last key segments the package keeps for itself:
// hidden names (the marker, temporary files), version files and sidecars.
var reservedName = regexp.MustCompile(`^\.|\.v[0-9]+$|\.fwmeta$`)

// beforeCommit, when set (tests), runs after the temporary file is written
// and fsynced and the sidecar is in place, just before the object gets its
// final name; an error ends the write there, as a crash would.
var beforeCommit func(tmp, final string) error

// Store is one local target: a directory and a prefix.
type Store struct {
	root   string // ARCHIVE_ALLOWED_ROOT
	dir    string // ARCHIVE_LOCAL_DIR
	prefix string
	base   string // dir/prefix
	now    func() time.Time
	// installID is this install's id (database.ArchiveInstallID): the marker
	// must carry it ("" = not checked: a read-only user such as
	// --verify-month).
	installID string

	netMu    sync.Mutex
	netKnown bool // network is settled (see onNetwork)
	network  bool // the directory is on a network filesystem (reads bypass the page cache)
}

// SetInstallID sets the install id the marker must carry (Init writes it).
func (s *Store) SetInstallID(id string) { s.installID = id }

// deviceOf is the st_dev of a path; a variable so tests can simulate a
// volume replaced under the archive (an unmount).
var deviceOf = deviceOfSys

// openUncached opens a file for a read that must come from the storage, not
// this client's cache; a variable so tests can see it used.
var openUncached = openUncachedSys

// *Store is an archive target.
var _ objstore.Store = (*Store)(nil)

// New builds the target from the configuration (ValidateLocal). It touches
// no file.
func New(cfg config.ArchiveConfig) (*Store, error) {
	if err := cfg.ValidateLocal(); err != nil {
		return nil, err
	}
	return &Store{root: cfg.Root(), dir: filepath.Clean(cfg.LocalDir), prefix: cfg.Prefix, base: cfg.LocalBase(), now: time.Now}, nil
}

// Dir is the directory every object is under ("<ARCHIVE_LOCAL_DIR>/<prefix>").
func (s *Store) Dir() string { return s.base }

// Key returns the full object key for rel ("<prefix>/<rel>"), as the S3
// target does; rel's last segment may not be a name the package reserves.
func (s *Store) Key(rel string) (string, error) {
	if !config.ValidArchiveKeyPath(rel) || reservedName.MatchString(path.Base(rel)) {
		return "", fmt.Errorf("archive local: invalid object key path %q", rel)
	}
	return s.prefix + "/" + rel, nil
}

func (s *Store) file(rel string) string { return filepath.Join(s.base, filepath.FromSlash(rel)) }

// versionFile is the file of version v of the object at p.
func versionFile(p string, v int) string {
	if v == 1 {
		return p
	}
	return p + ".v" + strconv.Itoa(v)
}

// latestVersion is the highest version of the object at p (0: none). Versions
// are written in order, each only after the one before exists.
func latestVersion(p string) (int, error) {
	v := 0
	for {
		_, err := os.Lstat(versionFile(p, v+1))
		if errors.Is(err, fs.ErrNotExist) {
			return v, nil
		}
		if err != nil {
			return 0, describe("stat", versionFile(p, v+1), err)
		}
		v++
	}
}

// sidecar is "<object>.fwmeta".
type sidecar struct {
	Kind      string            `json:"kind"`
	Key       string            `json:"key"`
	Version   int               `json:"version"`
	Size      int64             `json:"size"`
	SHA256    string            `json:"sha256"`
	MD5       string            `json:"md5"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	WrittenAt string            `json:"written_at"`
}

const sidecarKind = "fwmon-archive-object"

func readSidecar(vp string) (*sidecar, error) {
	f, err := os.OpenFile(vp+metaSuffix, os.O_RDONLY|oNoFollow, 0) // #nosec G304 -- a sidecar below the archive's directory
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, describe("open", vp+metaSuffix, err)
	}
	defer f.Close()
	var sc sidecar
	if err := json.NewDecoder(io.LimitReader(f, sidecarLimit)).Decode(&sc); err != nil {
		return nil, corruptSidecar(vp, err.Error())
	}
	if sc.Kind != sidecarKind {
		return nil, corruptSidecar(vp, fmt.Sprintf("kind %q", sc.Kind))
	}
	return &sc, nil
}

// errCorruptSidecar marks a sidecar that exists but does not parse.
var errCorruptSidecar = errors.New("corrupt sidecar")

// corruptSidecar is the error of a sidecar that exists but is not one. It is
// a mismatch (objstore.ErrMismatch): the stored object cannot be shown to be
// what was written, so the worker exports the chunk again — a new version
// with a fresh sidecar — and, if that keeps failing, parks the chunk in
// needs_attention like any other mismatch; a seal re-check refuses the month
// with this text.
func corruptSidecar(vp, why string) error {
	return fmt.Errorf("%w: %w: archive local: the sidecar %s cannot be read (%s). It holds the ETag and metadata of %s, "+
		"which the archive does not guess; the chunk is written again as a new version. Inspect the file: if %s itself is intact "+
		"(compare its sha256 with the manifest's sha256_object) the sidecar may be removed — its ETag is then computed from the bytes — "+
		"except for a _MONTH.json, whose sidecar records the seal's sha256 and must be restored from a copy",
		objstore.ErrMismatch, errCorruptSidecar, vp+metaSuffix, why, vp, vp)
}

// markerPresent checks the marker: ErrUninitialized when it is missing.
func (s *Store) markerPresent() error {
	_, err := s.markerDev()
	return err
}

// markerDev checks the marker and returns the device it is on.
func (s *Store) markerDev() (uint64, error) {
	mp := filepath.Join(s.base, MarkerName)
	_, err := os.Lstat(mp)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0, fmt.Errorf("%w: %s has no %s: the archive was never initialised there, or the partition or share is not mounted (on the host, and bind-mounted into the container)",
			objstore.ErrUninitialized, s.base, MarkerName)
	case err != nil:
		return 0, describe("stat", mp, err)
	}
	dev, err := deviceOf(mp)
	if err != nil {
		return 0, describe("stat", mp, err)
	}
	return dev, nil
}

// ErrForeignMarker: the directory's marker was written by another install.
var ErrForeignMarker = errors.New("the archive directory belongs to another install")

// checkOwner reads the marker and refuses one another install wrote (two
// servers writing one directory would each supersede the other's objects
// and break the single-writer rule the no-replace commit relies on).
func (s *Store) checkOwner() error {
	if s.installID == "" {
		return nil
	}
	mp := filepath.Join(s.base, MarkerName)
	b, err := os.ReadFile(mp) // #nosec G304 -- the marker below the archive's directory
	if err != nil {
		return describe("read", mp, err)
	}
	var m marker
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("archive local: %s is not a marker: %w", mp, err)
	}
	if m.InstallID != s.installID {
		return fmt.Errorf("%w: %s carries install id %q, this server's is %q; two servers must not share one archive directory: give this one its own directory or prefix",
			ErrForeignMarker, mp, m.InstallID, s.installID)
	}
	return nil
}

// stillMounted checks, after a write, that dir and the marker are on the
// device the marker was on when the write began: a share unmounted (or
// replaced) during the write fails it, so the chunk is not verified against
// files that are not on the share.
func (s *Store) stillMounted(dir string, dev uint64) error {
	now, err := s.markerDev()
	if err != nil {
		return fmt.Errorf("archive local: the archive volume went away during the write: %w", err)
	}
	ddev, err := deviceOf(dir)
	if err != nil {
		return describe("stat", dir, err)
	}
	if now == dev && ddev != dev {
		return fmt.Errorf("archive local: %s is on another filesystem than the archive's marker in %s (device %d, marker %d): a nested mount below the archive directory — an NFSv4 crossmnt child export, a ZFS dataset or a btrfs subvolume under it? The whole archive tree must be one filesystem (docs/OPERATIONS.md); the write is not counted",
			dir, s.base, ddev, now)
	}
	if now != dev || ddev != dev {
		return fmt.Errorf("archive local: the archive volume changed during the write (device %d, then marker %d, directory %d): unmounted or remounted? The write is not counted", dev, now, ddev)
	}
	return nil
}

// dirs checks the directories from the base down to dir: each must be a real
// directory, never a symbolic link (a link inside the archive could lead an
// object out of it). With create, a missing one is created; the base itself
// is never created here (Init does, once): a missing base is a volume that is
// not there.
func (s *Store) dirs(dir string, create bool) error {
	bi, err := os.Stat(s.base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if merr := s.markerPresent(); merr != nil {
				return merr
			}
		}
		return describe("stat", s.base, err)
	}
	if !bi.IsDir() {
		return fmt.Errorf("archive local: %s is not a directory", s.base)
	}
	rel, err := filepath.Rel(s.base, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("archive local: %s is not below %s", dir, s.base)
	}
	if rel == "." {
		return nil
	}
	cur := s.base
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		switch {
		case err == nil && fi.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("archive local: %s is a symbolic link: the archive's directories must be real directories", cur)
		case err == nil && !fi.IsDir():
			return fmt.Errorf("archive local: %s is not a directory", cur)
		case err == nil:
		case errors.Is(err, fs.ErrNotExist) && create:
			if err := os.Mkdir(cur, dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
				return describe("create directory", cur, err)
			}
			if fi, err := os.Lstat(cur); err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
				return fmt.Errorf("archive local: %s is not a directory after creating it", cur)
			}
		case errors.Is(err, fs.ErrNotExist):
			return nil // a read of something that is not there: the caller's not-found
		default:
			return describe("stat", cur, err)
		}
	}
	return nil
}

// onNetwork reports whether the directory is on a network filesystem.
func (s *Store) onNetwork() bool {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.netKnown {
		return s.network
	}
	// The answer is kept only once the marker is present on the filesystem
	// statfs described: during an outage statfs sees the empty mount point's
	// filesystem (the host's), and keeping "not network" then would let
	// every later read-back come from the page cache. Until then a read is
	// uncached, which is always correct, only slower.
	fi, err := StatFS(s.dir)
	if err != nil {
		return true
	}
	if mdev, merr := s.markerDev(); merr == nil && mdev == fi.Device {
		s.netKnown, s.network = true, fi.Network()
		return s.network
	}
	return true
}

// openRead opens version file vp for reading: never through a symbolic
// link, and on a network filesystem bypassing this client's page cache, so
// a read-back verifies what the server stored, not what was just written
// into local memory (openUncached).
func (s *Store) openRead(vp string) (io.ReadCloser, error) {
	if err := s.dirs(filepath.Dir(vp), false); err != nil {
		return nil, err
	}
	// A directory swapped for a link between this check and the open below
	// is not caught (accepted: it needs write access to the share itself).
	if s.onNetwork() {
		f, direct, err := openUncached(vp)
		if err != nil {
			return nil, err
		}
		if direct {
			return newDirectReader(f), nil
		}
		return f, nil
	}
	return os.OpenFile(vp, os.O_RDONLY|oNoFollow, 0) // #nosec G304 -- an object below the archive's directory
}

// notFound is the error of an object that does not exist: ErrNotFound when
// the target is there (its marker is), else the marker's error.
func (s *Store) notFound(key, version string) error {
	if err := s.markerPresent(); err != nil {
		return err
	}
	if version != "" {
		return fmt.Errorf("%w: archive local: %s version %s", objstore.ErrNotFound, key, version)
	}
	return fmt.Errorf("%w: archive local: %s", objstore.ErrNotFound, key)
}

// ctxReader stops a long copy when ctx ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// writeTemp copies size bytes of body into a new temporary file in dir and
// fsyncs it, returning its name and the bytes' sha256 and MD5.
func writeTemp(ctx context.Context, dir, name string, body io.Reader, size int64) (tmp, shaHex, md5Hex string, err error) {
	f, err := os.CreateTemp(dir, "."+name+tmpInfix+"*")
	if err != nil {
		return "", "", "", describe("create a temporary file in", dir, err)
	}
	tmp = f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			_ = os.Remove(tmp)
		}
	}()
	sh, mh := sha256.New(), md5.New() // #nosec G401 -- the S3-compatible ETag
	n, err := io.Copy(io.MultiWriter(f, sh, mh), ctxReader{ctx, body})
	if err != nil {
		return "", "", "", describe("write", tmp, err)
	}
	if n != size {
		return "", "", "", fmt.Errorf("archive local: write %s: got %d of %d bytes", tmp, n, size)
	}
	if err := f.Sync(); err != nil {
		return "", "", "", describe("fsync", tmp, err)
	}
	if err := f.Close(); err != nil {
		return "", "", "", describe("close", tmp, err)
	}
	ok = true
	return tmp, hex.EncodeToString(sh.Sum(nil)), hex.EncodeToString(mh.Sum(nil)), nil
}

// writeSmall writes body to the new file final (crash-safe, never replacing
// it) and makes it read-only. An existing final is errExists.
func writeSmall(ctx context.Context, final string, body []byte) error {
	dir, name := filepath.Split(final)
	tmp, _, _, err := writeTemp(ctx, dir, name, bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := commitNoReplace(tmp, final); err != nil {
		if errors.Is(err, errExists) {
			return errExists
		}
		return describe("commit", final, err)
	}
	_ = os.Chmod(final, objectMode)
	return nil
}

// Put stores size bytes of body at rel and returns what it stored (see the
// package doc: write once, versions, crash-safe). body is read once.
func (s *Store) Put(ctx context.Context, rel string, body io.ReaderAt, size int64, meta map[string]string) (objstore.PutResult, error) {
	key, err := s.Key(rel)
	if err != nil {
		return objstore.PutResult{}, err
	}
	if size < 0 {
		return objstore.PutResult{}, fmt.Errorf("archive local: negative size %d for %s", size, key)
	}
	dev, err := s.markerDev()
	if err != nil {
		return objstore.PutResult{}, err
	}
	if err := s.checkOwner(); err != nil {
		return objstore.PutResult{}, err
	}
	p := s.file(rel)
	dir, name := filepath.Split(p)
	dir = filepath.Clean(dir)
	if err := s.dirs(dir, true); err != nil {
		return objstore.PutResult{}, err
	}
	sweepTemps(dir, name)
	tmp, shaHex, md5Hex, err := writeTemp(ctx, dir, name, io.NewSectionReader(body, 0, size), size)
	if err != nil {
		return objstore.PutResult{}, err
	}
	defer os.Remove(tmp) // a no-op once committed
	res := objstore.PutResult{Rel: rel, Key: key, Size: size, SHA256: shaHex, ETag: md5Hex}

	latest, err := latestVersion(p)
	if err != nil {
		return objstore.PutResult{}, err
	}
	if latest > 0 {
		same, err := s.sameObject(ctx, versionFile(p, latest), size, shaHex, meta)
		if err != nil {
			return objstore.PutResult{}, err
		}
		if same {
			// The stored copy may be the one a crash interrupted before its
			// directory fsync: make it durable, on the same volume, before
			// it counts.
			if err := syncDirs(dir, s.base); err != nil {
				return objstore.PutResult{}, err
			}
			if err := s.stillMounted(dir, dev); err != nil {
				return objstore.PutResult{}, err
			}
			res.VersionID = strconv.Itoa(latest)
			return res, nil
		}
	}
	v := latest + 1
	vp := versionFile(p, v)
	sc := sidecar{Kind: sidecarKind, Key: key, Version: v, Size: size, SHA256: shaHex, MD5: md5Hex, Metadata: meta,
		WrittenAt: s.now().UTC().Format(time.RFC3339Nano)}
	if err := writeSidecar(ctx, vp, sc); err != nil {
		return objstore.PutResult{}, err
	}
	if beforeCommit != nil {
		if err := beforeCommit(tmp, vp); err != nil {
			return objstore.PutResult{}, err
		}
	}
	if _, err := commitNoReplace(tmp, vp); err != nil {
		if errors.Is(err, errExists) {
			return objstore.PutResult{}, fmt.Errorf("archive local: %s appeared while it was being written: another writer uses this directory", vp)
		}
		return objstore.PutResult{}, describe("commit", vp, err)
	}
	// Read-only is best effort: a share mounted without permission support
	// keeps its mount's file mode (Probe reports it).
	_ = os.Chmod(vp, objectMode)
	if err := syncDirs(dir, s.base); err != nil {
		return objstore.PutResult{}, err
	}
	if err := s.stillMounted(dir, dev); err != nil {
		return objstore.PutResult{}, err
	}
	fi, err := os.Stat(vp)
	if err != nil {
		return objstore.PutResult{}, describe("stat", vp, err)
	}
	if fi.Size() != size {
		return objstore.PutResult{}, fmt.Errorf("archive local: %s is %d bytes after the write, want %d", vp, fi.Size(), size)
	}
	res.VersionID = strconv.Itoa(v)
	return res, nil
}

// syncDirs fsyncs dir and every directory above it up to base: the new
// object's name, and the names of the directories MkdirAll may just have
// created for it, survive a power cut.
func syncDirs(dir, base string) error {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := syncDir(d); err != nil {
			return describe("fsync directory", d, err)
		}
		if d == base || !within(d, base) || filepath.Dir(d) == d {
			return nil
		}
	}
}

// writeSidecar writes vp's sidecar. One left by a write that crashed before
// its object was committed (vp does not exist, so it describes nothing) is
// replaced.
func writeSidecar(ctx context.Context, vp string, sc sidecar) error {
	body, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	mp := vp + metaSuffix
	if _, err := os.Lstat(mp); err == nil {
		_ = os.Chmod(mp, 0o600) // an SMB server refuses to delete a read-only file
		if err := os.Remove(mp); err != nil {
			return describe("remove the orphaned sidecar", mp, err)
		}
	}
	if err := writeSmall(ctx, mp, body); err != nil {
		if errors.Is(err, errExists) {
			return fmt.Errorf("archive local: %s appeared while it was being written: another writer uses this directory", mp)
		}
		return err
	}
	return nil
}

// sameObject reports whether the stored version vp holds exactly size bytes
// hashing to shaHex — read in full, not taken from its sidecar — with the
// metadata meta.
func (s *Store) sameObject(ctx context.Context, vp string, size int64, shaHex string, meta map[string]string) (bool, error) {
	fi, err := os.Stat(vp)
	if err != nil {
		return false, describe("stat", vp, err)
	}
	if fi.Size() != size {
		return false, nil
	}
	sc, err := readSidecar(vp)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errCorruptSidecar):
		return false, nil // a copy without (readable) metadata is never reused
	case err != nil:
		return false, err
	case sc.SHA256 != shaHex || !maps.Equal(sc.Metadata, meta):
		return false, nil
	}
	got, err := s.hashFile(ctx, vp, sha256.New(), nil)
	if err != nil {
		return false, err
	}
	return got == shaHex, nil
}

// hashFile hashes the file at p, copying its bytes to w as well (nil
// discards), and returns the hex digest.
func (s *Store) hashFile(ctx context.Context, p string, h hash.Hash, w io.Writer) (string, error) {
	f, err := s.openRead(p)
	if err != nil {
		return "", describe("open", p, err)
	}
	defer f.Close()
	dst := io.Writer(h)
	if w != nil {
		dst = io.MultiWriter(h, w)
	}
	if _, err := io.Copy(dst, ctxReader{ctx, f}); err != nil {
		return "", describe("read", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// version resolves a version id ("" = the latest) of the object at p; 0
// when there is none.
func version(p, versionID string) (int, error) {
	if versionID == "" {
		return latestVersion(p)
	}
	v, err := strconv.Atoi(versionID)
	if err != nil || v < 1 || strconv.Itoa(v) != versionID {
		return 0, nil
	}
	if _, err := os.Lstat(versionFile(p, v)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, describe("stat", versionFile(p, v), err)
	}
	return v, nil
}

// Head reports an object (a version, or the latest when versionID is "").
func (s *Store) Head(ctx context.Context, rel, versionID string) (objstore.ObjectInfo, error) {
	key, err := s.Key(rel)
	if err != nil {
		return objstore.ObjectInfo{}, err
	}
	p := s.file(rel)
	v, err := version(p, versionID)
	if err != nil {
		return objstore.ObjectInfo{}, err
	}
	if v == 0 {
		return objstore.ObjectInfo{}, s.notFound(key, versionID)
	}
	vp := versionFile(p, v)
	fi, err := os.Stat(vp)
	if errors.Is(err, fs.ErrNotExist) {
		return objstore.ObjectInfo{}, s.notFound(key, versionID)
	} else if err != nil {
		return objstore.ObjectInfo{}, describe("stat", vp, err)
	}
	info := objstore.ObjectInfo{Key: key, Size: fi.Size(), VersionID: strconv.Itoa(v)}
	switch sc, err := readSidecar(vp); {
	case err == nil:
		info.ETag, info.Metadata = sc.MD5, sc.Metadata
	case errors.Is(err, fs.ErrNotExist):
		// No sidecar (an object copied in by hand): its ETag is the MD5 of
		// its bytes, and it has no metadata.
		if info.ETag, err = s.hashFile(ctx, vp, md5.New(), nil); err != nil { // #nosec G401 -- the S3-compatible ETag
			return objstore.ObjectInfo{}, err
		}
	default:
		// A sidecar that cannot be read or parsed says nothing about the
		// object: an error, not a guess.
		return objstore.ObjectInfo{}, err
	}
	return info, nil
}

// mismatch wraps a verify finding in ErrMismatch.
func mismatch(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{objstore.ErrMismatch}, args...)...)
}

// missing turns a not-found error of a verify into a mismatch: the object
// is gone (its target is there: ErrUninitialized stays what it is).
func missing(err error) error {
	if errors.Is(err, objstore.ErrNotFound) {
		return fmt.Errorf("%w: missing: %w", objstore.ErrMismatch, err)
	}
	return err
}

// VerifyHead checks the stored version's size and ETag against want.
func (s *Store) VerifyHead(ctx context.Context, want objstore.PutResult) error {
	info, err := s.Head(ctx, want.Rel, want.VersionID)
	if err != nil {
		return missing(err)
	}
	switch {
	case info.Size != want.Size:
		return mismatch("archive local: verify %s: size %d, want %d", want.Key, info.Size, want.Size)
	case info.ETag != want.ETag:
		return mismatch("archive local: verify %s: ETag %q, want %q", want.Key, info.ETag, want.ETag)
	}
	return nil
}

// VerifyFull reads the version want names back in full and checks its
// length and sha256 (and its sidecar's ETag); every byte read is also
// written to w (nil discards).
func (s *Store) VerifyFull(ctx context.Context, want objstore.PutResult, w io.Writer) error {
	key, err := s.Key(want.Rel)
	if err != nil {
		return err
	}
	p := s.file(want.Rel)
	v, err := version(p, want.VersionID)
	if err != nil {
		return err
	}
	if v == 0 {
		return missing(s.notFound(key, want.VersionID))
	}
	vp := versionFile(p, v)
	switch sc, err := readSidecar(vp); {
	case err == nil && want.ETag != "" && sc.MD5 != want.ETag:
		return mismatch("archive local: verify %s: ETag %q, want %q", want.Key, sc.MD5, want.ETag)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	f, err := s.openRead(vp)
	if errors.Is(err, fs.ErrNotExist) {
		return missing(s.notFound(key, want.VersionID))
	} else if err != nil {
		return describe("open", vp, err)
	}
	defer f.Close()
	h := sha256.New()
	dst := io.Writer(h)
	if w != nil {
		dst = io.MultiWriter(h, w)
	}
	n, err := io.Copy(dst, ctxReader{ctx, f})
	if err != nil {
		return describe("read back", vp, err)
	}
	if n != want.Size {
		return mismatch("archive local: verify %s: read %d bytes, want %d", want.Key, n, want.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want.SHA256 {
		return mismatch("archive local: verify %s: sha256 %s, want %s", want.Key, got, want.SHA256)
	}
	return nil
}

// GetBytes reads a small object whole: at most limit bytes, else an error.
func (s *Store) GetBytes(ctx context.Context, rel, versionID string, limit int64) ([]byte, objstore.ObjectInfo, error) {
	info, err := s.Head(ctx, rel, versionID)
	if err != nil {
		return nil, objstore.ObjectInfo{}, err
	}
	vp := versionFile(s.file(rel), mustAtoi(info.VersionID))
	f, err := s.openRead(vp)
	if err != nil {
		return nil, objstore.ObjectInfo{}, describe("open", vp, err)
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(ctxReader{ctx, f}, limit+1))
	if err != nil {
		return nil, objstore.ObjectInfo{}, describe("read", vp, err)
	}
	if int64(len(body)) > limit {
		return nil, objstore.ObjectInfo{}, fmt.Errorf("archive local: %s is larger than %d bytes", info.Key, limit)
	}
	info.Size = int64(len(body))
	return body, info, nil
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// Versions counts the stored versions of exactly rel (0 when there is none).
func (s *Store) Versions(ctx context.Context, rel string) (int, error) {
	if _, err := s.Key(rel); err != nil {
		return 0, err
	}
	return latestVersion(s.file(rel))
}

// Preflight checks the directory: it resolves (symbolic links followed)
// under ARCHIVE_ALLOWED_ROOT and outside the database volume, holds the
// marker (ErrUninitialized otherwise), and a temporary file can be written,
// fsynced, committed under a second name, read back and removed. It writes
// no object.
func (s *Store) Preflight(ctx context.Context) error {
	if _, err := ResolveUnderRoot(s.root, s.dir); err != nil {
		return err
	}
	if err := s.checkVolume(); err != nil {
		return err
	}
	if _, err := os.Stat(s.base); err == nil {
		if _, err := ResolveUnderRoot(s.root, s.base); err != nil {
			return err
		}
	}
	if err := s.markerPresent(); err != nil {
		return err
	}
	if err := s.checkOwner(); err != nil {
		return err
	}
	_, err := probeWrite(ctx, s.base, 4<<10)
	return err
}

// checkVolume refuses a directory that cannot be the host's archive volume:
// one in the container's writable layer or memory (overlay, tmpfs), or one
// where neither it nor any directory up to ARCHIVE_ALLOWED_ROOT is a mount
// point (the bind mount is missing). The worker runs it before its first
// write, whatever set the configuration (environment or admin page).
func (s *Store) checkVolume() error {
	fi, err := StatFS(s.dir)
	if err != nil {
		return fmt.Errorf("archive local: %s: filesystem unknown: %w", s.dir, err)
	}
	if fi.Type == "overlay" || fi.Type == "tmpfs" {
		return fmt.Errorf("archive local: %s is on %s: the container's writable layer or memory, lost with the container; bind-mount the host's archive volume under ARCHIVE_ALLOWED_ROOT %s", s.dir, fi.Type, s.root)
	}
	for d := s.dir; ; d = filepath.Dir(d) {
		mounted, err := IsMountPoint(d)
		if err != nil {
			return describe("check the mount of", d, err)
		}
		if mounted {
			return nil
		}
		if d == s.root || !within(d, s.root) || filepath.Dir(d) == d {
			break
		}
	}
	return fmt.Errorf("archive local: neither %s nor a directory above it up to ARCHIVE_ALLOWED_ROOT %s is a mount point: the archive would be written into the container; bind-mount the host's archive partition or share there (docs/OPERATIONS.md)", s.dir, s.root)
}

// marker is the marker file's content.
type marker struct {
	Kind      string `json:"kind"`
	Prefix    string `json:"prefix"`
	CreatedAt string `json:"created_at"`
	// InstallID is the install that initialised the directory
	// (database.ArchiveInstallID); another install's is refused.
	InstallID string `json:"install_id"`
}

// Init creates "<ARCHIVE_LOCAL_DIR>/<prefix>" and its marker (a marker that
// exists is kept). ARCHIVE_LOCAL_DIR itself must exist: it is the mounted
// volume, or a directory the operator made on it. Only the archive worker
// calls it, and only while the archive holds no chunk.
func (s *Store) Init(ctx context.Context) error {
	if _, err := ResolveUnderRoot(s.root, s.dir); err != nil {
		return err
	}
	if err := s.checkVolume(); err != nil {
		return err
	}
	if s.installID == "" {
		return errors.New("archive local: no install id: the archive directory is initialised only by the archive worker")
	}
	if err := os.MkdirAll(s.base, dirMode); err != nil {
		return describe("create directory", s.base, err)
	}
	if _, err := ResolveUnderRoot(s.root, s.base); err != nil {
		return err
	}
	body, err := json.MarshalIndent(marker{Kind: "fwmon-archive-target", Prefix: s.prefix, CreatedAt: s.now().UTC().Format(time.RFC3339),
		InstallID: s.installID}, "", "  ")
	if err != nil {
		return err
	}
	mp := filepath.Join(s.base, MarkerName)
	if err := writeSmall(ctx, mp, append(body, '\n')); err != nil && !errors.Is(err, errExists) {
		return err
	}
	if _, err := syncDir(s.base); err != nil {
		return describe("fsync directory", s.base, err)
	}
	if _, err := syncDir(filepath.Dir(s.base)); err != nil {
		return describe("fsync directory", filepath.Dir(s.base), err)
	}
	return s.checkOwner()
}

// randomSuffix is a short random hex string for probe file names.
func randomSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
