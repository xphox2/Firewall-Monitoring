// Package objstore is what the archive's worker, seal, verify-month, restore
// and preflight see of the place the archive writes to (the "target"): the
// result of a write, what a HEAD reports, the two error classes the callers
// branch on, and the interface every target implements. Two targets exist:
// internal/archive/s3 (S3-compatible object storage) and
// internal/archive/local (a directory on a local partition or a network
// share mounted by the host). internal/archive/target builds the one the
// configuration names.
//
// Every target keeps the same object layout below its prefix
// ("<prefix>/<stream>/v<schema>/<YYYY-MM>/…", chunk.json, _MONTH.json), the
// same verification (stored bytes against their sha256, read back in full)
// and the same write-once rule: an object is never overwritten, a second
// write of a key with other bytes is a new version, addressable by the
// version id the write returned.
package objstore

import (
	"context"
	"errors"
	"io"
	"time"
)

// PutResult describes a stored object. The verify helpers compare against
// it, so callers store it (the manifest) rather than re-deriving it.
type PutResult struct {
	Rel         string    // key below the prefix, as passed to Put
	Key         string    // full object key ("<prefix>/<rel>")
	Size        int64     // bytes stored
	SHA256      string    // hex sha256 of the bytes stored (sha256_object)
	ETag        string    // ETag without quotes: md5 hex, or "<md5 of part md5s>-<parts>" (S3 multipart)
	Parts       int       // 0 for a single write, else the multipart part count
	VersionID   string    // the version written ("" on an unversioned S3 bucket)
	RetainUntil time.Time // Object Lock retain-until sent (zero when lock is off, always zero on a local target)
}

// ObjectInfo is what HEAD reports about an object.
type ObjectInfo struct {
	Key         string
	Size        int64
	ETag        string // without quotes
	VersionID   string
	LockMode    string    // "" when the target does not report it
	RetainUntil time.Time // zero when the target does not report it
	Metadata    map[string]string
}

// ErrMismatch marks a verify failure where the target answered and the
// stored object is not what was written (missing, or another size, ETag,
// lock or hash). Any other verify error — a network, service or filesystem
// failure — says nothing about the object and is worth retrying as it is.
var ErrMismatch = errors.New("stored object does not match the upload")

// ErrNotFound marks an error where the target says the object (or the
// version) does not exist.
var ErrNotFound = errors.New("object not found")

// Store is a target as a whole. The worker, the seal, VerifyMonth and the
// restore each use the slice of it they need.
type Store interface {
	// Key returns the full object key for rel ("<prefix>/<rel>").
	Key(rel string) (string, error)
	// Put stores size bytes of body at rel and returns what was stored. It
	// never overwrites: a key that exists gets a new version.
	Put(ctx context.Context, rel string, body io.ReaderAt, size int64, meta map[string]string) (PutResult, error)
	// Head reports an object; a non-empty versionID addresses that version.
	Head(ctx context.Context, rel, versionID string) (ObjectInfo, error)
	// VerifyHead checks the stored object's size and ETag against want.
	VerifyHead(ctx context.Context, want PutResult) error
	// VerifyFull reads the object back in full, checks its length and
	// sha256 against want and copies every byte read to w (nil discards).
	VerifyFull(ctx context.Context, want PutResult, w io.Writer) error
	// GetBytes reads a small object whole (at most limit bytes).
	GetBytes(ctx context.Context, rel, versionID string, limit int64) ([]byte, ObjectInfo, error)
	// Versions counts the stored versions of exactly rel.
	Versions(ctx context.Context, rel string) (int, error)
	// Preflight proves the target can be written and read, writing no
	// object.
	Preflight(ctx context.Context) error
}

// ErrUninitialized marks a target that has never been written to: a local
// target's directory without its marker file. Only the archive worker, and
// only while the archive holds no chunk, initialises it (Initializer); any
// other caller treats it as "not there" — with chunks recorded it usually
// means the share is not mounted.
var ErrUninitialized = errors.New("archive target not initialised")

// Initializer is a target that must be initialised before its first write
// (a local directory's marker file).
type Initializer interface {
	Init(ctx context.Context) error
}
