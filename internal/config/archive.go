package config

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ArchiveConfig is the raw syslog / flow archive to S3-compatible object
// storage (ARCHIVE_* env; archive plan PR 2). Load reads it from the
// environment or CONFIG_FILE; since A-10 every key can also be set on the
// admin Retention page, which wins over the environment (WithSettings,
// archive_fields.go; resolved by database.ResolveArchiveConfig). The
// environment is the default.
//
// Every connection key is REQUIRED once either stream is enabled, and none has
// a default: the project names no storage service, bucket or region in code.
// With both streams disabled (the default) nothing here is validated or used,
// so an install that does not set ARCHIVE_* behaves exactly as before.
//
// An enabled stream is exported, uploaded and verified by the poller's
// archive worker (internal/archive/worker), and its raw deletes wait for that
// verification: retention, the severity 6/7 aggregation and the flow rollup
// only take rows at or below the verified-through id (the retention gate,
// internal/database/archive_gate.go). A disabled stream deletes exactly as
// without the archive.
type ArchiveConfig struct {
	SyslogEnabled bool // ARCHIVE_SYSLOG_ENABLED (default false)
	FlowsEnabled  bool // ARCHIVE_FLOWS_ENABLED (default false): sflow, netflow and sflow-counters

	Endpoint        string // ARCHIVE_S3_ENDPOINT: https://host[:port], no path / userinfo / query
	Region          string // ARCHIVE_S3_REGION
	Bucket          string // ARCHIVE_S3_BUCKET
	Prefix          string // ARCHIVE_S3_PREFIX: every object key starts with "<prefix>/"
	AccessKeyID     string // ARCHIVE_S3_ACCESS_KEY_ID
	SecretAccessKey Secret // ARCHIVE_S3_SECRET_ACCESS_KEY (redacted by every formatter)
	PathStyle       bool   // ARCHIVE_S3_PATH_STYLE (default true)

	// Object Lock retention applied to every object the archive writes.
	// 0 days = no per-object retention headers.
	ObjectLockDays int    // ARCHIVE_OBJECT_LOCK_DAYS (default 0)
	ObjectLockMode string // ARCHIVE_OBJECT_LOCK_MODE: GOVERNANCE or COMPLIANCE, required when days > 0

	// MinAgeHours is how long after a syslog day / counter day ends before its
	// chunk may be exported (flows use a fixed 5 minutes).
	MinAgeHours int // ARCHIVE_MIN_AGE_HOURS (default 2)

	// Month seal: a stream's month M is sealed (its _MONTH.json written, the
	// folder closed to writes) at the first pass at or after the 1st of M+1
	// 00:00 UTC + SealGraceHours. SealReverify is how the seal re-checks every
	// object of the month first: "head" (size and ETag) or "full" (read back
	// and re-hashed).
	SealGraceHours int    // ARCHIVE_SEAL_GRACE_HOURS (default 48, 6-168)
	SealReverify   string // ARCHIVE_SEAL_REVERIFY: head (default) or full

	// Read pacing of an export, rows per second (100-100000):
	// syslog_messages, and flow_samples / flow_if_counters.
	SyslogRateRowsPerSec int // ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC (default 5000)
	FlowRateRowsPerSec   int // ARCHIVE_FLOW_RATE_ROWS_PER_SEC (default 20000)
	// Window "HH:MM-HH:MM" (UTC, may wrap midnight): syslog chunks start
	// only inside it. Empty = any time. Flows always run.
	Window string // ARCHIVE_WINDOW (default empty)
	// StagingDir holds each chunk's compressed objects between export and
	// upload: an absolute path, REQUIRED once a stream is enabled (no
	// default — a temp directory would sit in a container's writable layer,
	// often on the database's disk).
	StagingDir string // ARCHIVE_STAGING_DIR

	// Target is where the objects go: "s3" (S3-compatible object storage,
	// the ARCHIVE_S3_* keys) or "local" (a directory, LocalDir: a local
	// partition or a network share the HOST mounts and bind-mounts into the
	// container under AllowedRoot; the application never mounts anything).
	// The object layout below ARCHIVE_S3_PREFIX is the same for both.
	Target string // ARCHIVE_TARGET: s3 (default) or local
	// LocalDir is the local target's directory: an existing absolute path
	// under AllowedRoot, outside the database volume. Objects are written to
	// "<LocalDir>/<prefix>/<stream>/…".
	LocalDir string // ARCHIVE_LOCAL_DIR
	// AllowedRoot bounds every directory the admin form may choose (the
	// local target and the staging directory) and the local target itself:
	// a bind mount of the host's archive partition or share. Environment
	// only; blank is DefaultArchiveAllowedRoot.
	AllowedRoot string // ARCHIVE_ALLOWED_ROOT (default /archive)

	// Lab / self-hosted escape hatches (MinIO, Garage, SeaweedFS on a LAN).
	AllowHTTP            bool // ARCHIVE_ALLOW_HTTP (default false)
	AllowPrivateEndpoint bool // ARCHIVE_ALLOW_PRIVATE_ENDPOINT (default false)

	// invalid lists ARCHIVE_* values that were set but could not be parsed
	// (strictIntEnv / strictBoolEnv). They are fatal in Validate instead of
	// silently falling back to a default: "ARCHIVE_OBJECT_LOCK_DAYS=400d"
	// must not quietly mean "no Object Lock".
	invalid []string
	// envSet lists the ARCHIVE_* keys the environment set (EnvSet): the
	// admin form shows whether a value is the environment's or the default.
	envSet map[string]bool
}

// ARCHIVE_TARGET values.
const (
	ArchiveTargetS3    = "s3"
	ArchiveTargetLocal = "local"
)

// DefaultArchiveAllowedRoot is ARCHIVE_ALLOWED_ROOT when it is blank: a path
// inside the container, where docker-compose.override.yml bind-mounts the
// host's archive partition or share (docs/OPERATIONS.md).
const DefaultArchiveAllowedRoot = "/archive"

// ArchiveDatabaseDir is the database volume inside the container (the
// Dockerfile's /data, PGDATA /data/pgdata). Neither the local target nor the
// allowed root may lie in it: an archive on the database's own disk is no
// copy, and it would fill the disk the retention is protecting. A variable
// so tests can move it.
var ArchiveDatabaseDir = "/data"

// normalizeArchiveTarget is ARCHIVE_TARGET as read: trimmed, lower case,
// blank = s3.
func normalizeArchiveTarget(v string) string {
	if v = strings.ToLower(strings.TrimSpace(v)); v == "" {
		return ArchiveTargetS3
	}
	return v
}

// IsLocal reports whether the archive writes to a directory (ARCHIVE_TARGET
// local) rather than to S3.
func (a ArchiveConfig) IsLocal() bool { return a.Target == ArchiveTargetLocal }

// TargetName is ARCHIVE_TARGET, "s3" when unset.
func (a ArchiveConfig) TargetName() string { return normalizeArchiveTarget(a.Target) }

// Root is ARCHIVE_ALLOWED_ROOT, cleaned, or DefaultArchiveAllowedRoot when
// it is blank.
func (a ArchiveConfig) Root() string {
	if r := strings.TrimSpace(a.AllowedRoot); r != "" {
		return filepath.Clean(r)
	}
	return DefaultArchiveAllowedRoot
}

// pathWithin reports whether p is dir or below it (both clean and absolute).
func pathWithin(p, dir string) bool {
	if dir == "/" {
		return true
	}
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// ValidateAllowedRoot checks ARCHIVE_ALLOWED_ROOT: absolute, not "/", and
// neither inside nor containing the database volume.
func (a ArchiveConfig) ValidateAllowedRoot() error {
	raw := strings.TrimSpace(a.AllowedRoot)
	root := a.Root()
	db := filepath.Clean(ArchiveDatabaseDir)
	switch {
	case raw != "" && !filepath.IsAbs(raw):
		return fmt.Errorf("ARCHIVE_ALLOWED_ROOT must be an absolute path, got %q", raw)
	case root == "/":
		return fmt.Errorf("ARCHIVE_ALLOWED_ROOT must not be /: name the directory the host's archive volume is bind-mounted on, e.g. %s", DefaultArchiveAllowedRoot)
	case pathWithin(root, db) || pathWithin(db, root):
		return fmt.Errorf("ARCHIVE_ALLOWED_ROOT %s overlaps the database volume %s: bind-mount the archive volume elsewhere", root, db)
	}
	return nil
}

// CheckArchivePath checks a directory chosen for the archive (the local
// target, or a staging directory set from the admin form) by its text: an
// absolute, clean path at or under ARCHIVE_ALLOWED_ROOT and outside the
// database volume. key names the setting in the message. Symbolic links are
// resolved where the directory is used (internal/archive/local), since only
// the filesystem knows where one leads.
func (a ArchiveConfig) CheckArchivePath(key, p string) error {
	if err := a.ValidateAllowedRoot(); err != nil {
		return err
	}
	root := a.Root()
	switch {
	case p == "":
		return fmt.Errorf("%s is empty: choose a directory under %s", key, root)
	case !filepath.IsAbs(p):
		return fmt.Errorf("%s must be an absolute path, got %q", key, p)
	case filepath.Clean(p) != p:
		return fmt.Errorf("%s must be a clean path (no '..', '.', '//' or trailing '/'), got %q", key, p)
	case !pathWithin(p, root):
		return fmt.Errorf("%s %s is outside ARCHIVE_ALLOWED_ROOT %s: choose a directory under it (the host's archive volume is bind-mounted there)", key, p, root)
	case pathWithin(p, filepath.Clean(ArchiveDatabaseDir)):
		return fmt.Errorf("%s %s is on the database volume %s", key, p, ArchiveDatabaseDir)
	}
	return nil
}

// LocalBase is "<ARCHIVE_LOCAL_DIR>/<prefix>": the directory every object
// of a local target is under.
func (a ArchiveConfig) LocalBase() string {
	return filepath.Join(a.LocalDir, filepath.FromSlash(a.Prefix))
}

// ValidateTarget checks the keys the configured target needs, whether or not
// a stream is enabled (a restore needs them too): ValidateS3, or for a local
// target ValidateLocal.
func (a ArchiveConfig) ValidateTarget() error {
	switch a.TargetName() {
	case ArchiveTargetS3:
		return a.ValidateS3()
	case ArchiveTargetLocal:
		return a.ValidateLocal()
	}
	return fmt.Errorf("ARCHIVE_TARGET must be s3 or local, got %q", a.Target)
}

// ValidateLocal checks a local target: ARCHIVE_LOCAL_DIR under
// ARCHIVE_ALLOWED_ROOT (CheckArchivePath), the prefix, and no Object Lock
// (a directory has none: immutability is the storage's — ZFS snapshots, a
// WORM share; see docs/OPERATIONS.md).
func (a ArchiveConfig) ValidateLocal() error {
	if err := a.CheckArchivePath("ARCHIVE_LOCAL_DIR", a.LocalDir); err != nil {
		return err
	}
	if a.Prefix == "" {
		return fmt.Errorf("archive is enabled but ARCHIVE_S3_PREFIX is empty: the local target writes below <ARCHIVE_LOCAL_DIR>/<prefix> too (there is no default)")
	}
	if !ValidArchiveKeyPath(a.Prefix) {
		return fmt.Errorf("ARCHIVE_S3_PREFIX %q must be slash-separated segments of A-Z a-z 0-9 . _ - with no leading or trailing slash and no '.' or '..' segment", a.Prefix)
	}
	if a.ObjectLockDays != 0 || a.ObjectLockMode != "" {
		return fmt.Errorf("ARCHIVE_OBJECT_LOCK_DAYS / ARCHIVE_OBJECT_LOCK_MODE apply to an S3 target only; a local directory has no Object Lock: clear them and make the storage immutable instead (ZFS snapshots, a WORM share; docs/OPERATIONS.md)")
	}
	return nil
}

// validateStagingOverlap refuses a staging directory inside the local
// target's object tree, or the tree inside the staging directory (the
// workers clear their own entries from the staging directory).
func (a ArchiveConfig) validateStagingOverlap() error {
	if !a.IsLocal() || a.StagingDir == "" || a.LocalDir == "" || !filepath.IsAbs(a.StagingDir) {
		return nil
	}
	st, base := filepath.Clean(a.StagingDir), filepath.Clean(a.LocalBase())
	if pathWithin(st, base) || pathWithin(base, st) {
		return fmt.Errorf("ARCHIVE_STAGING_DIR %s and the local target's directory %s must not contain each other: choose two separate directories", st, base)
	}
	return nil
}

// MaxArchiveObjectLockDays is the longest Object Lock retention accepted:
// Backblaze B2's documented maximum (its Object Lock documentation: "between
// one and 3,000 days"). AWS allows longer; one
// limit for every service keeps a config portable between them.
const MaxArchiveObjectLockDays = 3000

// ARCHIVE_SEAL_REVERIFY values.
const (
	SealReverifyHead = "head"
	SealReverifyFull = "full"
)

// Enabled reports whether any archive stream is switched on.
func (a ArchiveConfig) Enabled() bool { return a.SyslogEnabled || a.FlowsEnabled }

// SealGrace is ARCHIVE_SEAL_GRACE_HOURS as a duration (48 h when unset): a
// month M is due to be sealed at the 1st of M+1, 00:00 UTC, plus it.
func (a ArchiveConfig) SealGrace() time.Duration {
	if a.SealGraceHours <= 0 {
		return 48 * time.Hour
	}
	return time.Duration(a.SealGraceHours) * time.Hour
}

// Secret is a credential that must never reach a log line, an error string or
// an API response by accident. Every fmt verb, encoding/json, encoding/text and
// log/slog render it as RedactedSecret; Reveal returns the value (to check
// that it is set, and for the S3 request signer).
type Secret string

// RedactedSecret is what a non-empty Secret renders as.
const RedactedSecret = "********"

// Reveal returns the plaintext value.
func (s Secret) Reveal() string { return string(s) }

func (s Secret) masked() string {
	if s == "" {
		return ""
	}
	return RedactedSecret
}

// Format implements fmt.Formatter for every verb (%v %+v %#v %s %q %x %d ...),
// including the error paths fmt takes for a mismatched verb, which would
// otherwise print the underlying string.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.masked()) }

// MarshalText implements encoding.TextMarshaler (and so encoding/json).
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.masked()), nil }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.masked()) }

var (
	archiveRegionRe = regexp.MustCompile(`^[a-z0-9-]{2,32}$`)
	// archiveBucketRe is the union of the bucket names the services the
	// archive supports accept (see validBucketName), not one service's rule.
	archiveBucketRe = regexp.MustCompile(`^[A-Za-z0-9-][A-Za-z0-9._-]{1,253}[A-Za-z0-9-]$`)
	// archiveKeyPathRe is the shape of ARCHIVE_S3_PREFIX and of every object
	// key path below it: slash-separated segments of [A-Za-z0-9._-]. "." and
	// ".." segments are rejected separately (ValidArchiveKeyPath).
	archiveKeyPathRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
)

// ValidArchiveKeyPath reports whether p is a slash-separated key path of
// [A-Za-z0-9._-] segments with no empty, "." or ".." segment and no leading or
// trailing slash. It is the rule for ARCHIVE_S3_PREFIX and for every key the
// S3 client writes below it.
func ValidArchiveKeyPath(p string) bool {
	if len(p) > 512 || !archiveKeyPathRe.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Validate checks the archive configuration. With both streams disabled it
// checks nothing (beyond the enable flags themselves parsing) and returns nil.
// Error text never contains the secret or the endpoint's userinfo.
func (a ArchiveConfig) Validate() error {
	for _, bad := range a.invalid {
		if strings.HasPrefix(bad, "ARCHIVE_SYSLOG_ENABLED=") || strings.HasPrefix(bad, "ARCHIVE_FLOWS_ENABLED=") {
			return fmt.Errorf("%s", bad)
		}
	}
	if !a.Enabled() {
		return nil
	}
	if len(a.invalid) > 0 {
		return fmt.Errorf("archive is enabled but %s", strings.Join(a.invalid, "; "))
	}
	if err := a.ValidateTarget(); err != nil {
		return err
	}
	if err := a.validateSchedule(); err != nil {
		return err
	}
	switch {
	case a.StagingDir == "":
		return fmt.Errorf("archive is enabled but ARCHIVE_STAGING_DIR is empty: set it to an absolute directory on a volume with room for a day of compressed syslog (there is no default)")
	case !filepath.IsAbs(a.StagingDir):
		return fmt.Errorf("ARCHIVE_STAGING_DIR must be an absolute path, got %q", a.StagingDir)
	}
	return a.validateStagingOverlap()
}

// validateSchedule checks the export pacing, seal and window keys.
func (a ArchiveConfig) validateSchedule() error {
	if a.MinAgeHours < 1 || a.MinAgeHours > 168 {
		return fmt.Errorf("ARCHIVE_MIN_AGE_HOURS must be 1-168, got %d", a.MinAgeHours)
	}
	if a.SealGraceHours < 6 || a.SealGraceHours > 168 {
		return fmt.Errorf("ARCHIVE_SEAL_GRACE_HOURS must be 6-168, got %d", a.SealGraceHours)
	}
	if a.SealReverify != SealReverifyHead && a.SealReverify != SealReverifyFull {
		return fmt.Errorf("ARCHIVE_SEAL_REVERIFY must be head or full, got %q", a.SealReverify)
	}
	for _, r := range []struct {
		key string
		val int
	}{{"ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC", a.SyslogRateRowsPerSec}, {"ARCHIVE_FLOW_RATE_ROWS_PER_SEC", a.FlowRateRowsPerSec}} {
		if r.val < 100 || r.val > 100000 {
			return fmt.Errorf("%s must be 100-100000, got %d", r.key, r.val)
		}
	}
	if _, _, _, err := a.WindowMinutes(); err != nil {
		return err
	}
	return nil
}

// WindowMinutes parses ARCHIVE_WINDOW ("HH:MM-HH:MM", UTC) into minutes
// since UTC midnight; start > end wraps past midnight. ok is false when the window
// is empty (no restriction).
func (a ArchiveConfig) WindowMinutes() (start, end int, ok bool, err error) {
	w := strings.TrimSpace(a.Window)
	if w == "" {
		return 0, 0, false, nil
	}
	from, to, found := strings.Cut(w, "-")
	if !found {
		return 0, 0, false, fmt.Errorf("ARCHIVE_WINDOW %q: want HH:MM-HH:MM", w)
	}
	hm := func(p string) (int, error) {
		t, err := time.Parse("15:04", strings.TrimSpace(p))
		if err != nil {
			return 0, fmt.Errorf("ARCHIVE_WINDOW %q: want HH:MM-HH:MM", w)
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	if start, err = hm(from); err != nil {
		return 0, 0, false, err
	}
	if end, err = hm(to); err != nil {
		return 0, 0, false, err
	}
	if start == end {
		return 0, 0, false, fmt.Errorf("ARCHIVE_WINDOW %q: start equals end", w)
	}
	return start, end, true, nil
}

// ValidateS3 checks the keys the S3 client needs, whether or not a stream is
// enabled (the client constructor calls it too). Every key is required.
func (a ArchiveConfig) ValidateS3() error {
	var missing []string
	for _, kv := range []struct{ key, val string }{
		{"ARCHIVE_S3_ENDPOINT", a.Endpoint},
		{"ARCHIVE_S3_REGION", a.Region},
		{"ARCHIVE_S3_BUCKET", a.Bucket},
		{"ARCHIVE_S3_PREFIX", a.Prefix},
		{"ARCHIVE_S3_ACCESS_KEY_ID", a.AccessKeyID},
		{"ARCHIVE_S3_SECRET_ACCESS_KEY", a.SecretAccessKey.Reveal()},
	} {
		if kv.val == "" {
			missing = append(missing, kv.key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("archive is enabled but required setting(s) are empty: %s (there are no defaults)", strings.Join(missing, ", "))
	}
	if _, err := a.EndpointURL(); err != nil {
		return err
	}
	if !archiveRegionRe.MatchString(a.Region) {
		return fmt.Errorf("ARCHIVE_S3_REGION must match %s, got %q", archiveRegionRe, a.Region)
	}
	if !validBucketName(a.Bucket) {
		return fmt.Errorf("ARCHIVE_S3_BUCKET %q is not a valid bucket name: 3-255 of A-Z a-z 0-9 . _ -, starting and ending with a letter, digit or '-', no '..', not an IP address (the storage service checks its own rules when you Test connection)", a.Bucket)
	}
	if !ValidArchiveKeyPath(a.Prefix) {
		return fmt.Errorf("ARCHIVE_S3_PREFIX %q must be slash-separated segments of A-Z a-z 0-9 . _ - with no leading or trailing slash and no '.' or '..' segment", a.Prefix)
	}
	if strings.ContainsAny(a.AccessKeyID, " \t\r\n") {
		return fmt.Errorf("ARCHIVE_S3_ACCESS_KEY_ID contains whitespace")
	}
	switch {
	case a.ObjectLockDays < 0 || a.ObjectLockDays > MaxArchiveObjectLockDays:
		return fmt.Errorf("ARCHIVE_OBJECT_LOCK_DAYS must be 0-%d, got %d", MaxArchiveObjectLockDays, a.ObjectLockDays)
	case a.ObjectLockDays > 0 && a.LockMode() == "":
		return fmt.Errorf("ARCHIVE_OBJECT_LOCK_DAYS=%d requires ARCHIVE_OBJECT_LOCK_MODE=GOVERNANCE or COMPLIANCE, got %q", a.ObjectLockDays, a.ObjectLockMode)
	case a.ObjectLockDays == 0 && a.ObjectLockMode != "":
		return fmt.Errorf("ARCHIVE_OBJECT_LOCK_MODE=%q is set but ARCHIVE_OBJECT_LOCK_DAYS is 0; set the days or clear the mode", a.ObjectLockMode)
	}
	return nil
}

// LockMode returns the Object Lock mode in its canonical upper-case form, or
// "" when it is not one of GOVERNANCE / COMPLIANCE.
func (a ArchiveConfig) LockMode() string {
	switch m := strings.ToUpper(a.ObjectLockMode); m {
	case "GOVERNANCE", "COMPLIANCE":
		return m
	}
	return ""
}

// EndpointURL parses ARCHIVE_S3_ENDPOINT: an absolute https URL naming a host
// (and optional port) only. http is accepted only with ARCHIVE_ALLOW_HTTP.
// Whether the host may be a private address is decided where the connection is
// made (internal/archive/s3), which pins every dial unless
// ARCHIVE_ALLOW_PRIVATE_ENDPOINT is set.
func (a ArchiveConfig) EndpointURL() (*url.URL, error) {
	u, err := url.Parse(a.Endpoint)
	if err != nil {
		// url.Error repeats the input, which may carry credentials.
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT is not a valid URL")
	}
	switch {
	case u.Scheme == "http" && !a.AllowHTTP:
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT uses http; use https, or set ARCHIVE_ALLOW_HTTP=true for a lab endpoint")
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT must be an absolute https:// URL")
	case u.User != nil:
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT must not contain credentials; use ARCHIVE_S3_ACCESS_KEY_ID / ARCHIVE_S3_SECRET_ACCESS_KEY")
	case u.Opaque != "" || u.Hostname() == "":
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT must name a host")
	case u.Path != "" && u.Path != "/":
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT must not have a path (the bucket is ARCHIVE_S3_BUCKET), got %q", u.Path)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT must not have a query or fragment")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT port must be 1-65535, got %q", p)
		}
	}
	u.Path = ""
	return u, nil
}

// validBucketName is a safety check, not any one service's naming rule: the
// service rejects a name it does not accept, and the preflight (Test
// connection, the save) shows its answer. It accepts every name the services
// the archive supports document (checked 2026-10-06):
//
//   - Backblaze B2: 6-63 of upper- and lower-case letters, digits, '-' and
//     '.'; may start or end with '-'; "not case sensitive, even though they
//     can include upper-case letters" — its console shows the name as
//     created ("Firewall-Mon"), its S3 API resolves any case of it;
//   - AWS S3: 3-63 of a-z 0-9 . -; buckets created in us-east-1 before
//     2018-03-01 may be up to 255 characters with upper case and '_';
//   - Cloudflare R2, DigitalOcean Spaces: 3-63 of a-z 0-9 -; Wasabi and
//     MinIO: the current AWS rule (MinIO's client also takes the legacy one).
//
// What it refuses is what could address something other than a bucket, or
// what no supported service documents: anything outside [A-Za-z0-9._-] ('/',
// '\', whitespace, '%', '?', '#', '@', ':' — a path, a URL or an "arn:"),
// '..', a leading or trailing '.' or '_' ("." and ".." are path segments),
// fewer than 3 or more than 255 characters, and an IP address.
//
// A name that is not a valid DNS label (upper case, '_', '.', longer than 63)
// is always sent path-style ("https://<endpoint>/<bucket>/<key>"): the AWS SDK
// falls back to it even with ARCHIVE_S3_PATH_STYLE=false
// (TestClient_NonDNSBucketIsPathStyle), so no name accepted here depends on
// virtual-hosted addressing.
func validBucketName(b string) bool {
	if !archiveBucketRe.MatchString(b) || strings.Contains(b, "..") {
		return false
	}
	return net.ParseIP(b) == nil
}

// SameBucket reports whether a and b name the same bucket. The comparison
// ignores case: Backblaze B2 resolves bucket names case-insensitively, and
// every other service the archive supports allows only lower-case names, so
// two spellings that differ only in case are the same bucket wherever both
// are valid. (A legacy AWS us-east-1 bucket or a MinIO bucket with upper case
// is the exception: the admin save checks that the archive's objects are
// visible under the new spelling before it accepts such a change.)
func SameBucket(a, b string) bool { return strings.EqualFold(a, b) }
