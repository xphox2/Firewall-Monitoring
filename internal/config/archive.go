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
// storage (ARCHIVE_* env; archive plan PR 2). It is read from the environment
// or CONFIG_FILE only, never from the admin UI.
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

	// Lab / self-hosted escape hatches (MinIO, Garage, SeaweedFS on a LAN).
	AllowHTTP            bool // ARCHIVE_ALLOW_HTTP (default false)
	AllowPrivateEndpoint bool // ARCHIVE_ALLOW_PRIVATE_ENDPOINT (default false)

	// invalid lists ARCHIVE_* values that were set but could not be parsed
	// (strictIntEnv / strictBoolEnv). They are fatal in Validate instead of
	// silently falling back to a default: "ARCHIVE_OBJECT_LOCK_DAYS=400d"
	// must not quietly mean "no Object Lock".
	invalid []string
}

// MaxArchiveObjectLockDays is the longest Object Lock retention accepted:
// Backblaze B2's documented maximum (its Object Lock documentation: "between
// one and 3,000 days"). AWS allows longer; one
// limit for every service keeps a config portable between them.
const MaxArchiveObjectLockDays = 3000

// Enabled reports whether any archive stream is switched on.
func (a ArchiveConfig) Enabled() bool { return a.SyslogEnabled || a.FlowsEnabled }

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
	archiveBucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
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
	if err := a.ValidateS3(); err != nil {
		return err
	}
	if a.MinAgeHours < 1 || a.MinAgeHours > 168 {
		return fmt.Errorf("ARCHIVE_MIN_AGE_HOURS must be 1-168, got %d", a.MinAgeHours)
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
	switch {
	case a.StagingDir == "":
		return fmt.Errorf("archive is enabled but ARCHIVE_STAGING_DIR is empty: set it to an absolute directory on a volume with room for a day of compressed syslog (there is no default)")
	case !filepath.IsAbs(a.StagingDir):
		return fmt.Errorf("ARCHIVE_STAGING_DIR must be an absolute path, got %q", a.StagingDir)
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
		return fmt.Errorf("ARCHIVE_S3_BUCKET %q is not a valid bucket name (3-63 of a-z 0-9 . -, starting and ending with a letter or digit, no '..', not an IP address)", a.Bucket)
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

func validBucketName(b string) bool {
	if !archiveBucketRe.MatchString(b) || strings.Contains(b, "..") ||
		strings.Contains(b, ".-") || strings.Contains(b, "-.") {
		return false
	}
	return net.ParseIP(b) == nil
}
