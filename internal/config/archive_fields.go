package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Admin-UI archive settings (A-10). Every ARCHIVE_* key can also be set on
// Settings → Retention; the value resolved for the archive is the admin
// setting when one is stored, else the environment value, else the built-in
// default — the repository's "admin-UI-managed settings with env as default"
// rule (v0.11.46). The environment is still read exactly as before
// (loadArchiveConfig), so an install that never saves the form behaves as an
// env-only one. ArchiveFields is the one list of keys both sides use; the
// admin settings are parsed by the same rules as the environment and checked
// by the same Validate.

// Kinds of an archive field's value.
const (
	ArchiveKindBool   = "bool"
	ArchiveKindInt    = "int"
	ArchiveKindString = "string"
	// ArchiveKindSecret is write-only: never rendered, never returned.
	ArchiveKindSecret = "secret"
)

// Sections of the admin form an archive field belongs to.
const (
	ArchiveSectionConnection = "connection"
	ArchiveSectionStreams    = "streams"
	ArchiveSectionObjectLock = "object_lock"
	ArchiveSectionSchedule   = "schedule"
	ArchiveSectionAdvanced   = "advanced"
)

// ArchiveField is one ARCHIVE_* key.
type ArchiveField struct {
	// Env is the environment key; the admin API names fields by it.
	Env     string
	Kind    string
	Section string
	// Location: the value is part of every object's location (endpoint,
	// bucket, prefix). Once the archive holds a chunk it cannot change from
	// the admin UI: the manifest's objects would point at the old place.
	Location bool
	// Connection: the value is used to reach the bucket (Test connection,
	// and the preflight a save runs while a stream is enabled).
	Connection bool
	get        func(ArchiveConfig) string
	set        func(*ArchiveConfig, string)
}

// Setting is the system_settings key holding the field's admin value: the
// environment key in lower case (ARCHIVE_S3_BUCKET → archive_s3_bucket).
func (f ArchiveField) Setting() string { return strings.ToLower(f.Env) }

func boolText(b bool) string { return strconv.FormatBool(b) }

// ArchiveFields lists every ARCHIVE_* key, in form order.
var ArchiveFields = []ArchiveField{
	{Env: "ARCHIVE_SYSLOG_ENABLED", Kind: ArchiveKindBool, Section: ArchiveSectionStreams,
		get: func(a ArchiveConfig) string { return boolText(a.SyslogEnabled) },
		set: func(a *ArchiveConfig, v string) { a.SyslogEnabled = v == "true" }},
	{Env: "ARCHIVE_FLOWS_ENABLED", Kind: ArchiveKindBool, Section: ArchiveSectionStreams,
		get: func(a ArchiveConfig) string { return boolText(a.FlowsEnabled) },
		set: func(a *ArchiveConfig, v string) { a.FlowsEnabled = v == "true" }},
	{Env: "ARCHIVE_STAGING_DIR", Kind: ArchiveKindString, Section: ArchiveSectionStreams,
		get: func(a ArchiveConfig) string { return a.StagingDir },
		set: func(a *ArchiveConfig, v string) { a.StagingDir = v }},

	{Env: "ARCHIVE_S3_ENDPOINT", Kind: ArchiveKindString, Section: ArchiveSectionConnection, Location: true, Connection: true,
		get: func(a ArchiveConfig) string { return a.Endpoint },
		set: func(a *ArchiveConfig, v string) { a.Endpoint = v }},
	{Env: "ARCHIVE_S3_REGION", Kind: ArchiveKindString, Section: ArchiveSectionConnection, Connection: true,
		get: func(a ArchiveConfig) string { return a.Region },
		set: func(a *ArchiveConfig, v string) { a.Region = v }},
	{Env: "ARCHIVE_S3_BUCKET", Kind: ArchiveKindString, Section: ArchiveSectionConnection, Location: true, Connection: true,
		get: func(a ArchiveConfig) string { return a.Bucket },
		set: func(a *ArchiveConfig, v string) { a.Bucket = v }},
	{Env: "ARCHIVE_S3_PREFIX", Kind: ArchiveKindString, Section: ArchiveSectionConnection, Location: true, Connection: true,
		get: func(a ArchiveConfig) string { return a.Prefix },
		set: func(a *ArchiveConfig, v string) { a.Prefix = v }},
	{Env: "ARCHIVE_S3_PATH_STYLE", Kind: ArchiveKindBool, Section: ArchiveSectionConnection, Connection: true,
		get: func(a ArchiveConfig) string { return boolText(a.PathStyle) },
		set: func(a *ArchiveConfig, v string) { a.PathStyle = v == "true" }},
	{Env: "ARCHIVE_S3_ACCESS_KEY_ID", Kind: ArchiveKindString, Section: ArchiveSectionConnection, Connection: true,
		get: func(a ArchiveConfig) string { return a.AccessKeyID },
		set: func(a *ArchiveConfig, v string) { a.AccessKeyID = v }},
	{Env: "ARCHIVE_S3_SECRET_ACCESS_KEY", Kind: ArchiveKindSecret, Section: ArchiveSectionConnection, Connection: true,
		get: func(ArchiveConfig) string { return "" },
		set: func(a *ArchiveConfig, v string) { a.SecretAccessKey = Secret(v) }},

	{Env: "ARCHIVE_OBJECT_LOCK_MODE", Kind: ArchiveKindString, Section: ArchiveSectionObjectLock, Connection: true,
		get: func(a ArchiveConfig) string { return a.ObjectLockMode },
		set: func(a *ArchiveConfig, v string) { a.ObjectLockMode = v }},
	{Env: "ARCHIVE_OBJECT_LOCK_DAYS", Kind: ArchiveKindInt, Section: ArchiveSectionObjectLock, Connection: true,
		get: func(a ArchiveConfig) string { return strconv.Itoa(a.ObjectLockDays) },
		set: func(a *ArchiveConfig, v string) { a.ObjectLockDays, _ = strconv.Atoi(v) }},

	{Env: "ARCHIVE_WINDOW", Kind: ArchiveKindString, Section: ArchiveSectionSchedule,
		get: func(a ArchiveConfig) string { return a.Window },
		set: func(a *ArchiveConfig, v string) { a.Window = v }},
	{Env: "ARCHIVE_MIN_AGE_HOURS", Kind: ArchiveKindInt, Section: ArchiveSectionSchedule,
		get: func(a ArchiveConfig) string { return strconv.Itoa(a.MinAgeHours) },
		set: func(a *ArchiveConfig, v string) { a.MinAgeHours, _ = strconv.Atoi(v) }},
	{Env: "ARCHIVE_SEAL_GRACE_HOURS", Kind: ArchiveKindInt, Section: ArchiveSectionSchedule,
		get: func(a ArchiveConfig) string { return strconv.Itoa(a.SealGraceHours) },
		set: func(a *ArchiveConfig, v string) { a.SealGraceHours, _ = strconv.Atoi(v) }},
	{Env: "ARCHIVE_SEAL_REVERIFY", Kind: ArchiveKindString, Section: ArchiveSectionSchedule,
		get: func(a ArchiveConfig) string { return a.SealReverify },
		set: func(a *ArchiveConfig, v string) {
			// As loadArchiveConfig: case-insensitive, blank = head.
			if a.SealReverify = strings.ToLower(v); a.SealReverify == "" {
				a.SealReverify = SealReverifyHead
			}
		}},
	{Env: "ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC", Kind: ArchiveKindInt, Section: ArchiveSectionSchedule,
		get: func(a ArchiveConfig) string { return strconv.Itoa(a.SyslogRateRowsPerSec) },
		set: func(a *ArchiveConfig, v string) { a.SyslogRateRowsPerSec, _ = strconv.Atoi(v) }},
	{Env: "ARCHIVE_FLOW_RATE_ROWS_PER_SEC", Kind: ArchiveKindInt, Section: ArchiveSectionSchedule,
		get: func(a ArchiveConfig) string { return strconv.Itoa(a.FlowRateRowsPerSec) },
		set: func(a *ArchiveConfig, v string) { a.FlowRateRowsPerSec, _ = strconv.Atoi(v) }},

	{Env: "ARCHIVE_ALLOW_HTTP", Kind: ArchiveKindBool, Section: ArchiveSectionAdvanced, Connection: true,
		get: func(a ArchiveConfig) string { return boolText(a.AllowHTTP) },
		set: func(a *ArchiveConfig, v string) { a.AllowHTTP = v == "true" }},
	{Env: "ARCHIVE_ALLOW_PRIVATE_ENDPOINT", Kind: ArchiveKindBool, Section: ArchiveSectionAdvanced, Connection: true,
		get: func(a ArchiveConfig) string { return boolText(a.AllowPrivateEndpoint) },
		set: func(a *ArchiveConfig, v string) { a.AllowPrivateEndpoint = v == "true" }},
}

// ArchiveFieldByEnv returns the field of an ARCHIVE_* key.
func ArchiveFieldByEnv(env string) (ArchiveField, bool) {
	for _, f := range ArchiveFields {
		if f.Env == env {
			return f, true
		}
	}
	return ArchiveField{}, false
}

// ParseArchiveValue normalizes a raw value of field f the way the
// environment is read: trimmed, and for a bool or int strictly parsed. set is
// false for a blank bool or int (it has no value: the next layer applies).
func ParseArchiveValue(f ArchiveField, raw string) (val string, set bool, err error) {
	v := strings.TrimSpace(raw)
	switch f.Kind {
	case ArchiveKindBool:
		if v == "" {
			return "", false, nil
		}
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			return "", false, fmt.Errorf("%s=%q is not a boolean (true/false)", f.Env, v)
		}
		return strconv.FormatBool(b), true, nil
	case ArchiveKindInt:
		if v == "" {
			return "", false, nil
		}
		n, perr := strconv.Atoi(v)
		if perr != nil {
			return "", false, fmt.Errorf("%s=%q is not an integer", f.Env, v)
		}
		return strconv.Itoa(n), true, nil
	}
	return v, true, nil
}

// Value is the field's value in a, as text ("" for the secret, always).
func (a ArchiveConfig) Value(f ArchiveField) string { return f.get(a) }

// WithSettings returns a copy of a with the admin settings applied: settings
// maps an ARCHIVE_* key to its stored value. A value that does not parse is
// recorded like a malformed environment value — Validate refuses it while a
// stream is enabled — and the field keeps its environment value.
func (a ArchiveConfig) WithSettings(settings map[string]string) ArchiveConfig {
	out := a
	out.invalid = append([]string(nil), a.invalid...)
	for _, f := range ArchiveFields {
		raw, ok := settings[f.Env]
		if !ok {
			continue
		}
		v, set, err := ParseArchiveValue(f, raw)
		if err != nil {
			// Starts with "KEY=" like an env entry: Validate refuses a
			// bad enable switch by that prefix even while the archive is off.
			out.invalid = append(out.invalid, err.Error()+" (admin setting)")
			continue
		}
		if set {
			f.set(&out, v)
		}
	}
	return out
}

// WithProblem returns a copy of a that Validate refuses with msg while a
// stream is enabled (a stored admin value that cannot be used, such as a
// secret that no longer decrypts).
func (a ArchiveConfig) WithProblem(msg string) ArchiveConfig {
	out := a
	out.invalid = append(append([]string(nil), a.invalid...), msg)
	return out
}

// EnvSet reports whether the environment (or CONFIG_FILE) set key to a
// non-blank value when the configuration was loaded.
func (a ArchiveConfig) EnvSet(key string) bool { return a.envSet[key] }

// archiveEnvSet records which ARCHIVE_* keys the environment sets.
func archiveEnvSet() map[string]bool {
	set := map[string]bool{}
	for _, f := range ArchiveFields {
		if strings.TrimSpace(os.Getenv(f.Env)) != "" {
			set[f.Env] = true
		}
	}
	return set
}

// ValidateDraft checks a configuration an admin is saving or testing. With a
// stream enabled it is Validate. With both off nothing is required yet, but
// what is filled in must already be valid: every malformed value, the S3 keys
// once all six are set, the schedule ranges and a staging path that is not
// absolute are refused.
func (a ArchiveConfig) ValidateDraft() error {
	if len(a.invalid) > 0 {
		return fmt.Errorf("%s", strings.Join(a.invalid, "; "))
	}
	if a.Enabled() {
		return a.Validate()
	}
	if a.s3Complete() {
		if err := a.ValidateS3(); err != nil {
			return err
		}
	}
	if err := a.validateSchedule(); err != nil {
		return err
	}
	if a.StagingDir != "" && !filepath.IsAbs(a.StagingDir) {
		return fmt.Errorf("ARCHIVE_STAGING_DIR must be an absolute path, got %q", a.StagingDir)
	}
	return nil
}

// s3Complete reports whether every required S3 key is set.
func (a ArchiveConfig) s3Complete() bool {
	return a.Endpoint != "" && a.Region != "" && a.Bucket != "" && a.Prefix != "" && a.AccessKeyID != "" && a.SecretAccessKey != ""
}

// SameLocation reports whether a and b write their objects to the same place:
// the same endpoint (scheme and host, compared as Validate canonicalizes it),
// bucket (SameBucket: case-insensitive) and prefix (case-sensitive: it is
// part of every object key).
func (a ArchiveConfig) SameLocation(b ArchiveConfig) bool {
	return canonicalEndpoint(a) == canonicalEndpoint(b) && SameBucket(a.Bucket, b.Bucket) && a.Prefix == b.Prefix
}

// SameLocationText compares two Location strings as SameLocation compares
// configurations: the bucket — the path segment after the endpoint — ignoring
// case, everything else exactly. A recorded location is kept as first written
// ("…/firewall-mon/…"); a configuration naming the bucket "Firewall-Mon" is
// still at it.
func SameLocationText(a, b string) bool {
	ea, ba, pa, okA := splitLocation(a)
	eb, bb, pb, okB := splitLocation(b)
	if !okA || !okB {
		return a == b
	}
	return ea == eb && SameBucket(ba, bb) && pa == pb
}

// LocationBucket is the bucket of a Location string ("" when it does not
// parse).
func LocationBucket(loc string) string {
	_, bucket, _, _ := splitLocation(loc)
	return bucket
}

// splitLocation splits "<scheme>://<host>/<bucket>/<prefix>/" into its
// endpoint, bucket and the rest.
func splitLocation(loc string) (endpoint, bucket, rest string, ok bool) {
	scheme, after, found := strings.Cut(loc, "://")
	if !found {
		return "", "", "", false
	}
	host, path, found := strings.Cut(after, "/")
	if !found {
		return "", "", "", false
	}
	bucket, rest, found = strings.Cut(path, "/")
	if !found || bucket == "" {
		return "", "", "", false
	}
	return scheme + "://" + host, bucket, rest, true
}

// Location is "<endpoint>/<bucket>/<prefix>/", the endpoint as
// canonicalEndpoint gives it: where the archive's objects are.
func (a ArchiveConfig) Location() string {
	return canonicalEndpoint(a) + "/" + a.Bucket + "/" + a.Prefix + "/"
}

func canonicalEndpoint(a ArchiveConfig) string {
	if u, err := a.EndpointURL(); err == nil {
		return strings.ToLower(u.Scheme + "://" + u.Host)
	}
	return a.Endpoint
}

// WithArchive returns a shallow copy of c whose Archive is a: the resolved
// archive configuration for one request or tick, leaving c (the
// environment's) untouched.
func (c *Config) WithArchive(a ArchiveConfig) *Config {
	cp := *c
	cp.Archive = a
	return &cp
}
