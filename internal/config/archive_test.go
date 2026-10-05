package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const archiveTestSecret = "TESTSECRETdoNotLeak0123456789abcdefABCDEF"

var archiveKeys = []string{
	"ARCHIVE_SYSLOG_ENABLED", "ARCHIVE_FLOWS_ENABLED", "ARCHIVE_S3_ENDPOINT", "ARCHIVE_S3_REGION",
	"ARCHIVE_S3_BUCKET", "ARCHIVE_S3_PREFIX", "ARCHIVE_S3_ACCESS_KEY_ID", "ARCHIVE_S3_SECRET_ACCESS_KEY",
	"ARCHIVE_S3_PATH_STYLE", "ARCHIVE_OBJECT_LOCK_DAYS", "ARCHIVE_OBJECT_LOCK_MODE", "ARCHIVE_MIN_AGE_HOURS",
	"ARCHIVE_ALLOW_HTTP", "ARCHIVE_ALLOW_PRIVATE_ENDPOINT",
}

// setArchiveEnv clears every ARCHIVE_* key, then sets kv.
func setArchiveEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range archiveKeys {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func validArchiveEnv() map[string]string {
	return map[string]string{
		"ARCHIVE_SYSLOG_ENABLED":       "true",
		"ARCHIVE_S3_ENDPOINT":          "https://s3.us-east-005.example.com",
		"ARCHIVE_S3_REGION":            "us-east-005",
		"ARCHIVE_S3_BUCKET":            "example-bucket",
		"ARCHIVE_S3_PREFIX":            "fwmon/site-a",
		"ARCHIVE_S3_ACCESS_KEY_ID":     "005exampleKeyID",
		"ARCHIVE_S3_SECRET_ACCESS_KEY": archiveTestSecret,
		"ARCHIVE_OBJECT_LOCK_DAYS":     "400",
		"ARCHIVE_OBJECT_LOCK_MODE":     "governance",
	}
}

// TestArchiveConfig_DefaultsNameNoService: unset, the archive is off, every
// connection key is empty (no default points at any service), and Validate
// passes — the disabled path changes nothing.
func TestArchiveConfig_DefaultsNameNoService(t *testing.T) {
	setArchiveEnv(t, nil)
	a := Load().Archive
	if a.Enabled() {
		t.Error("archive enabled by default")
	}
	if a.Endpoint != "" || a.Region != "" || a.Bucket != "" || a.Prefix != "" || a.AccessKeyID != "" || a.SecretAccessKey != "" || a.ObjectLockMode != "" {
		t.Errorf("connection keys have defaults: %+v", a)
	}
	if !a.PathStyle || a.MinAgeHours != 2 || a.ObjectLockDays != 0 || a.AllowHTTP || a.AllowPrivateEndpoint {
		t.Errorf("defaults = %+v", a)
	}
	if err := a.Validate(); err != nil {
		t.Errorf("Validate (disabled) = %v", err)
	}
}

// TestArchiveConfig_DisabledIgnoresOtherKeys: with both streams off, invalid
// connection keys are not checked (no behaviour change for an install that
// has not opted in).
func TestArchiveConfig_DisabledIgnoresOtherKeys(t *testing.T) {
	setArchiveEnv(t, map[string]string{
		"ARCHIVE_S3_ENDPOINT":      "http://bad host/x",
		"ARCHIVE_OBJECT_LOCK_DAYS": "400d",
		"ARCHIVE_MIN_AGE_HOURS":    "0",
	})
	if err := Load().Archive.Validate(); err != nil {
		t.Errorf("Validate (disabled) = %v", err)
	}
}

func TestArchiveConfig_ValidEnabled(t *testing.T) {
	for _, flag := range []string{"ARCHIVE_SYSLOG_ENABLED", "ARCHIVE_FLOWS_ENABLED"} {
		env := validArchiveEnv()
		delete(env, "ARCHIVE_SYSLOG_ENABLED")
		env[flag] = "true"
		setArchiveEnv(t, env)
		a := Load().Archive
		if err := a.Validate(); err != nil {
			t.Fatalf("%s: Validate = %v", flag, err)
		}
		if a.LockMode() != "GOVERNANCE" || a.ObjectLockDays != 400 || a.SecretAccessKey.Reveal() != archiveTestSecret {
			t.Errorf("%s: loaded %+v", flag, a)
		}
	}
}

// TestArchiveConfig_RequiredWhenEnabled: every connection key is required and
// named in the error.
func TestArchiveConfig_RequiredWhenEnabled(t *testing.T) {
	setArchiveEnv(t, map[string]string{"ARCHIVE_FLOWS_ENABLED": "true"})
	err := Load().Archive.Validate()
	if err == nil {
		t.Fatal("Validate accepted an enabled archive with no settings")
	}
	for _, k := range []string{"ARCHIVE_S3_ENDPOINT", "ARCHIVE_S3_REGION", "ARCHIVE_S3_BUCKET", "ARCHIVE_S3_PREFIX", "ARCHIVE_S3_ACCESS_KEY_ID", "ARCHIVE_S3_SECRET_ACCESS_KEY"} {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("error %q does not name %s", err, k)
		}
	}
	// Each one on its own.
	for _, k := range []string{"ARCHIVE_S3_ENDPOINT", "ARCHIVE_S3_REGION", "ARCHIVE_S3_BUCKET", "ARCHIVE_S3_PREFIX", "ARCHIVE_S3_ACCESS_KEY_ID", "ARCHIVE_S3_SECRET_ACCESS_KEY"} {
		env := validArchiveEnv()
		delete(env, k)
		setArchiveEnv(t, env)
		if err := Load().Archive.Validate(); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("without %s: Validate = %v", k, err)
		}
	}
	// Config.Validate (the startup gate) surfaces it.
	setArchiveEnv(t, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "true"})
	if err := Load().Validate(); err == nil || !strings.Contains(err.Error(), "ARCHIVE_S3_ENDPOINT") {
		t.Errorf("Config.Validate = %v, want the archive error", err)
	}
}

func TestArchiveConfig_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name, key, val, want string
	}{
		{"http endpoint", "ARCHIVE_S3_ENDPOINT", "http://s3.example.com", "ARCHIVE_ALLOW_HTTP"},
		{"ftp endpoint", "ARCHIVE_S3_ENDPOINT", "ftp://s3.example.com", "https://"},
		{"relative endpoint", "ARCHIVE_S3_ENDPOINT", "s3.example.com", "https://"},
		{"endpoint userinfo", "ARCHIVE_S3_ENDPOINT", "https://alice:" + archiveTestSecret + "@s3.example.com", "credentials"},
		{"endpoint path", "ARCHIVE_S3_ENDPOINT", "https://s3.example.com/example-bucket", "path"},
		{"endpoint query", "ARCHIVE_S3_ENDPOINT", "https://s3.example.com?x=1", "query"},
		{"endpoint fragment", "ARCHIVE_S3_ENDPOINT", "https://s3.example.com#x", "fragment"},
		{"endpoint no host", "ARCHIVE_S3_ENDPOINT", "https://", "host"},
		{"endpoint port", "ARCHIVE_S3_ENDPOINT", "https://s3.example.com:0", "port"},
		{"region case", "ARCHIVE_S3_REGION", "US-East-005", "ARCHIVE_S3_REGION"},
		{"region chars", "ARCHIVE_S3_REGION", "us_east", "ARCHIVE_S3_REGION"},
		{"bucket case", "ARCHIVE_S3_BUCKET", "Example-Bucket", "ARCHIVE_S3_BUCKET"},
		{"bucket short", "ARCHIVE_S3_BUCKET", "ab", "ARCHIVE_S3_BUCKET"},
		{"bucket dots", "ARCHIVE_S3_BUCKET", "a..b", "ARCHIVE_S3_BUCKET"},
		{"bucket ip", "ARCHIVE_S3_BUCKET", "192.0.2.10", "ARCHIVE_S3_BUCKET"},
		{"bucket dash", "ARCHIVE_S3_BUCKET", "bucket-", "ARCHIVE_S3_BUCKET"},
		{"prefix leading slash", "ARCHIVE_S3_PREFIX", "/fwmon", "ARCHIVE_S3_PREFIX"},
		{"prefix trailing slash", "ARCHIVE_S3_PREFIX", "fwmon/", "ARCHIVE_S3_PREFIX"},
		{"prefix dotdot", "ARCHIVE_S3_PREFIX", "fwmon/../x", "ARCHIVE_S3_PREFIX"},
		{"prefix dot", "ARCHIVE_S3_PREFIX", "./fwmon", "ARCHIVE_S3_PREFIX"},
		{"prefix empty seg", "ARCHIVE_S3_PREFIX", "a//b", "ARCHIVE_S3_PREFIX"},
		{"prefix space", "ARCHIVE_S3_PREFIX", "a b", "ARCHIVE_S3_PREFIX"},
		{"key id space", "ARCHIVE_S3_ACCESS_KEY_ID", "ab cd", "ARCHIVE_S3_ACCESS_KEY_ID"},
		{"lock days malformed", "ARCHIVE_OBJECT_LOCK_DAYS", "400d", "ARCHIVE_OBJECT_LOCK_DAYS"},
		{"lock days negative", "ARCHIVE_OBJECT_LOCK_DAYS", "-1", "ARCHIVE_OBJECT_LOCK_DAYS"},
		{"lock days above B2 max", "ARCHIVE_OBJECT_LOCK_DAYS", "3001", "ARCHIVE_OBJECT_LOCK_DAYS"},
		{"lock mode bad", "ARCHIVE_OBJECT_LOCK_MODE", "LEGAL", "ARCHIVE_OBJECT_LOCK_MODE"},
		{"lock mode empty", "ARCHIVE_OBJECT_LOCK_MODE", "", "ARCHIVE_OBJECT_LOCK_MODE"},
		{"min age zero", "ARCHIVE_MIN_AGE_HOURS", "0", "ARCHIVE_MIN_AGE_HOURS"},
		{"min age big", "ARCHIVE_MIN_AGE_HOURS", "169", "ARCHIVE_MIN_AGE_HOURS"},
		{"min age malformed", "ARCHIVE_MIN_AGE_HOURS", "2h", "ARCHIVE_MIN_AGE_HOURS"},
		{"path style malformed", "ARCHIVE_S3_PATH_STYLE", "yes", "ARCHIVE_S3_PATH_STYLE"},
		{"allow http malformed", "ARCHIVE_ALLOW_HTTP", "on", "ARCHIVE_ALLOW_HTTP"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := validArchiveEnv()
			env[c.key] = c.val
			setArchiveEnv(t, env)
			err := Load().Archive.Validate()
			if err == nil {
				t.Fatalf("%s=%q accepted", c.key, c.val)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s=%q: error %q does not mention %q", c.key, c.val, err, c.want)
			}
			if strings.Contains(err.Error(), archiveTestSecret) {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}

	// Mode without days.
	env := validArchiveEnv()
	env["ARCHIVE_OBJECT_LOCK_DAYS"] = "0"
	setArchiveEnv(t, env)
	if err := Load().Archive.Validate(); err == nil || !strings.Contains(err.Error(), "ARCHIVE_OBJECT_LOCK_DAYS is 0") {
		t.Errorf("mode without days: %v", err)
	}
	// A malformed enable flag is fatal even though it leaves the archive off.
	setArchiveEnv(t, map[string]string{"ARCHIVE_SYSLOG_ENABLED": "yes"})
	if err := Load().Archive.Validate(); err == nil || !strings.Contains(err.Error(), "ARCHIVE_SYSLOG_ENABLED") {
		t.Errorf("malformed enable flag: %v", err)
	}
	// The B2 maximum itself is accepted.
	env = validArchiveEnv()
	env["ARCHIVE_OBJECT_LOCK_DAYS"] = "3000"
	setArchiveEnv(t, env)
	if err := Load().Archive.Validate(); err != nil {
		t.Errorf("lock days 3000: %v", err)
	}
	// http is accepted with the escape hatch.
	env = validArchiveEnv()
	env["ARCHIVE_S3_ENDPOINT"], env["ARCHIVE_ALLOW_HTTP"] = "http://192.0.2.10:9000", "true"
	setArchiveEnv(t, env)
	if err := Load().Archive.Validate(); err != nil {
		t.Errorf("http with ARCHIVE_ALLOW_HTTP: %v", err)
	}
}

// TestArchiveConfig_SecretNeverRendered: the secret does not appear through
// any fmt verb (on the Secret, the ArchiveConfig or the whole Config), JSON or
// slog.
func TestArchiveConfig_SecretNeverRendered(t *testing.T) {
	setArchiveEnv(t, validArchiveEnv())
	cfg := Load()
	a := cfg.Archive
	if a.SecretAccessKey.Reveal() != archiveTestSecret {
		t.Fatal("secret not loaded")
	}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T %v"} {
		out = append(out,
			fmt.Sprintf(verb, a.SecretAccessKey),
			fmt.Sprintf(verb, a),
			fmt.Sprintf(verb, &a),
			fmt.Sprintf(verb, cfg),
			fmt.Sprintf(verb, *cfg),
		)
	}
	out = append(out, fmt.Sprint(a.SecretAccessKey), fmt.Sprintln(a))
	for _, v := range []any{a.SecretAccessKey, a, cfg} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		out = append(out, string(b))
	}
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	lg.Info("cfg", "secret", a.SecretAccessKey, "archive", a)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "secret", a.SecretAccessKey, "archive", a)
	out = append(out, buf.String())

	for _, s := range out {
		if strings.Contains(s, archiveTestSecret) || strings.Contains(s, fmt.Sprintf("%x", archiveTestSecret)) {
			t.Errorf("secret rendered: %s", s)
		}
	}
	if got := fmt.Sprint(a.SecretAccessKey); got != RedactedSecret {
		t.Errorf("Sprint(secret) = %q, want the mask", got)
	}
	if got := fmt.Sprint(Secret("")); got != "" {
		t.Errorf("Sprint(empty secret) = %q, want empty", got)
	}
}
