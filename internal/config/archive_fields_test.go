package config

import (
	"sort"
	"strings"
	"testing"
)

// TestArchiveFields_CoverEveryKey: the admin form's field list is exactly the
// ARCHIVE_* keys the environment reads, so no key is env-only by omission.
func TestArchiveFields_CoverEveryKey(t *testing.T) {
	var got []string
	for _, f := range ArchiveFields {
		got = append(got, f.Env)
		if f.Setting() != strings.ToLower(f.Env) {
			t.Errorf("%s: setting key %q", f.Env, f.Setting())
		}
	}
	want := append([]string(nil), archiveKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ArchiveFields = %v\nthe env keys = %v", got, want)
	}
}

// TestArchiveConfig_WithSettingsPrecedence: an admin setting wins over the
// environment, the environment over the built-in default, and an absent
// setting leaves the environment's value; EnvSet says which keys the
// environment set.
func TestArchiveConfig_WithSettingsPrecedence(t *testing.T) {
	env := validArchiveEnv()
	delete(env, "ARCHIVE_S3_REGION")
	setArchiveEnv(t, env)
	a := Load().Archive
	if !a.EnvSet("ARCHIVE_S3_BUCKET") || a.EnvSet("ARCHIVE_S3_REGION") || a.EnvSet("ARCHIVE_MIN_AGE_HOURS") {
		t.Fatalf("EnvSet: bucket %v region %v min age %v", a.EnvSet("ARCHIVE_S3_BUCKET"), a.EnvSet("ARCHIVE_S3_REGION"), a.EnvSet("ARCHIVE_MIN_AGE_HOURS"))
	}
	r := a.WithSettings(map[string]string{
		"ARCHIVE_S3_BUCKET":                "example-bucket-ui", // ui over env
		"ARCHIVE_S3_REGION":                "us-west-004",       // ui over none
		"ARCHIVE_MIN_AGE_HOURS":            " 6 ",               // ui over default, trimmed
		"ARCHIVE_S3_PATH_STYLE":            "false",
		"ARCHIVE_WINDOW":                   "",     // an empty admin value is a value
		"ARCHIVE_SEAL_REVERIFY":            "FULL", // case as the env
		"ARCHIVE_S3_SECRET_ACCESS_KEY":     "fake-ui-secret",
		"ARCHIVE_SYSLOG_RATE_ROWS_PER_SEC": "", // a blank number has no value: env/default applies
	})
	switch {
	case r.Bucket != "example-bucket-ui", r.Region != "us-west-004", r.MinAgeHours != 6, r.PathStyle,
		r.SealReverify != SealReverifyFull, r.SecretAccessKey.Reveal() != "fake-ui-secret", r.SyslogRateRowsPerSec != 5000:
		t.Fatalf("resolved %+v", r)
	case r.Prefix != "fwmon/site-a" || r.ObjectLockDays != 400:
		t.Fatalf("an absent setting must keep the env value: %+v", r)
	}
	if a.Bucket != "example-bucket" || a.SecretAccessKey.Reveal() != archiveTestSecret {
		t.Fatal("WithSettings changed its receiver")
	}
	w := a
	w.Window = "01:00-05:00"
	if got := w.WithSettings(map[string]string{"ARCHIVE_WINDOW": ""}); got.Window != "" {
		t.Fatalf("an empty admin window must override the env's: %q", got.Window)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate(resolved) = %v", err)
	}
}

// TestArchiveConfig_WithSettingsInvalid: a stored value that does not parse
// is refused by the same Validate as a malformed env value, and the field
// keeps its env value meanwhile; the receiver's list is not shared.
func TestArchiveConfig_WithSettingsInvalid(t *testing.T) {
	setArchiveEnv(t, validArchiveEnv())
	a := Load().Archive
	r := a.WithSettings(map[string]string{"ARCHIVE_OBJECT_LOCK_DAYS": "400d"})
	if r.ObjectLockDays != 400 {
		t.Fatalf("days = %d, want the env's 400 kept", r.ObjectLockDays)
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "ARCHIVE_OBJECT_LOCK_DAYS") {
		t.Fatalf("Validate = %v, want the bad admin value named", err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("the receiver picked up the invalid entry: %v", err)
	}
	if err := a.WithProblem("the stored secret cannot be decrypted").Validate(); err == nil {
		t.Fatal("WithProblem was not refused")
	}
	// An unparseable enable switch is refused even with the archive off.
	off := a.WithSettings(map[string]string{"ARCHIVE_SYSLOG_ENABLED": "false"})
	if err := off.Validate(); err != nil {
		t.Fatalf("archive off: %v", err)
	}
	if err := off.WithSettings(map[string]string{"ARCHIVE_FLOWS_ENABLED": "yes please"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "(admin setting)") {
		t.Fatalf("an unparseable switch with the archive off: %v", err)
	}
}

// TestArchiveConfig_ValidateDraft: with both streams off nothing is required,
// but what is filled in must be valid; enabled it is Validate.
func TestArchiveConfig_ValidateDraft(t *testing.T) {
	setArchiveEnv(t, nil)
	a := Load().Archive
	if err := a.ValidateDraft(); err != nil {
		t.Fatalf("empty draft: %v", err)
	}
	if err := a.WithSettings(map[string]string{"ARCHIVE_S3_BUCKET": "example-bucket"}).ValidateDraft(); err != nil {
		t.Fatalf("a partial connection while off: %v", err)
	}
	for name, s := range map[string]map[string]string{
		"bad min age":    {"ARCHIVE_MIN_AGE_HOURS": "0"},
		"bad window":     {"ARCHIVE_WINDOW": "1am-5am"},
		"relative stage": {"ARCHIVE_STAGING_DIR": "staging"},
		"not a number":   {"ARCHIVE_FLOW_RATE_ROWS_PER_SEC": "fast"},
	} {
		if err := a.WithSettings(s).ValidateDraft(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	full := validArchiveEnv()
	delete(full, "ARCHIVE_SYSLOG_ENABLED")
	full["ARCHIVE_S3_REGION"] = "Not A Region"
	if err := a.WithSettings(full).ValidateDraft(); err == nil || !strings.Contains(err.Error(), "ARCHIVE_S3_REGION") {
		t.Fatalf("a complete but invalid connection while off: %v", err)
	}
	full["ARCHIVE_S3_REGION"] = "us-east-005"
	full["ARCHIVE_FLOWS_ENABLED"] = "true"
	delete(full, "ARCHIVE_STAGING_DIR")
	if err := a.WithSettings(full).ValidateDraft(); err == nil || !strings.Contains(err.Error(), "ARCHIVE_STAGING_DIR") {
		t.Fatalf("enabled without staging: %v", err)
	}
}

// TestArchiveConfig_SameLocation: endpoint (canonicalized), bucket and prefix
// decide where objects go; other keys do not.
func TestArchiveConfig_SameLocation(t *testing.T) {
	a := ArchiveConfig{Endpoint: "https://s3.example.com", Bucket: "example-bucket", Prefix: "fwmon"}
	for name, tc := range map[string]struct {
		b    ArchiveConfig
		same bool
	}{
		"identical":      {a, true},
		"trailing slash": {ArchiveConfig{Endpoint: "https://S3.example.com/", Bucket: "example-bucket", Prefix: "fwmon", Region: "x"}, true},
		"endpoint":       {ArchiveConfig{Endpoint: "https://s3.example.net", Bucket: "example-bucket", Prefix: "fwmon"}, false},
		"bucket":         {ArchiveConfig{Endpoint: "https://s3.example.com", Bucket: "example-bucket-2", Prefix: "fwmon"}, false},
		"prefix":         {ArchiveConfig{Endpoint: "https://s3.example.com", Bucket: "example-bucket", Prefix: "fwmon/b"}, false},
		// B2 resolves bucket names in any case: a re-cased name is the same
		// bucket. The prefix is part of every key: its case matters.
		"bucket case": {ArchiveConfig{Endpoint: "https://s3.example.com", Bucket: "Example-Bucket", Prefix: "fwmon"}, true},
		"prefix case": {ArchiveConfig{Endpoint: "https://s3.example.com", Bucket: "example-bucket", Prefix: "FWMON"}, false},
	} {
		if got := a.SameLocation(tc.b); got != tc.same {
			t.Errorf("%s: SameLocation = %v", name, got)
		}
	}
}

// TestSameLocationText: a recorded location string compares as SameLocation
// does — the bucket segment in any case, the endpoint and prefix exactly.
func TestSameLocationText(t *testing.T) {
	const rec = "https://s3.us-west-002.example.com/firewall-mon/fwmon/"
	for loc, same := range map[string]bool{
		rec: true,
		"https://s3.us-west-002.example.com/Firewall-Mon/fwmon/":   true,
		"https://s3.us-west-002.example.com/FIREWALL-MON/fwmon/":   true,
		"https://s3.us-west-002.example.com/firewall-mon/FWMON/":   false,
		"https://s3.us-west-002.example.com/firewall-mon2/fwmon/":  false,
		"https://s3.us-west-002.example.net/firewall-mon/fwmon/":   false,
		"http://s3.us-west-002.example.com/firewall-mon/fwmon/":    false,
		"https://s3.us-west-002.example.com/firewall-mon/fwmon/b/": false,
		"not a location": false,
	} {
		if got := SameLocationText(rec, loc); got != same {
			t.Errorf("SameLocationText(%s, %s) = %v, want %v", rec, loc, got, same)
		}
	}
	// Built from configurations, the strings agree with SameLocation.
	a := ArchiveConfig{Endpoint: "https://s3.example.com", Bucket: "firewall-mon", Prefix: "fwmon"}
	b := a
	b.Bucket = "Firewall-Mon"
	if !SameLocationText(a.Location(), b.Location()) || !a.SameLocation(b) {
		t.Errorf("re-cased bucket: %s vs %s not the same location", a.Location(), b.Location())
	}
}
