package config

import (
	"strings"
	"testing"
)

// The local target's configuration (0.11.315): ARCHIVE_TARGET,
// ARCHIVE_LOCAL_DIR and the environment-only ARCHIVE_ALLOWED_ROOT.

// localArchiveEnv is a valid local target with the syslog stream on.
func localArchiveEnv() map[string]string {
	return map[string]string{
		"ARCHIVE_SYSLOG_ENABLED": "true",
		"ARCHIVE_TARGET":         "LOCAL",
		"ARCHIVE_LOCAL_DIR":      "/archive/nfs-share",
		"ARCHIVE_S3_PREFIX":      "fwmon/site-a",
		"ARCHIVE_STAGING_DIR":    "/archive/staging",
	}
}

// TestArchiveConfig_LocalTarget: loaded from the environment (the target
// case-insensitive, the root defaulting to /archive) a local target needs no
// S3 key and validates; the S3 target stays the default.
func TestArchiveConfig_LocalTarget(t *testing.T) {
	setArchiveEnv(t, localArchiveEnv())
	a := Load().Archive
	if !a.IsLocal() || a.TargetName() != "local" || a.Root() != DefaultArchiveAllowedRoot || a.LocalBase() != "/archive/nfs-share/fwmon/site-a" {
		t.Fatalf("loaded %+v (root %s, base %s)", a, a.Root(), a.LocalBase())
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := a.ValidateTarget(); err != nil {
		t.Fatalf("ValidateTarget: %v", err)
	}
	if a.Location() != "file:///archive/nfs-share/fwmon/site-a/" {
		t.Fatalf("Location %q", a.Location())
	}
	setArchiveEnv(t, nil)
	if d := Load().Archive; d.TargetName() != ArchiveTargetS3 || d.IsLocal() || d.Value(mustField(t, "ARCHIVE_TARGET")) != "s3" {
		t.Fatalf("default target %q", d.Target)
	}
}

func mustField(t *testing.T, env string) ArchiveField {
	t.Helper()
	f, ok := ArchiveFieldByEnv(env)
	if !ok {
		t.Fatalf("no field %s", env)
	}
	return f
}

// TestArchiveConfig_LocalTargetRefusals: every way a local directory could
// escape the allowed root, land on the database volume, or mix with S3-only
// settings is refused, naming the key.
func TestArchiveConfig_LocalTargetRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		set  map[string]string
		want string
	}{
		"no dir":           {map[string]string{"ARCHIVE_LOCAL_DIR": ""}, "ARCHIVE_LOCAL_DIR is empty"},
		"relative":         {map[string]string{"ARCHIVE_LOCAL_DIR": "archive/x"}, "absolute"},
		"dotdot":           {map[string]string{"ARCHIVE_LOCAL_DIR": "/archive/../etc"}, "clean path"},
		"trailing slash":   {map[string]string{"ARCHIVE_LOCAL_DIR": "/archive/x/"}, "clean path"},
		"outside root":     {map[string]string{"ARCHIVE_LOCAL_DIR": "/srv/archive"}, "outside ARCHIVE_ALLOWED_ROOT"},
		"sibling of root":  {map[string]string{"ARCHIVE_LOCAL_DIR": "/archive-other"}, "outside ARCHIVE_ALLOWED_ROOT"},
		"database volume":  {map[string]string{"ARCHIVE_ALLOWED_ROOT": "/", "ARCHIVE_LOCAL_DIR": "/data/archive"}, "must not be /"},
		"root on db":       {map[string]string{"ARCHIVE_ALLOWED_ROOT": "/data/archive", "ARCHIVE_LOCAL_DIR": "/data/archive/x"}, "overlaps the database volume"},
		"root above db":    {map[string]string{"ARCHIVE_ALLOWED_ROOT": "/srv", "ARCHIVE_LOCAL_DIR": "/srv/x"}, ""},
		"relative root":    {map[string]string{"ARCHIVE_ALLOWED_ROOT": "archive"}, "ARCHIVE_ALLOWED_ROOT must be an absolute path"},
		"no prefix":        {map[string]string{"ARCHIVE_S3_PREFIX": ""}, "ARCHIVE_S3_PREFIX is empty"},
		"bad prefix":       {map[string]string{"ARCHIVE_S3_PREFIX": "a/../b"}, "ARCHIVE_S3_PREFIX"},
		"object lock":      {map[string]string{"ARCHIVE_OBJECT_LOCK_DAYS": "30", "ARCHIVE_OBJECT_LOCK_MODE": "GOVERNANCE"}, "Object Lock"},
		"unknown target":   {map[string]string{"ARCHIVE_TARGET": "nfs"}, "ARCHIVE_TARGET must be s3 or local"},
		"staging inside":   {map[string]string{"ARCHIVE_STAGING_DIR": "/archive/nfs-share/fwmon/site-a/staging"}, "must not contain each other"},
		"staging contains": {map[string]string{"ARCHIVE_STAGING_DIR": "/archive/nfs-share"}, "must not contain each other"},
	} {
		env := localArchiveEnv()
		for k, v := range c.set {
			env[k] = v
		}
		setArchiveEnv(t, env)
		err := Load().Archive.Validate()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: Validate = %v, want %q", name, err, c.want)
		}
	}
}

// TestArchiveConfig_LocalLocation: the location of a local target is its
// directory and prefix, compared exactly (no bucket case folding); a switch
// of target type is another location.
func TestArchiveConfig_LocalLocation(t *testing.T) {
	l := ArchiveConfig{Target: ArchiveTargetLocal, LocalDir: "/archive/nfs-share", Prefix: "fwmon"}
	s := ArchiveConfig{Endpoint: "https://s3.example.com", Bucket: "archive", Prefix: "fwmon"}
	l2 := l
	l2.LocalDir = "/archive/NFS-share"
	l3 := l
	l3.Bucket = "ignored-for-local"
	switch {
	case !l.SameLocation(l3):
		t.Error("a bucket name moved a local target")
	case l.SameLocation(l2), SameLocationText(l.Location(), l2.Location()):
		t.Error("a local directory compared ignoring case")
	case l.SameLocation(s), s.SameLocation(l), SameLocationText(l.Location(), s.Location()):
		t.Error("a local and an S3 target compared as the same location")
	case !IsLocalLocation(l.Location()) || IsLocalLocation(s.Location()):
		t.Error("IsLocalLocation")
	}
}

// TestArchiveConfig_TargetFromAdminSettings: the admin form sets the target
// and directory like any field (normalised as the environment is); the
// allowed root has no field and cannot be set from it.
func TestArchiveConfig_TargetFromAdminSettings(t *testing.T) {
	setArchiveEnv(t, validArchiveEnv())
	a := Load().Archive.WithSettings(map[string]string{"ARCHIVE_TARGET": " Local ", "ARCHIVE_LOCAL_DIR": "/archive/disk",
		"ARCHIVE_OBJECT_LOCK_DAYS": "0", "ARCHIVE_OBJECT_LOCK_MODE": ""})
	if !a.IsLocal() || a.LocalDir != "/archive/disk" {
		t.Fatalf("WithSettings: %+v", a)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, ok := ArchiveFieldByEnv("ARCHIVE_ALLOWED_ROOT"); ok {
		t.Fatal("ARCHIVE_ALLOWED_ROOT is settable from the admin form")
	}
	if f := mustField(t, "ARCHIVE_LOCAL_DIR"); !f.Location || !f.Connection {
		t.Fatalf("ARCHIVE_LOCAL_DIR must be locked with the location and preflighted: %+v", f)
	}
	if f := mustField(t, "ARCHIVE_TARGET"); !f.Location || !f.Connection {
		t.Fatalf("ARCHIVE_TARGET must be locked with the location and preflighted: %+v", f)
	}
	// With the streams off, a draft's local directory is still checked.
	d := Load().Archive.WithSettings(map[string]string{"ARCHIVE_SYSLOG_ENABLED": "false", "ARCHIVE_TARGET": "local", "ARCHIVE_LOCAL_DIR": "/etc"})
	if err := d.ValidateDraft(); err == nil || !strings.Contains(err.Error(), "outside ARCHIVE_ALLOWED_ROOT") {
		t.Fatalf("a draft outside the root: %v", err)
	}
}
