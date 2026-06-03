package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadOrGenerate_EnvValuePreferred — if the operator supplied an env
// var, it wins. No file is touched (asserted by using a non-existent dir).
func TestLoadOrGenerate_EnvValuePreferred(t *testing.T) {
	got, src, err := LoadOrGenerate("operator-set-value", "/this/does/not/exist", "anything")
	if err != nil {
		t.Fatalf("env-preferred path returned error: %v", err)
	}
	if got != "operator-set-value" {
		t.Errorf("got %q, want operator-set-value", got)
	}
	if src != FromEnv {
		t.Errorf("source = %v, want FromEnv", src)
	}
}

// TestLoadOrGenerate_GenerateThenLoad locks in AUDIT-008: a first run
// without env vars must generate-AND-persist; subsequent runs must read
// the SAME value back so JWT signatures stay valid and ENC ciphertext
// stays decryptable across restarts.
func TestLoadOrGenerate_GenerateThenLoad(t *testing.T) {
	dir := t.TempDir()

	// First call — directory empty, no env → generate + persist.
	v1, src1, err := LoadOrGenerate("", dir, ".jwt-secret")
	if err != nil {
		t.Fatalf("first LoadOrGenerate: %v", err)
	}
	if src1 != Generated {
		t.Errorf("first call source = %v, want Generated", src1)
	}
	if len(v1) < 32 {
		t.Errorf("generated secret too short: len=%d, want >= 32 hex chars", len(v1))
	}

	// File must exist with chmod 0600.
	path := filepath.Join(dir, ".jwt-secret")
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("expected persisted file at %s: %v", path, statErr)
	}
	// Permission check is best-effort on Windows (it always reports 0666);
	// only enforce on Unix-like.
	if mode := info.Mode().Perm(); mode != 0o600 && mode != 0o666 {
		t.Errorf("file mode = %o, want 0600 (or 0666 on Windows)", mode)
	}

	// Second call — same dir, file exists → load same value.
	v2, src2, err := LoadOrGenerate("", dir, ".jwt-secret")
	if err != nil {
		t.Fatalf("second LoadOrGenerate: %v", err)
	}
	if src2 != FromFile {
		t.Errorf("second call source = %v, want FromFile", src2)
	}
	if v2 != v1 {
		t.Fatalf("AUDIT-008 regression: second call returned %q, want same %q from first call (JWT/ENC would break)", v2, v1)
	}
}

// TestLoadOrGenerate_EmptyFileTreatedAsMissing — an existing-but-empty
// secret file is treated like a missing one (regenerate). Prevents the
// silent-zero-secret footgun where someone `touch`es the file.
func TestLoadOrGenerate_EmptyFileTreatedAsMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".jwt-secret")
	if err := os.WriteFile(path, []byte("\n   \n"), 0o600); err != nil {
		t.Fatalf("setup write: %v", err)
	}
	v, src, err := LoadOrGenerate("", dir, ".jwt-secret")
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if src != Generated {
		t.Errorf("source = %v, want Generated (empty file should regenerate)", src)
	}
	if v == "" {
		t.Error("returned empty secret")
	}
}

// TestLoadOrGenerate_TrimsWhitespace — file contents are trimmed so an
// editor's trailing newline doesn't break JWT signing (a "secret\n" key
// hashes differently from "secret").
func TestLoadOrGenerate_TrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".jwt-secret")
	if err := os.WriteFile(path, []byte("  the-actual-secret-value  \n"), 0o600); err != nil {
		t.Fatalf("setup write: %v", err)
	}
	v, src, err := LoadOrGenerate("", dir, ".jwt-secret")
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if v != "the-actual-secret-value" {
		t.Errorf("got %q, want trimmed secret", v)
	}
	if src != FromFile {
		t.Errorf("source = %v, want FromFile", src)
	}
}

// TestLoadOrGenerate_MissingArgs — rejects empty baseDir / filename so
// callers can't accidentally generate at the filesystem root or
// overwrite a path they didn't intend.
func TestLoadOrGenerate_MissingArgs(t *testing.T) {
	if _, _, err := LoadOrGenerate("", "", "x"); err == nil {
		t.Error("empty baseDir: expected error, got nil")
	}
	if _, _, err := LoadOrGenerate("", "/tmp", ""); err == nil {
		t.Error("empty filename: expected error, got nil")
	}
}

// TestLoadOrGenerate_PersistFailure — if the dir is unwritable, return
// an error instead of silently continuing. (Best-effort on Windows where
// chmod semantics differ; we use a deeply-invalid path instead.)
func TestLoadOrGenerate_PersistFailure(t *testing.T) {
	// On both Windows and Unix, a path containing a NUL byte is invalid
	// at the syscall level — neither MkdirAll nor WriteFile will accept it.
	_, _, err := LoadOrGenerate("", "/tmp/with\x00null", ".secret")
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

// TestPersistGeneratedPassword_FirstRunWritesThenNoOp — write on first
// call, no-op on subsequent calls (so we never overwrite a user-edited
// password file).
func TestPersistGeneratedPassword_FirstRunWritesThenNoOp(t *testing.T) {
	dir := t.TempDir()
	written, err := PersistGeneratedPassword("hunter2", dir, ".admin-password")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !written {
		t.Error("first call: written=false, want true")
	}

	path := filepath.Join(dir, ".admin-password")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if strings.TrimSpace(string(data)) != "hunter2" {
		t.Errorf("file contains %q, want hunter2", string(data))
	}

	// Second call with a DIFFERENT password → no-op, file unchanged.
	written2, err := PersistGeneratedPassword("different-password", dir, ".admin-password")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if written2 {
		t.Error("second call: written=true, want false (no-op when file exists)")
	}
	data2, _ := os.ReadFile(path)
	if strings.TrimSpace(string(data2)) != "hunter2" {
		t.Errorf("file unexpectedly changed to %q on second call", string(data2))
	}
}

// TestPersistGeneratedPassword_ValidatesArgs
func TestPersistGeneratedPassword_ValidatesArgs(t *testing.T) {
	if _, err := PersistGeneratedPassword("", "/tmp", "x"); err == nil {
		t.Error("empty password: expected error")
	}
	if _, err := PersistGeneratedPassword("pw", "", "x"); err == nil {
		t.Error("empty baseDir: expected error")
	}
	if _, err := PersistGeneratedPassword("pw", "/tmp", ""); err == nil {
		t.Error("empty filename: expected error")
	}
}

// TestLoadPassword_RoundTrip
func TestLoadPassword_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Missing file → ("", false, nil)
	pw, ok, err := LoadPassword(dir, ".admin-password")
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if ok || pw != "" {
		t.Errorf("missing file: got (%q, %v), want (\"\", false)", pw, ok)
	}

	// Persist then load.
	if _, err := PersistGeneratedPassword("the-password", dir, ".admin-password"); err != nil {
		t.Fatalf("persist: %v", err)
	}
	pw, ok, err = LoadPassword(dir, ".admin-password")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ok || pw != "the-password" {
		t.Errorf("load: got (%q, %v), want (\"the-password\", true)", pw, ok)
	}
}

// TestSource_String — readable in logs.
func TestSource_String(t *testing.T) {
	cases := map[Source]string{
		FromEnv:    "env",
		FromFile:   "file",
		Generated:  "generated",
		Source(99): "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Source(%d).String() = %q, want %q", s, got, want)
		}
	}
}
