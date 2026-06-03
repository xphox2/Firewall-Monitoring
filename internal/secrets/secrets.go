// Package secrets handles loading-or-generating sensitive runtime values
// (JWT signing key, auto-generated admin password) from environment vars,
// persisted files, or a fresh random generator — in that order of priority.
//
// AUDIT-008: previously these values were generated in-memory on every
// `cmd/api` startup if the env var was unset. That meant:
//   - every restart issued a NEW JWT-signing key → every existing login
//     token rejected (operators forced to re-login on each restart)
//   - the same key derives the AES-256 ENC key for `{enc}<base64>`
//     stored secrets (SNMP / IRC / SMTP); a new key on restart made
//     EVERY existing ciphertext permanently unreadable
//   - the auto-generated admin password was likewise regenerated each
//     restart, locking the operator out (the DB still held the FIRST
//     run's bcrypt hash; the printed-on-restart "password" was a fresh
//     random string that hashed to a different value)
//
// LoadOrGenerate fixes all three by persisting the generated value to a
// chmod-0600 file in a dedicated secrets directory. Subsequent runs read
// the same value back. Persistence failure is a fatal error — the caller
// MUST fail the process rather than continue with an unpersisted secret.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"firewall-mon/internal/auth"
)

// Source indicates where the secret came from.
type Source int

const (
	// FromEnv means the operator-supplied env var was used; nothing was
	// written to disk.
	FromEnv Source = iota
	// FromFile means a previously-persisted secret was loaded from disk.
	FromFile
	// Generated means a fresh secret was generated AND persisted to disk.
	Generated
)

func (s Source) String() string {
	switch s {
	case FromEnv:
		return "env"
	case FromFile:
		return "file"
	case Generated:
		return "generated"
	default:
		return "unknown"
	}
}

// LoadOrGenerate returns the resolved secret value and its source.
//
// Resolution order:
//  1. If envValue is non-empty → use it (Source=FromEnv, no file I/O).
//  2. Else if baseDir/filename exists and is non-empty → use its contents
//     (Source=FromFile, trimmed of surrounding whitespace).
//  3. Else generate a fresh 32-byte hex token, ensure baseDir exists
//     (chmod 0700), write the token to baseDir/filename (chmod 0600),
//     return it (Source=Generated).
//
// Any I/O error in step 2 or 3 (other than "file does not exist" in step 2)
// is returned. The caller MUST treat a returned error as fatal — silently
// running with an unpersisted secret reintroduces the bug AUDIT-008 closed.
func LoadOrGenerate(envValue, baseDir, filename string) (value string, source Source, err error) {
	if envValue != "" {
		return envValue, FromEnv, nil
	}
	if baseDir == "" {
		return "", 0, fmt.Errorf("secrets.LoadOrGenerate: baseDir must not be empty")
	}
	if filename == "" {
		return "", 0, fmt.Errorf("secrets.LoadOrGenerate: filename must not be empty")
	}
	path := filepath.Join(baseDir, filename)

	// Step 2: try loading a previously-persisted secret.
	data, readErr := os.ReadFile(path)
	if readErr == nil {
		trimmed := strings.TrimSpace(string(data))
		if trimmed != "" {
			return trimmed, FromFile, nil
		}
		// File exists but is empty / whitespace-only — best-effort
		// remove so the O_CREATE|O_EXCL claim below can succeed. Any
		// races between our remove and another process's recreate
		// resolve via the ErrExist branch (loser re-reads winner's value).
		_ = os.Remove(path)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", 0, fmt.Errorf("read existing secret %s: %w", path, readErr)
	}

	// Step 3: generate and persist.
	token, gErr := auth.GenerateSecureToken(32)
	if gErr != nil {
		return "", 0, fmt.Errorf("generate secret: %w", gErr)
	}
	if mkErr := os.MkdirAll(baseDir, 0o700); mkErr != nil {
		return "", 0, fmt.Errorf("mkdir secrets dir %s: %w", baseDir, mkErr)
	}
	// Use O_CREATE|O_EXCL to defeat the TOCTOU race when multiple
	// processes (cmd/api, cmd/poller, cmd/trap-receiver) start
	// concurrently on a fresh /data volume and all see the file as
	// missing. The winner writes the secret; everyone else hits
	// os.ErrExist and re-reads the now-present file.
	f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		if errors.Is(openErr, os.ErrExist) {
			// Another process won the race; re-read and use their value.
			data, rErr := os.ReadFile(path)
			if rErr != nil {
				return "", 0, fmt.Errorf("re-read secret %s after race: %w", path, rErr)
			}
			trimmed := strings.TrimSpace(string(data))
			if trimmed == "" {
				return "", 0, fmt.Errorf("secret file %s is empty after concurrent write", path)
			}
			return trimmed, FromFile, nil
		}
		return "", 0, fmt.Errorf("create secret %s: %w", path, openErr)
	}
	if _, wErr := f.Write([]byte(token + "\n")); wErr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", 0, fmt.Errorf("write secret to %s: %w", path, wErr)
	}
	if cErr := f.Close(); cErr != nil {
		return "", 0, fmt.Errorf("close secret %s: %w", path, cErr)
	}
	return token, Generated, nil
}

// PersistGeneratedPassword writes an existing password (typically the one
// config.Load already generated in-memory) to the secrets file IF the file
// does not already exist. Used by the admin-password flow where the
// password was generated upstream by config.Load and the caller wants to
// pin it to disk on first run only.
//
// Returns true if the file was written (first-run pin), false if it
// already existed (no-op), or an error on any I/O failure.
func PersistGeneratedPassword(password, baseDir, filename string) (bool, error) {
	if password == "" {
		return false, fmt.Errorf("PersistGeneratedPassword: password must not be empty")
	}
	if baseDir == "" || filename == "" {
		return false, fmt.Errorf("PersistGeneratedPassword: baseDir and filename must not be empty")
	}
	path := filepath.Join(baseDir, filename)
	if _, err := os.Stat(path); err == nil {
		return false, nil // already exists
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", baseDir, err)
	}
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		return false, fmt.Errorf("persist password to %s: %w", path, err)
	}
	return true, nil
}

// LoadPassword reads a previously-persisted password from disk. Returns
// ("", false, nil) if the file does not exist; ("", false, err) on any
// other I/O error; (password, true, nil) on success.
func LoadPassword(baseDir, filename string) (string, bool, error) {
	if baseDir == "" || filename == "" {
		return "", false, fmt.Errorf("LoadPassword: baseDir and filename must not be empty")
	}
	path := filepath.Join(baseDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read %s: %w", path, err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return "", false, nil
	}
	return trimmed, true, nil
}
