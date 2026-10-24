package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// projectLocalDirWarning returns a startup warning when dir — which may be
// relative, in which case it resolves against wd — lands inside a git
// checkout. That is the M-14 finding: a writable data/config directory
// pointed INTO the project tree means generated secrets and runtime data can
// be committed to the repository (pushing the JWT secret / admin password
// public) or silently destroyed by git checkout/clean during routine dev
// work. "" when the location is fine.
//
// "Project-local" needs BOTH conditions, and each exists to keep the warning
// truthful:
//   - dir resolves inside wd (or equals it): the daemons resolve relative
//     paths against the working directory, so only paths under it are the
//     dev-shortcut case this warns about. Absolute paths elsewhere (/data,
//     /var/lib/...) are the normal, correct setup.
//   - some ancestor of wd (including wd) carries a .git entry (a directory
//     for a checkout, a file for a worktree): os.Stat accepts both. Without
//     this, running from an arbitrary directory would false-positive on every
//     relative path.
func projectLocalDirWarning(envKey, dir, wd string) string {
	if dir == "" {
		return ""
	}
	absWd, err := filepath.Abs(wd)
	if err != nil {
		return ""
	}
	var absDir string
	if filepath.IsAbs(dir) {
		absDir = filepath.Clean(dir)
	} else {
		// Resolve against wd, NOT the process cwd, so the check is a pure
		// function of its arguments (and testable without chdir).
		absDir = filepath.Join(absWd, filepath.Clean(dir))
	}
	if absDir != absWd && !strings.HasPrefix(absDir, absWd+string(filepath.Separator)) {
		return ""
	}
	root := ""
	for p := absWd; ; p = filepath.Dir(p) {
		if _, err := os.Stat(filepath.Join(p, ".git")); err == nil {
			root = p
			break
		}
		if parent := filepath.Dir(p); parent == p {
			break // reached "/" without finding a checkout
		}
	}
	if root == "" {
		return ""
	}
	return fmt.Sprintf(
		"WARNING: %s %s resolves inside the git checkout at %s — files written there (secrets, runtime data) can be committed to the repository or wiped by git checkout/clean. Point it at a durable directory outside the project.",
		envKey, dir, root)
}

// ProjectLocalDirWarnings returns the M-14 warnings for every writable
// directory the daemons use: SECRETS_DIR (holds .jwt-secret, .admin-password
// and the {enc} key material), the GeoIP directories (the live DB and the
// extracted bundle cache), and the archive staging/local directories. Each
// warning fires only when the directory resolves inside a git checkout rooted
// at or above wd — see projectLocalDirWarning for the rationale.
func (c *Config) ProjectLocalDirWarnings(secretsDir, wd string) []string {
	var out []string
	for _, d := range []struct{ envKey, dir string }{
		{"SECRETS_DIR", secretsDir},
		{"GEOIP_DB_DIR", c.Server.GeoIPDBDir},
		{"GEOIP_CACHE_DIR", c.Server.GeoIPCacheDir},
		{"ARCHIVE_STAGING_DIR", c.Archive.StagingDir},
		{"ARCHIVE_LOCAL_DIR", c.Archive.LocalDir},
	} {
		if msg := projectLocalDirWarning(d.envKey, d.dir, wd); msg != "" {
			out = append(out, msg)
		}
	}
	return out
}

// WarnProjectLocalDirs logs the M-14 project-local directory warnings against
// the process working directory. Called by every daemon's main right after
// the config and SECRETS_DIR are known. A warning is never fatal: dev setups
// legitimately run from a checkout; the point is that the operator KNOWS the
// secrets/data live somewhere git can see.
func (c *Config) WarnProjectLocalDirs(secretsDir string) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	for _, msg := range c.ProjectLocalDirWarnings(secretsDir, wd) {
		log.Println(msg)
	}
}
