package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkCheckout builds a throwaway git checkout: a root with a .git entry (a
// directory by default, a file to simulate a worktree) and a nested working
// directory wd under it.
func mkCheckout(t *testing.T, worktreeStyleGit bool) (root, wd string) {
	t.Helper()
	root = t.TempDir()
	if worktreeStyleGit {
		if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wd = filepath.Join(root, "cmd", "api")
	if err := os.MkdirAll(wd, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, wd
}

// TestProjectLocalDirWarning covers the M-14 predicate: a directory inside a
// git checkout warns; everything else (outside paths, non-checkout dirs,
// empty values) stays silent.
func TestProjectLocalDirWarning(t *testing.T) {
	root, wd := mkCheckout(t, false)

	cases := []struct {
		name      string
		envKey    string
		dir       string
		wantWarn  bool
		wantParts []string // substrings the warning must contain
	}{
		{
			name:     "absolute path inside the checkout",
			dir:      filepath.Join(wd, "data"),
			wantWarn: true,
			wantParts: []string{
				"SECRETS_DIR",
				"inside the git checkout at " + root,
				"committed to the repository",
			},
		},
		{
			name:     "relative path resolves against wd",
			envKey:   "ARCHIVE_STAGING_DIR",
			dir:      "staging",
			wantWarn: true,
			wantParts: []string{
				"ARCHIVE_STAGING_DIR",
				"staging",
			},
		},
		{
			name:     "dir equal to wd is still inside the checkout",
			envKey:   "GEOIP_CACHE_DIR",
			dir:      ".",
			wantWarn: true,
			wantParts: []string{
				"GEOIP_CACHE_DIR",
				"git checkout",
			},
		},
		{
			name:     "durable absolute path outside the project is silent",
			envKey:   "SECRETS_DIR",
			dir:      "/data",
			wantWarn: false,
		},
		{
			name:     "sibling path outside wd is silent even under a checkout elsewhere",
			envKey:   "SECRETS_DIR",
			dir:      filepath.Join(root, "..", "elsewhere"),
			wantWarn: false,
		},
		{
			name:     "empty dir is skipped",
			envKey:   "GEOIP_CACHE_DIR",
			dir:      "",
			wantWarn: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envKey := tc.envKey
			if envKey == "" {
				envKey = "SECRETS_DIR"
			}
			got := projectLocalDirWarning(envKey, tc.dir, wd)
			if tc.wantWarn {
				if got == "" {
					t.Fatalf("expected a warning for %q (wd=%s), got none", tc.dir, wd)
				}
				for _, want := range tc.wantParts {
					if !strings.Contains(got, want) {
						t.Fatalf("warning %q missing %q", got, want)
					}
				}
			} else if got != "" {
				t.Fatalf("expected no warning for %q, got %q", tc.dir, got)
			}
		})
	}
}

// TestProjectLocalDirWarning_NeedsGit: the same in-checkout path must stay
// silent when the working directory is NOT inside a git checkout — running
// from an arbitrary installed directory with relative paths is a legitimate
// setup, and warning there would be noise.
func TestProjectLocalDirWarning_NeedsGit(t *testing.T) {
	wd := t.TempDir() // no .git anywhere above it
	if got := projectLocalDirWarning("SECRETS_DIR", filepath.Join(wd, "data"), wd); got != "" {
		t.Fatalf("no .git above wd: expected silence, got %q", got)
	}
}

// TestProjectLocalDirWarning_WorktreeGitFile: a worktree's .git is a FILE
// pointing at the real gitdir; os.Stat (not the directory-only check) must
// still recognize it.
func TestProjectLocalDirWarning_WorktreeGitFile(t *testing.T) {
	_, wd := mkCheckout(t, true)
	if got := projectLocalDirWarning("SECRETS_DIR", "data", wd); got == "" {
		t.Fatal("a .git file (worktree) must count as a checkout")
	}
}

// TestProjectLocalDirWarnings_AllDirs: the Config-level sweep covers SECRETS_DIR
// and every configured writable directory, and stays silent for the defaults
// (all durable absolute paths outside any checkout).
func TestProjectLocalDirWarnings_AllDirs(t *testing.T) {
	_, wd := mkCheckout(t, false)

	c := &Config{}
	c.Server.GeoIPCacheDir = filepath.Join(wd, "geoip-cache")
	c.Archive.StagingDir = "stage" // relative — resolves into the checkout
	c.Archive.LocalDir = "/var/archive"

	got := c.ProjectLocalDirWarnings(filepath.Join(wd, "secrets"), wd)
	if len(got) != 3 {
		t.Fatalf("expected 3 warnings (secrets, geoip cache, staging), got %d: %v", len(got), got)
	}
	for _, want := range []string{"SECRETS_DIR", "GEOIP_CACHE_DIR", "ARCHIVE_STAGING_DIR"} {
		found := false
		for _, w := range got {
			if strings.Contains(w, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s warning in %v", want, got)
		}
	}

	// Defaults: nothing configured inside a checkout → no warnings.
	dflt := &Config{}
	if got := dflt.ProjectLocalDirWarnings("/data", wd); len(got) != 0 {
		t.Fatalf("default dirs should be silent, got %v", got)
	}
}
