package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestChangelog_KeepAChangelogHeader_AUDIT110 — the regression
// for the audit: the CHANGELOG must follow Keep-A-Changelog
// 1.1.0 (the linked standard). The audit's complaint was that
// the file was "free-form" and "not machine-readable" before
// the fix.
//
// The fix added a header line referencing Keep-A-Changelog 1.1.0 and
// Semantic Versioning 2.0.0, which the test still pins.
//
// UPDATE 2026-06-11: the original AUDIT-110 also mandated a top
// `## [Unreleased]` section. The maintainer removed that convention —
// it had drifted into a catch-all blob and diverged from the sibling
// Firewall-Collector, which uses per-version `## [x.y.z] - date`
// sections (newest first), as does this file's own <= 0.10.281 history.
// The test now enforces the per-version convention: the first `## [...]`
// section must be a concrete version, NOT `## [Unreleased]`.
func TestChangelog_KeepAChangelogHeader_AUDIT110(t *testing.T) {
	const path = "../../CHANGELOG.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("CHANGELOG.md not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// The file must reference Keep-A-Changelog in the header.
	if !strings.Contains(body, "Keep a Changelog") {
		t.Errorf("CHANGELOG.md is missing the Keep-A-Changelog reference in the header (AUDIT-110). The header must link to https://keepachangelog.com/ so a future agent who edits the file knows which version of the spec to follow. Currently the body has %d characters.", len(body))
	}

	// The file must reference Semantic Versioning.
	if !strings.Contains(body, "Semantic Versioning") {
		t.Errorf("CHANGELOG.md is missing the Semantic Versioning reference in the header (AUDIT-110). The header must link to https://semver.org/ so the version-bump discipline is documented in-place.")
	}

	// The first `## [...]` section must be a concrete `## [X.Y.Z] - date`
	// release (newest first) — NOT a `## [Unreleased]` accumulator. This repo
	// (and the sibling Firewall-Collector) use per-version sections; the
	// maintainer removed the Keep-A-Changelog [Unreleased] convention on
	// 2026-06-11 because it had drifted into a catch-all blob and diverged from
	// the collector's format. New releases each get their own dated section.
	firstSectionRe := regexp.MustCompile(`(?m)^## \[([^\]]+)\]`)
	m := firstSectionRe.FindStringSubmatch(body)
	if m == nil {
		t.Errorf("CHANGELOG.md has no `## [...]` version section (AUDIT-110).")
	} else if m[1] == "Unreleased" {
		t.Errorf("CHANGELOG.md leads with `## [Unreleased]`. This project uses per-version `## [x.y.z] - date` sections, newest first (matching the sibling Firewall-Collector and this file's own <= 0.10.281 history) — not a Keep-A-Changelog [Unreleased] accumulator. Give the change its own `## [x.y.z] - date` section at the top.")
	}
}

// TestKnownIssues_Exists_AUDIT110 is a static check on the
// companion KNOWN-ISSUES.md file the audit recommended. The
// file is a one-stop reference for operator-known limitations
// that don't yet have a fix (so the operator doesn't waste time
// debugging something we already know about).
func TestKnownIssues_Exists_AUDIT110(t *testing.T) {
	const path = "../../KNOWN-ISSUES.md"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("KNOWN-ISSUES.md missing at %s (AUDIT-110: the audit recommended this file; without it, operators waste time debugging issues we've already documented elsewhere). The file should exist and contain at least the AUDIT references listed in the audit doc.", path)
	}
	body := string(data)

	// The file must reference at least one of the audit IDs that
	// drove its creation. We check the highest-impact ones; a
	// future agent who deletes all of these references fails here.
	expectedRefs := []string{"AUDIT-040", "AUDIT-118", "AUDIT-093", "AUDIT-105", "AUDIT-029"}
	found := 0
	for _, ref := range expectedRefs {
		if strings.Contains(body, ref) {
			found++
		}
	}
	if found < 3 {
		t.Errorf("KNOWN-ISSUES.md mentions only %d of the %d AUDIT-NNN references the file should cross-link to. A future agent who strips the cross-links is removing the value of having a separate file — readers can no longer navigate from a known issue to its audit doc row.", found, len(expectedRefs))
	}
}
