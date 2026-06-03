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
// The fix added:
//  1. A header line referencing Keep-A-Changelog 1.1.0 and
//     Semantic Versioning 2.0.0.
//  2. An `## [Unreleased]` section at the top with the standard
//     sub-section placeholders (Added, Changed, Deprecated,
//     Removed, Fixed, Security).
//
// The test pins both. A future agent who removes the header
// (e.g. while reflowing the file) or the [Unreleased] section
// fails here, with a message pointing at the audit and the
// Keep-A-Changelog spec.
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

	// The [Unreleased] section must be the FIRST version section
	// (i.e. appear before the first `## [0.X.Y]` heading). The
	// audit's recommendation was to add this; without it, a
	// future changelog-edit agent has no convention to follow for
	// in-flight changes.
	unreleasedRe := regexp.MustCompile(`(?m)^## \[Unreleased\]`)
	firstVersionRe := regexp.MustCompile(`(?m)^## \[\d+\.\d+\.\d+\]`)
	unreleasedIdx := unreleasedRe.FindStringIndex(body)
	firstVersionIdx := firstVersionRe.FindStringIndex(body)
	if unreleasedIdx == nil {
		t.Errorf("CHANGELOG.md is missing the `## [Unreleased]` section (AUDIT-110). The Keep-A-Changelog spec requires this for in-flight changes; the audit's recommendation was to add it as a placeholder for future entries.")
	} else if firstVersionIdx != nil && unreleasedIdx[0] > firstVersionIdx[0] {
		t.Errorf("CHANGELOG.md has `## [Unreleased]` AFTER a `## [0.X.Y]` section (line %d vs line %d). Keep-A-Changelog requires [Unreleased] to be the first version section, before any released versions.", unreleasedIdx[0], firstVersionIdx[0])
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
