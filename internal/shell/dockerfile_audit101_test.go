package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDockerfile_OCILabelsUseBuildArgs_AUDIT101 is a static regression
// for the audit: the Dockerfile used to ship
// `org.opencontainers.image.version="0.10.X"` as a hardcoded literal,
// caught stale at v0.10.237 and v0.10.239 in past releases (the
// build would ship with a label that said one version while the
// binary inside reported another, which broke operator-side
// "is-this-the-right-image" checks).
//
// The fix: declare the version (and .revision, .created) as ARG
// values, with defaults so a `docker build .` without --build-arg
// still produces a working image labeled "dev". The CI workflow
// (when added — AUDIT-004 deferred halves) will pass
// --build-arg VERSION=<tag> for tagged releases.
//
// This test pins two things:
//  1. The Dockerfile declares ARG VERSION, ARG REVISION, ARG CREATED
//     before the LABEL block.
//  2. The LABEL block references ${VERSION}, ${REVISION}, ${CREATED}
//     rather than the hardcoded literal.
//  3. No `org.opencontainers.image.version="<literal>"` survives
//     anywhere in the Dockerfile.
func TestDockerfile_OCILabelsUseBuildArgs_AUDIT101(t *testing.T) {
	const path = "../../Dockerfile"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("Dockerfile not found at %s (tests must run from the package root); err: %v", path, err)
	}
	body := string(data)

	// (1) ARG declarations must be present.
	for _, wantArg := range []string{"ARG VERSION=", "ARG REVISION=", "ARG CREATED="} {
		if !strings.Contains(body, wantArg) {
			t.Errorf("Dockerfile missing %q (AUDIT-101: the OCI labels must come from build-args, not hardcoded literals). The build-arg has a sensible default so a bare `docker build .` still works.", wantArg)
		}
	}

	// (2) LABEL block must reference the build-args, not the literals.
	for _, wantRef := range []string{
		`org.opencontainers.image.version="${VERSION}"`,
		`org.opencontainers.image.revision="${REVISION}"`,
		`org.opencontainers.image.created="${CREATED}"`,
	} {
		if !strings.Contains(body, wantRef) {
			t.Errorf("Dockerfile LABEL block missing %q (AUDIT-101). The label must be sourced from the build-arg, not a hardcoded literal.", wantRef)
		}
	}

	// (3) No hardcoded version literal survives. The regex matches
	// `org.opencontainers.image.version="<something>"` and we
	// exclude the canonical `${VERSION}` form by string check (Go's
	// regex engine doesn't support lookaheads).
	hardcodedRe := regexp.MustCompile(`org\.opencontainers\.image\.version="([^"]*)"`)
	for _, m := range hardcodedRe.FindAllStringSubmatch(body, -1) {
		fullMatch := m[0]
		innerValue := m[1]
		if innerValue == "${VERSION}" {
			// Good — this is the build-arg form.
			continue
		}
		t.Errorf("Dockerfile has a hardcoded org.opencontainers.image.version=%q (AUDIT-101). Use ${VERSION} build-arg instead. Caught a literal version here: %q", fullMatch, innerValue)
	}
}
