package shell

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestDockerfileBuilderGoVersion_GoModFloor pins the Dockerfile builder base
// image to keep pace with the `go.mod` `go` directive. In v0.10.385 the
// directive was bumped to 1.25.11 (AUDIT-018) but the builder stage was left at
// `golang:1.23-alpine`; because the official Go images run with
// GOTOOLCHAIN=local, `go mod download` refused to auto-fetch a newer toolchain
// and `docker build` died with "go.mod requires go >= 1.25.11 (running go
// 1.23.12)". CI's go-native lanes don't build the container, so nothing caught
// the drift. This static guard fails loudly if the two ever diverge again.
func TestDockerfileBuilderGoVersion_GoModFloor(t *testing.T) {
	gomod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	dirRe := regexp.MustCompile(`(?m)^go\s+([0-9]+)\.([0-9]+)`)
	dm := dirRe.FindStringSubmatch(string(gomod))
	if len(dm) < 3 {
		t.Fatal("no `go` directive found in go.mod")
	}
	wantMajor, _ := strconv.Atoi(dm[1])
	wantMinor, _ := strconv.Atoi(dm[2])

	const path = "../../Dockerfile"
	df, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("Dockerfile not found at %s; err: %v", path, err)
	}
	// Match `FROM golang:<major>.<minor>[.patch]...` ignoring commented lines.
	imgRe := regexp.MustCompile(`(?mi)^\s*FROM\s+golang:([0-9]+)\.([0-9]+)`)
	im := imgRe.FindStringSubmatch(string(df))
	if len(im) < 3 {
		t.Fatalf("no `FROM golang:<ver>` builder stage found in Dockerfile")
	}
	gotMajor, _ := strconv.Atoi(im[1])
	gotMinor, _ := strconv.Atoi(im[2])

	if gotMajor < wantMajor || (gotMajor == wantMajor && gotMinor < wantMinor) {
		t.Errorf("Dockerfile builder is golang:%d.%d but go.mod requires go >= %d.%d — "+
			"the official Go image runs GOTOOLCHAIN=local, so `go mod download` will refuse to "+
			"auto-upgrade and `docker build` will fail. Bump the FROM line to golang:%d.%d-alpine.",
			gotMajor, gotMinor, wantMajor, wantMinor, wantMajor, wantMinor)
	}
}
