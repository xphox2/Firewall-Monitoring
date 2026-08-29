package shell

import (
	"os"
	"regexp"
	"testing"
)

// TestReadmeVersionBadge_MatchesServerVersion guards AUDIT-228: the README
// version badge had drifted to 0.10.553 while cmd/api/main.go's ServerVersion
// const moved on into the 0.11.x series. The badge is the human-facing version
// claim, so it must track the build-baked const exactly. This static guard
// fails loudly the next time the two diverge.
func TestReadmeVersionBadge_MatchesServerVersion(t *testing.T) {
	mainSrc, err := os.ReadFile("../../cmd/api/main.go")
	if err != nil {
		t.Fatalf("read cmd/api/main.go: %v", err)
	}
	verRe := regexp.MustCompile(`ServerVersion\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"`)
	vm := verRe.FindStringSubmatch(string(mainSrc))
	if len(vm) < 2 {
		t.Fatal("could not find the ServerVersion const in cmd/api/main.go")
	}
	want := vm[1]

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	// Robust to badge cosmetics (label text, color suffix): match only the
	// shields.io version-badge's version segment.
	badgeRe := regexp.MustCompile(`img\.shields\.io/badge/version-([0-9]+\.[0-9]+\.[0-9]+)`)
	bm := badgeRe.FindStringSubmatch(string(readme))
	if len(bm) < 2 {
		t.Fatal("could not find the version badge (img.shields.io/badge/version-<x.y.z>) in README.md")
	}
	if bm[1] != want {
		t.Errorf("README version badge is %s but cmd/api/main.go ServerVersion is %s — "+
			"bump the badge to match the const (AUDIT-228).", bm[1], want)
	}
}
