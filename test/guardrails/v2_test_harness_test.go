package guardrails

import (
	"strings"
	"testing"
)

// The Go test harness's cost.
//
// `internal/database` has 766 tests and EVERY one of them used to build the
// schema from scratch: AutoMigrate over 80 models. That is 15ms without the
// race detector and **356ms with it** — the pure-Go SQLite parser is
// instrumented, so every statement costs 23x more. That was 4.5 minutes of
// the race suite's wall clock spent re-creating an identical schema, and it
// is why `go test -race ./internal/database/` needed 4m37s and OVERFLOWED a
// 5-minute timeout on a busy machine.
//
// It looked like a deadlock. The goroutine dump showed the SQL PARSER, not
// a lock: every goroutine was inside `sqlite3Prepare`. And the test that
// appeared to hang was different on every run — the signature of a timeout,
// not of a deadlock.
//
// The schema is now built ONCE into a template file and copied per test.
// The whole tree's race suite went from "two packages too slow to run" to
// 1m47s.
//
// These tests pin that, because the regression is invisible: the tests all
// PASS either way. Only the wall clock changes.

const harnessPath = "internal/database/testing.go"

// TestV2TheTestHarnessDoesNotRemigratePerTest pins the schema template.
func TestV2TheTestHarnessDoesNotRemigratePerTest(t *testing.T) {
	harness := readRepoFile(t, harnessPath)

	// The template has to exist.
	for _, needle := range []string{
		"schemaTemplate",
		"copyFile",
		"VACUUM INTO",
	} {
		if !strings.Contains(harness, needle) {
			t.Errorf("%s has no %q — every test re-migrates 80 models, which is 356ms apiece under the race detector", harnessPath, needle)
		}
	}

	// And the per-test AutoMigrate loop has to be gone. The schema is
	// built once, in the template, so the loop belongs in
	// buildTestSchema — which the template calls — and NOT in the
	// per-test constructor.
	ctor := harness[strings.Index(harness, "func NewDatabaseForTesting"):]
	if strings.Contains(ctor, "AutoMigrate") {
		t.Errorf("%s: NewDatabaseForTesting still AutoMigrates — the schema must come from the template", harnessPath)
	}

	// The copy has to be per-test and isolated, so the file is removed
	// with the test.
	if !strings.Contains(ctor, "TempDir()") {
		t.Errorf("%s: NewDatabaseForTesting does not use t.TempDir() — each test's copy has to be isolated and cleaned up", harnessPath)
	}
}

// TestV2TheRaceSuiteFitsInOneTimeout pins the CI shape.
//
// The CI shards the two heavy packages by test name because they were too
// slow to run in one process. With the template they fit, so the shards are
// no longer about the wall clock — but the shard script still exists and
// still has to work, because the CI job's 20-minute budget is the real
// limit.
//
// What this test pins is simpler and more useful: the harness must not
// reintroduce a per-test migration, because that is what made the package
// need sharding in the first place.
func TestV2TheRaceSuiteFitsInOneTimeout(t *testing.T) {
	// The shard script still exists and still covers the two heavy
	// packages: if the harness ever gets slow again, the sharding is
	// there.
	script := readRepoFile(t, ".github/scripts/shard-tests.sh")
	for _, needle := range []string{"internal/database", "internal/api/handlers"} {
		if !strings.Contains(script, needle) {
			t.Errorf("the shard script no longer covers %s — the heavy packages have to stay sharded for the CI budget", needle)
		}
	}
}
