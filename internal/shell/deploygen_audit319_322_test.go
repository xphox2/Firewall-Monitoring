package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// AUDIT-322: each deploy/rollback/recheck POST handler opened the progress
// modal (bumping deployGen) and then guarded its own resolution with
// deployLive(deployGen) — comparing the live generation against itself, so the
// generation half of the guard was always true. Only the modal-is-open half
// did any work, and that stays true when the operator has meanwhile opened a
// DIFFERENT tunnel's modal, letting a late POST start a rogue second poll loop
// against it. Each site must pin the generation it opened with.
func TestDeployPollGuard_PinsGeneration_AUDIT322(t *testing.T) {
	js := readJS(t, "admin-ipsec.js")

	if strings.Contains(js, "deployLive(deployGen)") {
		t.Error("AUDIT-322 regression: a deploy guard compares deployGen against itself — " +
			"capture `var gen = deployGen` after openDeployModal and check that instead")
	}
	for _, op := range []string{"deploy", "rollback", "recheck"} {
		if strings.Contains(js, "pollDeploy(id, deployGen, Date.now(), '"+op+"')") {
			t.Errorf("AUDIT-322 regression: the %s POST handler still starts pollDeploy with the "+
				"live deployGen instead of the generation its modal opened with", op)
		}
	}

	// Every deferred-poll site must capture the generation. openDeployModal's
	// own internal call is the one legitimate live-deployGen use, since it runs
	// immediately after the bump.
	deferred := regexp.MustCompile(`openDeployModal\(id, '(deploy|rollback|recheck)', true\);`)
	if got := len(deferred.FindAllString(js, -1)); got != 3 {
		t.Fatalf("expected 3 deferred-poll deploy sites, found %d — the AUDIT-322 guard "+
			"below no longer covers what it was written for", got)
	}
	if got := strings.Count(js, "var gen = deployGen;"); got != 3 {
		t.Errorf("AUDIT-322: expected all 3 deferred-poll sites to pin the generation, found %d", got)
	}
}

// AUDIT-319: go-ircevent's Connect spawns readLoop/writeLoop/pingLoop and
// allocates the socket BEFORE negotiating capabilities, then returns a
// negotiateCaps error without unwinding any of it. Bot.Start's error branch
// must tear the connection down, and must do so ONLY when those loops actually
// exist — a nil ErrorChan means Connect bailed before allocating anything, and
// Disconnect would then block forever sending on that nil channel.
func TestIRCConnectFailure_TearsDownSpawnedLoops_AUDIT319(t *testing.T) {
	b, err := os.ReadFile("../../internal/irc/bot.go")
	if err != nil {
		t.Fatalf("read bot.go: %v", err)
	}
	src := string(b)

	start := strings.Index(src, "if err := conn.Connect(addr); err != nil {")
	if start < 0 {
		t.Fatal("could not locate Bot.Start's Connect error branch in bot.go")
	}
	end := strings.Index(src[start:], "\n\t}\n")
	if end < 0 {
		t.Fatal("could not delimit the Connect error branch")
	}
	branch := src[start : start+end]

	if !strings.Contains(branch, "teardownFailedConn") {
		t.Error("AUDIT-319 regression: Bot.Start's Connect-error branch no longer tears down the " +
			"connection — a SASL rejection strands writeLoop, pingLoop and the socket on every " +
			"reconnect attempt")
	}
	if !strings.Contains(branch, "conn.ErrorChan() != nil") {
		t.Error("AUDIT-319 regression: the teardown is no longer gated on a non-nil ErrorChan — " +
			"on a pre-dial failure Disconnect blocks forever sending on the nil Error channel")
	}
}
