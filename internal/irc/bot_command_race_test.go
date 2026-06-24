package irc

import (
	"sync"
	"testing"

	"firewall-mon/internal/models"
)

// TestManager_LookupCommand_RaceFree is the regression for the 2026-06-23
// CTO-loop H4 finding: onPrivmsg read Manager.commands under the per-Bot mutex
// (b.mu) while loadCommands replaces the same map under the Manager mutex
// (m.mu). Two different locks are not mutual exclusion, so a `!command` arriving
// while an admin saved/reloaded commands triggered Go's unrecoverable
// "fatal error: concurrent map read and map write", aborting the whole API
// process. The read is now centralized in Manager.lookupCommand under m.mu.
//
// Run with -race; this fails (data race / fatal) if the read ever drifts back
// off m.mu. The writer mimics loadCommands' locked map replacement so we don't
// need a live DB.
func TestManager_LookupCommand_RaceFree(t *testing.T) {
	m := NewManager(nil)
	m.commands["ping"] = &models.IRCCommand{Command: "ping", Enabled: true}

	const readers = 8
	const iters = 20000

	var writerWG sync.WaitGroup
	stop := make(chan struct{})
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Mirror loadCommands: wholesale replacement under m.mu.
			m.mu.Lock()
			m.commands = map[string]*models.IRCCommand{
				"ping": {Command: "ping", Enabled: true},
				"help": {Command: "help", Enabled: true},
			}
			m.mu.Unlock()
		}
	}()

	var readWG sync.WaitGroup
	for r := 0; r < readers; r++ {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			for i := 0; i < iters; i++ {
				_, _ = m.lookupCommand("ping")
			}
		}()
	}
	readWG.Wait()
	close(stop)
	writerWG.Wait()
}
