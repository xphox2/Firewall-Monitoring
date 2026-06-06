package main

import (
	"context"
	"testing"
	"time"
)

// TestProbeCleanup_CancelsAndDrainsPolls_AUDIT087 proves the fix for the
// untracked `go p.pollDevice(dev)` goroutines: cleanup() must (1) cancel the
// probe context so in-flight polls observe shutdown at their next
// checkpoint, and (2) wait for tracked polls to drain — but in a BOUNDED
// way, so a poll stuck in a slow SNMP timeout can't hang shutdown forever.
//
// We simulate an in-flight poll with a goroutine that registers on pollWG
// and exits when the context is cancelled (mirroring pollDevice's
// `if ctx.Err() != nil { return }` checkpoints).
func TestProbeCleanup_CancelsAndDrainsPolls_AUDIT087(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Probe{
		stopChan: make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}

	started := make(chan struct{})
	exited := make(chan struct{})
	p.pollWG.Add(1)
	go func() {
		defer p.pollWG.Done()
		close(started)
		<-p.ctx.Done() // poll checkpoints on the context, like pollDevice
		close(exited)
	}()
	<-started

	done := make(chan struct{})
	go func() {
		p.cleanup()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup() did not return promptly — the in-flight-poll drain is not bounded (AUDIT-087)")
	}

	if p.ctx.Err() == nil {
		t.Error("cleanup() did not cancel the probe context — in-flight polls would keep running after Stop() (AUDIT-087)")
	}
	select {
	case <-exited:
	default:
		t.Error("the in-flight poll did not observe context cancellation (AUDIT-087)")
	}
}

// TestProbeCleanup_BoundedWhenPollIgnoresCtx_AUDIT087 proves the 5s ceiling:
// even a poll that never checks the context (e.g. blocked deep in a gosnmp
// timeout) cannot hang shutdown — cleanup() returns within the bound and the
// stuck goroutine is left to finish its harmless in-flight HTTP POSTs.
func TestProbeCleanup_BoundedWhenPollIgnoresCtx_AUDIT087(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the 5s bounded-drain test in -short mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Probe{
		stopChan: make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}

	release := make(chan struct{})
	p.pollWG.Add(1)
	go func() {
		defer p.pollWG.Done()
		<-release // ignores ctx entirely, like a poll stuck in an SNMP wait
	}()

	start := time.Now()
	p.cleanup()
	elapsed := time.Since(start)
	close(release) // let the simulated stuck poll finish

	if elapsed > 7*time.Second {
		t.Errorf("cleanup() took %v — the bounded drain (5s ceiling) is not working (AUDIT-087)", elapsed)
	}
	if elapsed < 4*time.Second {
		t.Errorf("cleanup() returned in %v — it did not wait for the in-flight poll at all (AUDIT-087 expects a bounded wait)", elapsed)
	}
}
