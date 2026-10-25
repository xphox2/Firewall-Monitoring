package database

import (
	"context"
	"log"
	"sync/atomic"
)

// IPSecRollbackWorker is the API primary's IPSec rollback-reconciler loop
// driver. cmd/api ticks it every 15 s while it holds the singleton.
//
// WHY it exists: the rolling_back → rolled_back|rollback_failed terminal was
// advanced ONLY by the UI-driven GET …/deploy poll. That has two consequences:
//
//   - the bulk orphaned-rollback endpoint's live-end tunnels never reached a
//     terminal unless somebody polled each one by hand;
//   - a tunnel left rolling_back (the operator closed the browser mid-rollback)
//     was stuck forever: it could not be re-rolled-back (the rollback's
//     fromStatuses exclude rolling_back) and it BLOCKED the purge of the
//     retired device it belonged to.
//
// So the primary advances every rolling_back tunnel with the shared
// ResolveIPSecRollback. The guarded write makes a concurrent resolution with
// the UI poll benign — exactly one of the two writers reaches the terminal.
type IPSecRollbackWorker struct {
	db      *Database
	running atomic.Bool
}

// NewIPSecRollbackWorker binds the worker to the background (durable) Database.
func NewIPSecRollbackWorker(db *Database) *IPSecRollbackWorker {
	return &IPSecRollbackWorker{db: db}
}

// Tick does two things for the IPSec deploy saga, every tick:
//
//  1. It BANKS the captured UUIDs of every tunnel whose saga has not cleanly
//     finished. The UUIDs the collector captured live in the apply command's
//     result, and terminal command rows are pruned after 30 days — the deploy
//     record is never pruned. Banking them as soon as they exist is what makes
//     a rollback possible years later, instead of "the result is gone, clean it
//     by hand".
//  2. It advances every rolling_back tunnel to its terminal.
//
// It returns immediately when a tick is already in flight in this process.
// Errors are logged, never returned: the next tick simply tries again.
func (w *IPSecRollbackWorker) Tick(ctx context.Context) {
	if !w.running.CompareAndSwap(false, true) {
		return
	}
	defer w.running.Store(false)
	if ctx.Err() != nil {
		return
	}
	// (1) Bank the captured UUIDs.
	//
	// The statuses are the ones where the saga has not cleanly finished, i.e.
	// where the deploy poll may never have run and the captures may still be
	// sitting unused in the apply command's result. A tunnel that reached
	// up/down/degraded went through the poll, which already merged them.
	if err := w.bankCapturedUUIDs(ctx); err != nil {
		log.Printf("ipsec-rollback: captured-UUID banking failed: %v", err)
	}
	// (2) Advance the rolling_back tunnels.
	//
	// A focused query — NOT ListIPSecTunnels, which loads every intent (and
	// every PSK ciphertext) just to find the handful of rolling-back rows.
	ids, err := w.db.ListIPSecTunnelsByStatus([]string{IPSecRollbackStatusRollingBack})
	if err != nil {
		log.Printf("ipsec-rollback: rolling_back probe failed: %v", err)
		return
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		status, reason, done, rerr := w.db.ResolveIPSecRollback(id)
		if rerr != nil {
			log.Printf("ipsec-rollback: tunnel %d: resolve failed: %v", id, rerr)
			continue
		}
		if done && (status == IPSecRollbackStatusRolledBack || status == IPSecRollbackStatusRollbackFailed) {
			log.Printf("ipsec-rollback: tunnel %d resolved to %s: %s", id, status, reason)
		}
	}
}

// ipsecSagaUnfinishedStatuses are the tunnel states where the deploy poll may
// never have run, so the apply's captured UUIDs may still be un-banked.
//
// `deploying` is the important one: a tunnel wedged there (its peer was
// decommissioned mid-deploy) is exactly the case where nobody polls, the
// captures sit unused in the command result, and the rollback has nothing to
// delete by. `rolling_back` / `error` / `rollback_failed` are included because a
// rollback started outside the poll (the operator POST, the bulk endpoint) also
// never merges them.
var ipsecSagaUnfinishedStatuses = []string{"deploying", IPSecRollbackStatusRollingBack, "error", "rollback_failed"}

// bankCapturedUUIDs merges the apply's captured UUIDs into the deploy records
// of the tunnels whose saga has not cleanly finished, and persists the ones
// that changed.
func (w *IPSecRollbackWorker) bankCapturedUUIDs(ctx context.Context) error {
	ids, err := w.db.ListIPSecTunnelsByStatus(ipsecSagaUnfinishedStatuses)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		banked, berr := w.db.BankIPSecCapturedUUIDs(id)
		if berr != nil {
			log.Printf("ipsec-rollback: tunnel %d: banking the captured UUIDs failed: %v", id, berr)
			continue
		}
		if banked {
			log.Printf("ipsec-rollback: tunnel %d: banked the apply's captured UUIDs (the command row is pruned after 30 days)", id)
		}
	}
	return nil
}
