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

// Tick advances every rolling_back tunnel that has reached its terminal.
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
