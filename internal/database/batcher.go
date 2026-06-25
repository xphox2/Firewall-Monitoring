package database

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"firewall-mon/internal/logging"
)

// BatchInserter buffers items of type T and flushes them in batches,
// either when the buffer reaches maxSize or on a periodic timer.
//
// AUDIT-006 (shutdown half): Stop now sets a `stopped` atomic BEFORE
// closing stopCh. Add checks the atomic and increments a Dropped counter
// instead of appending — guaranteeing no items can enter the buffer after
// Stop returns. The final Flush is performed by the background goroutine
// before it closes doneCh, so Stop returns only after every item that was
// in the buffer at stop-signal time has been handed to flushFn.
//
// AUDIT-006 (durability half — WAL-on-disk + fsync) is deferred: that
// requires a disk format design and operational changes for the operator,
// and is a separate commit.
type BatchInserter[T any] struct {
	mu            sync.Mutex
	buf           []T
	maxSize       int
	flushInterval time.Duration
	flushFn       func([]T) error
	stopCh        chan struct{}
	doneCh        chan struct{}

	stopped atomic.Bool  // set to true at the start of Stop()
	dropped atomic.Int64 // items rejected after stop (visible via Dropped())
}

// NewBatchInserter creates a BatchInserter and starts a background goroutine
// that flushes the buffer on the given interval.
func NewBatchInserter[T any](maxSize int, flushInterval time.Duration, flushFn func([]T) error) *BatchInserter[T] {
	b := &BatchInserter[T]{
		buf:           make([]T, 0, maxSize),
		maxSize:       maxSize,
		flushInterval: flushInterval,
		flushFn:       flushFn,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	go func() {
		// REL-01: a panic in flushFn must not crash the whole process. Recover
		// logs it with a stack and lets the deferred close(doneCh) below still
		// run, so Stop() unblocks instead of the binary aborting.
		defer logging.Recover("db-batcher")
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		// AUDIT-006: close doneCh ONLY after the final Flush completes.
		// Stop()'s <-doneCh therefore returns iff the goroutine has done
		// its last flush, so no items are stuck in the buffer at the
		// moment Stop returns.
		defer close(b.doneCh)
		for {
			select {
			case <-ticker.C:
				b.Flush()
			case <-b.stopCh:
				b.Flush() // final flush BEFORE close(doneCh)
				return
			}
		}
	}()

	return b
}

// Add appends an item to the buffer in a thread-safe manner. If the
// buffer reaches maxSize, it flushes immediately.
//
// AUDIT-006: if Stop has been called, the item is rejected and Dropped
// is incremented. Callers that need a synchronous-write guarantee should
// not use the batcher — write through the regular CreateX path instead.
func (b *BatchInserter[T]) Add(item T) {
	// Fast path: cheap atomic check before taking the mutex.
	if b.stopped.Load() {
		b.dropped.Add(1)
		return
	}

	b.mu.Lock()
	// Re-check under the lock so we don't miss a concurrent Stop racing
	// with this Add. Without the recheck a goroutine could pass the
	// fast-path check, then Stop fires + goroutine drains + closes
	// doneCh, then this goroutine appends — leaking the item past
	// Stop's "everything flushed" promise.
	if b.stopped.Load() {
		b.mu.Unlock()
		b.dropped.Add(1)
		return
	}
	b.buf = append(b.buf, item)
	shouldFlush := len(b.buf) >= b.maxSize
	b.mu.Unlock()

	if shouldFlush {
		b.Flush()
	}
}

// Flush swaps out the current buffer and calls flushFn on the collected items.
// If the buffer is empty, it does nothing. Errors from flushFn are logged but
// not propagated.
func (b *BatchInserter[T]) Flush() {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return
	}
	items := b.buf
	b.buf = make([]T, 0, b.maxSize)
	b.mu.Unlock()

	if err := b.flushFn(items); err != nil {
		log.Printf("BatchInserter flush error: %v", err)
	}
}

// Stop signals the background goroutine to exit and waits for the final
// flush. Safe to call once. Subsequent calls are no-ops.
//
// AUDIT-006: the stopped atomic is set BEFORE close(stopCh) so any Add
// that runs concurrently with Stop sees stopped=true and is rejected
// (counted via Dropped). The goroutine performs the final Flush before
// closing doneCh, so this function returns only after every accepted
// item has been handed to flushFn.
func (b *BatchInserter[T]) Stop() {
	if !b.stopped.CompareAndSwap(false, true) {
		return // already stopped
	}
	close(b.stopCh)
	<-b.doneCh
}

// Dropped returns the number of items that were rejected by Add because
// Stop had already been called. AUDIT-006 metric — exposed for the
// future /metrics endpoint and for operator-visible "did we lose data?"
// diagnostics at shutdown.
func (b *BatchInserter[T]) Dropped() int64 {
	return b.dropped.Load()
}
