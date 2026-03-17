package database

import (
	"log"
	"sync"
	"time"
)

// BatchInserter buffers items of type T and flushes them in batches,
// either when the buffer reaches maxSize or on a periodic timer.
type BatchInserter[T any] struct {
	mu            sync.Mutex
	buf           []T
	maxSize       int
	flushInterval time.Duration
	flushFn       func([]T) error
	stopCh        chan struct{}
	doneCh        chan struct{}
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
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.Flush()
			case <-b.stopCh:
				close(b.doneCh)
				return
			}
		}
	}()

	return b
}

// Add appends an item to the buffer in a thread-safe manner.
// If the buffer reaches maxSize, it flushes immediately.
func (b *BatchInserter[T]) Add(item T) {
	b.mu.Lock()
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

// Stop signals the background goroutine to exit, waits for it to finish,
// then performs a final flush of any remaining items.
func (b *BatchInserter[T]) Stop() {
	close(b.stopCh)
	<-b.doneCh
	b.Flush()
}
