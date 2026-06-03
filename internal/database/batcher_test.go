package database

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// helper: collects items received by flushFn into a thread-safe slice.
type flushSink struct {
	mu      sync.Mutex
	batches [][]int
	calls   atomic.Int64
}

func (s *flushSink) fn(items []int) error {
	s.calls.Add(1)
	s.mu.Lock()
	// Copy so caller can recycle its buffer.
	cp := make([]int, len(items))
	copy(cp, items)
	s.batches = append(s.batches, cp)
	s.mu.Unlock()
	return nil
}

func (s *flushSink) all() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int
	for _, b := range s.batches {
		out = append(out, b...)
	}
	return out
}

// TestBatcher_AddFlushesAtMaxSize — when the buffer reaches maxSize,
// it must flush immediately, not wait for the ticker.
func TestBatcher_AddFlushesAtMaxSize(t *testing.T) {
	sink := &flushSink{}
	b := NewBatchInserter[int](3, time.Hour, sink.fn)
	defer b.Stop()

	b.Add(1)
	b.Add(2)
	if got := len(sink.all()); got != 0 {
		t.Fatalf("after 2 adds (maxSize=3): got %d flushed, want 0", got)
	}
	b.Add(3)
	// Allow goroutine scheduling for the synchronous Flush call.
	time.Sleep(20 * time.Millisecond)
	if got := len(sink.all()); got != 3 {
		t.Fatalf("after 3rd add (maxSize=3): got %d flushed, want 3", got)
	}
}

// TestBatcher_StopDrainsBuffer_AUDIT006 — items in the buffer at the
// moment Stop is called must be handed to flushFn before Stop returns.
// Pre-AUDIT-006 the goroutine closed doneCh first, then Stop called its
// own Flush — items added concurrently with Stop could be lost.
func TestBatcher_StopDrainsBuffer_AUDIT006(t *testing.T) {
	sink := &flushSink{}
	b := NewBatchInserter[int](1000, time.Hour, sink.fn) // large maxSize so Add doesn't auto-flush

	for i := 1; i <= 10; i++ {
		b.Add(i)
	}
	b.Stop()

	got := sink.all()
	if len(got) != 10 {
		t.Fatalf("after Stop: flushed=%d, want 10 (Stop must drain buffer)", len(got))
	}
}

// TestBatcher_AddAfterStopRejected_AUDIT006 — Add must reject items
// after Stop was called and bump the Dropped counter.
func TestBatcher_AddAfterStopRejected_AUDIT006(t *testing.T) {
	sink := &flushSink{}
	b := NewBatchInserter[int](1000, time.Hour, sink.fn)

	b.Add(1)
	b.Stop()

	// All adds after Stop must be dropped.
	b.Add(2)
	b.Add(3)
	b.Add(4)

	if got := sink.all(); len(got) != 1 || got[0] != 1 {
		t.Errorf("flushed = %v, want [1]", got)
	}
	if dropped := b.Dropped(); dropped != 3 {
		t.Errorf("Dropped() = %d, want 3 (the 3 adds after Stop)", dropped)
	}
}

// TestBatcher_StopIdempotent — calling Stop twice must not panic on
// close-of-closed-channel.
func TestBatcher_StopIdempotent(t *testing.T) {
	sink := &flushSink{}
	b := NewBatchInserter[int](10, time.Hour, sink.fn)
	b.Add(1)
	b.Stop()
	b.Stop() // must be a no-op, not panic
	b.Stop() // and again
}

// TestBatcher_ConcurrentAddDuringStop_AUDIT006 — fire many Add goroutines
// concurrently with Stop. Every item must EITHER appear in the flush sink
// OR be counted in Dropped — never silently lost.
func TestBatcher_ConcurrentAddDuringStop_AUDIT006(t *testing.T) {
	sink := &flushSink{}
	b := NewBatchInserter[int](100, time.Hour, sink.fn)

	const writers = 10
	const itemsPer = 100

	var wg sync.WaitGroup
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < itemsPer; i++ {
				b.Add(g*itemsPer + i)
			}
		}(g)
	}

	// Stop while writers are mid-stride. The exact interleaving varies
	// per run, but the invariant holds: flushed + dropped == sent.
	time.Sleep(2 * time.Millisecond)
	b.Stop()
	wg.Wait()

	flushed := int64(len(sink.all()))
	dropped := b.Dropped()
	total := int64(writers * itemsPer)
	if flushed+dropped != total {
		t.Errorf("AUDIT-006 conservation: flushed (%d) + dropped (%d) = %d, want %d (some items vanished)",
			flushed, dropped, flushed+dropped, total)
	}
	if dropped > 0 {
		t.Logf("dropped %d items after Stop (expected under load — important is they were COUNTED, not vanished)", dropped)
	}
}

// TestBatcher_FlushOnTick — items below maxSize must be flushed by the
// background ticker.
func TestBatcher_FlushOnTick(t *testing.T) {
	sink := &flushSink{}
	b := NewBatchInserter[int](100, 30*time.Millisecond, sink.fn)
	defer b.Stop()

	b.Add(1)
	b.Add(2)

	// Wait long enough for the ticker to fire.
	time.Sleep(100 * time.Millisecond)
	if got := sink.all(); len(got) != 2 {
		t.Errorf("after ticker fire: got %v, want [1 2]", got)
	}
}

// TestBatcher_FlushErrorLoggedNotPropagated — error from flushFn must
// not crash the batcher; the next batch must still flush.
func TestBatcher_FlushErrorLoggedNotPropagated(t *testing.T) {
	var calls atomic.Int64
	failOnce := errors.New("synthetic")
	fn := func(items []int) error {
		c := calls.Add(1)
		if c == 1 {
			return failOnce
		}
		return nil
	}
	b := NewBatchInserter[int](2, time.Hour, fn)
	defer b.Stop()

	b.Add(1) // not yet flushed
	b.Add(2) // triggers flush (errors)
	b.Add(3) // not yet flushed
	b.Add(4) // triggers flush (succeeds)
	time.Sleep(20 * time.Millisecond)

	if got := calls.Load(); got != 2 {
		t.Errorf("flush calls = %d, want 2 (one failing + one succeeding)", got)
	}
}

// TestBatcher_DroppedReflectsExactCount — sanity that the atomic counter
// is exact (no double-increment, no skipped increment).
func TestBatcher_DroppedReflectsExactCount(t *testing.T) {
	sink := &flushSink{}
	b := NewBatchInserter[int](100, time.Hour, sink.fn)
	b.Stop()

	for i := 0; i < 47; i++ {
		b.Add(i)
	}
	if d := b.Dropped(); d != 47 {
		t.Errorf("Dropped() = %d, want 47", d)
	}
}
