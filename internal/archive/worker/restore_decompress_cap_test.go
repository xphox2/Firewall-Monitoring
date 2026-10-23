package worker

import (
	"bytes"
	"compress/gzip"
	"testing"
)

// TestEachLine_DecompressionCap pins D-8: the total decompressed bytes are
// bounded by maxBytes, so a compressed object that expands far past its
// manifest-recorded size (a decompression bomb) is truncated, not buffered
// whole into a single ReadBytes line.
func TestEachLine_DecompressionCap(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 1<<20) // 1 MiB, no newlines
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	var total int
	if err := eachLine(&buf, 64<<10, func(line []byte) error {
		total += len(line)
		return nil
	}); err != nil {
		t.Fatalf("eachLine: %v", err)
	}
	if total > 64<<10 {
		t.Errorf("decompressed %d bytes, want <= %d", total, 64<<10)
	}
}
