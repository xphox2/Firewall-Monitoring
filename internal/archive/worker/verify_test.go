package worker

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"firewall-mon/internal/models"
)

// TestContentCheck: the read-back check accepts exactly the recorded NDJSON
// and names what differs otherwise.
func TestContentCheck(t *testing.T) {
	good := "{\"id\":11,\"m\":\"a\"}\n{\"id\":12,\"m\":\"b\"}\n{\"id\":15,\"m\":\"c\"}\n"
	record := func(content string) *models.ArchiveObject {
		sum := sha256.Sum256([]byte(content))
		return &models.ArchiveObject{Sha256Content: hex.EncodeToString(sum[:]), RowCount: 3, RawBytes: int64(len(content)), MinID: 11, MaxID: 15}
	}
	gz := func(s string) []byte {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte(s))
		zw.Close()
		return b.Bytes()
	}
	chunk := &models.ArchiveChunk{IDLo: 10, IDHi: 15}
	run := func(stored []byte, o *models.ArchiveObject) (*contentCheck, error) {
		k := newContentCheck(chunk, o)
		// Write in small pieces, as a network read would.
		for i := 0; i < len(stored); i += 7 {
			if _, err := k.Write(stored[i:min(i+7, len(stored))]); err != nil {
				break
			}
		}
		return k, k.finish()
	}
	k, err := run(gz(good), record(good))
	if err != nil || k.rows != 3 || k.idSum != 38 {
		t.Fatalf("good object: %v rows %d sum %d", err, k.rows, k.idSum)
	}
	for _, c := range []struct {
		name, content, want string
		o                   *models.ArchiveObject
	}{
		{"content hash", good, "sha256_content", func() *models.ArchiveObject { o := record(good); o.Sha256Content = strings.Repeat("0", 64); return o }()},
		{"row count", good, "rows", func() *models.ArchiveObject { o := record(good); o.RowCount = 4; return o }()},
		{"id bounds", good, "ids 11-15", func() *models.ArchiveObject { o := record(good); o.MinID = 12; return o }()},
		{"not json", "{\"id\":11}\nnot json\n", "not JSON", nil},
		{"no id", "{\"x\":1}\n", "no id", nil},
		{"outside chunk", "{\"id\":16}\n", "outside the chunk", nil},
		{"at id_lo", "{\"id\":10}\n", "outside the chunk", nil},
		{"order", "{\"id\":12}\n{\"id\":11}\n", "after", nil},
		{"duplicate", "{\"id\":11}\n{\"id\":11}\n", "after", nil},
		{"unterminated", "{\"id\":11}", "newline", nil},
	} {
		o := c.o
		if o == nil {
			o = record(c.content)
		}
		if _, err := run(gz(c.content), o); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error mentioning %q", c.name, err, c.want)
		}
	}
	if _, err := run([]byte("not gzip at all"), record(good)); err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Errorf("not gzip: %v", err)
	}
	if _, err := run(gz(good)[:20], record(good)); err == nil {
		t.Error("a truncated object passed")
	}
}
