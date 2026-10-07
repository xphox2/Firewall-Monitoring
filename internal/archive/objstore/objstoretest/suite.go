// Package objstoretest is the conformance suite every archive target runs:
// the S3 client against the B2-strict fake (internal/archive/s3) and the
// local directory target (internal/archive/local) pass the same tests, so
// the worker, the seal, VerifyMonth and the restore can rely on one
// contract (internal/archive/objstore). Test support only; no binary
// imports it.
package objstoretest

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- the ETag the targets report
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"testing"

	"firewall-mon/internal/archive/objstore"
)

// Harness is one target under test.
type Harness struct {
	Store objstore.Store
	// Prefix is the target's key prefix: Key(rel) must be Prefix+"/"+rel.
	Prefix string
	// Corrupt changes the stored bytes of rel's latest version behind the
	// target's back (same length).
	Corrupt func(t *testing.T, rel string)
	// Versioned: an earlier version stays readable by its version id after
	// a later write of the same key (a versioned bucket, a local directory;
	// not the unversioned in-memory fake).
	Versioned bool
}

func payload(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b) // #nosec G404 -- test data
	return b
}

func hexSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func hexMD5(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) } // #nosec G401 -- the ETag

// Run runs the suite; newHarness builds a fresh, empty, ready target.
func Run(t *testing.T, newHarness func(t *testing.T) Harness) {
	ctx := context.Background()

	t.Run("PutHeadVerifyGet", func(t *testing.T) {
		h := newHarness(t)
		body := payload(3000, 1)
		meta := map[string]string{"fwmon-archive-stream": "syslog", "fwmon-archive-schema": "2"}
		res, err := h.Store.Put(ctx, "syslog/v2/2026-10/03/device-1.ndjson.gz", bytes.NewReader(body), int64(len(body)), meta)
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		if res.Key != h.Prefix+"/syslog/v2/2026-10/03/device-1.ndjson.gz" || res.Size != 3000 || res.SHA256 != hexSHA(body) || res.ETag != hexMD5(body) || res.Parts != 0 {
			t.Fatalf("PutResult %+v", res)
		}
		info, err := h.Store.Head(ctx, res.Rel, "")
		if err != nil {
			t.Fatalf("Head: %v", err)
		}
		if info.Key != res.Key || info.Size != res.Size || info.ETag != res.ETag || info.Metadata["fwmon-archive-stream"] != "syslog" {
			t.Fatalf("Head %+v", info)
		}
		if res.VersionID != "" {
			if v, err := h.Store.Head(ctx, res.Rel, res.VersionID); err != nil || v.ETag != res.ETag {
				t.Fatalf("Head of version %s: %+v %v", res.VersionID, v, err)
			}
		}
		if err := h.Store.VerifyHead(ctx, res); err != nil {
			t.Fatalf("VerifyHead: %v", err)
		}
		var copied bytes.Buffer
		if err := h.Store.VerifyFull(ctx, res, &copied); err != nil {
			t.Fatalf("VerifyFull: %v", err)
		}
		if !bytes.Equal(copied.Bytes(), body) {
			t.Fatal("VerifyFull copied other bytes than were stored")
		}
		got, gi, err := h.Store.GetBytes(ctx, res.Rel, res.VersionID, 1<<20)
		if err != nil || !bytes.Equal(got, body) || gi.ETag != res.ETag || gi.Size != res.Size {
			t.Fatalf("GetBytes: %d bytes, %+v, %v", len(got), gi, err)
		}
		if _, _, err := h.Store.GetBytes(ctx, res.Rel, "", 100); err == nil {
			t.Fatal("GetBytes ignored its limit")
		}
		if n, err := h.Store.Versions(ctx, res.Rel); err != nil || n != 1 {
			t.Fatalf("Versions = %d, %v; want 1", n, err)
		}
		if err := h.Store.Preflight(ctx); err != nil {
			t.Fatalf("Preflight: %v", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		h := newHarness(t)
		if _, err := h.Store.Head(ctx, "syslog/v2/2026-10/_MONTH.json", ""); !errors.Is(err, objstore.ErrNotFound) {
			t.Fatalf("Head of a missing object = %v, want ErrNotFound", err)
		}
		if _, _, err := h.Store.GetBytes(ctx, "syslog/v2/2026-10/_MONTH.json", "", 1<<20); !errors.Is(err, objstore.ErrNotFound) {
			t.Fatalf("GetBytes of a missing object = %v, want ErrNotFound", err)
		}
		want := objstore.PutResult{Rel: "syslog/v2/2026-10/x.json", Key: h.Prefix + "/syslog/v2/2026-10/x.json", Size: 3, SHA256: hexSHA([]byte("abc")), ETag: hexMD5([]byte("abc"))}
		if err := h.Store.VerifyFull(ctx, want, nil); !errors.Is(err, objstore.ErrMismatch) {
			t.Fatalf("VerifyFull of a missing object = %v, want ErrMismatch", err)
		}
		if err := h.Store.VerifyHead(ctx, want); !errors.Is(err, objstore.ErrMismatch) {
			t.Fatalf("VerifyHead of a missing object = %v, want ErrMismatch", err)
		}
		if n, err := h.Store.Versions(ctx, "syslog/v2/2026-10/x.json"); err != nil || n != 0 {
			t.Fatalf("Versions of a missing object = %d, %v", n, err)
		}
	})

	t.Run("CorruptedObjectIsAMismatch", func(t *testing.T) {
		h := newHarness(t)
		body := payload(2048, 2)
		res, err := h.Store.Put(ctx, "sflow/v1/2026-10/03/10/sflow.ndjson.gz", bytes.NewReader(body), int64(len(body)), nil)
		if err != nil {
			t.Fatal(err)
		}
		h.Corrupt(t, res.Rel)
		if err := h.Store.VerifyFull(ctx, res, nil); !errors.Is(err, objstore.ErrMismatch) {
			t.Fatalf("VerifyFull of a corrupted object = %v, want ErrMismatch", err)
		}
	})

	t.Run("WrongExpectationIsAMismatch", func(t *testing.T) {
		h := newHarness(t)
		body := payload(500, 3)
		res, err := h.Store.Put(ctx, "netflow/v1/2026-10/03/10/netflow.ndjson.gz", bytes.NewReader(body), int64(len(body)), nil)
		if err != nil {
			t.Fatal(err)
		}
		bad := res
		bad.SHA256 = hexSHA([]byte("other"))
		if err := h.Store.VerifyFull(ctx, bad, nil); !errors.Is(err, objstore.ErrMismatch) {
			t.Fatalf("VerifyFull with another sha256 = %v", err)
		}
		bad = res
		bad.Size++
		if err := h.Store.VerifyHead(ctx, bad); !errors.Is(err, objstore.ErrMismatch) {
			t.Fatalf("VerifyHead with another size = %v", err)
		}
		bad = res
		bad.ETag = hexMD5([]byte("other"))
		if err := h.Store.VerifyHead(ctx, bad); !errors.Is(err, objstore.ErrMismatch) {
			t.Fatalf("VerifyHead with another ETag = %v", err)
		}
	})

	t.Run("SecondWriteIsANewVersion", func(t *testing.T) {
		h := newHarness(t)
		rel := "syslog/v2/2026-10/03/chunk.json"
		a, b := payload(1500, 4), payload(1600, 5)
		ra, err := h.Store.Put(ctx, rel, bytes.NewReader(a), int64(len(a)), nil)
		if err != nil {
			t.Fatal(err)
		}
		rb, err := h.Store.Put(ctx, rel, bytes.NewReader(b), int64(len(b)), nil)
		if err != nil {
			t.Fatal(err)
		}
		info, err := h.Store.Head(ctx, rel, "")
		if err != nil || info.ETag != rb.ETag || info.Size != rb.Size {
			t.Fatalf("Head of the latest = %+v, %v; want the second write", info, err)
		}
		if err := h.Store.VerifyFull(ctx, rb, nil); err != nil {
			t.Fatalf("VerifyFull of the second write: %v", err)
		}
		if n, err := h.Store.Versions(ctx, rel); err != nil || n != 2 {
			t.Fatalf("Versions = %d, %v; want 2", n, err)
		}
		err = h.Store.VerifyFull(ctx, ra, nil)
		switch {
		case h.Versioned && err != nil:
			t.Fatalf("the first version is no longer readable by its id %q: %v", ra.VersionID, err)
		case !h.Versioned && !errors.Is(err, objstore.ErrMismatch):
			t.Fatalf("an unversioned target verified a replaced object: %v", err)
		}
	})

	t.Run("SameBytesAgainStillVerify", func(t *testing.T) {
		h := newHarness(t)
		rel := "syslog/v2/2026-10/04/device-2.ndjson.gz"
		a := payload(800, 6)
		r1, err := h.Store.Put(ctx, rel, bytes.NewReader(a), int64(len(a)), nil)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := h.Store.Put(ctx, rel, bytes.NewReader(a), int64(len(a)), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range []objstore.PutResult{r1, r2} {
			if err := h.Store.VerifyFull(ctx, r, nil); err != nil {
				t.Fatalf("VerifyFull %+v: %v", r, err)
			}
		}
	})

	t.Run("KeysStayUnderThePrefix", func(t *testing.T) {
		h := newHarness(t)
		for _, rel := range []string{"../escape.json", "/abs.json", "a//b.json", "a/./b.json", "a/../../b.json", ""} {
			if k, err := h.Store.Key(rel); err == nil {
				t.Errorf("Key(%q) = %q, want an error", rel, k)
			}
			if _, err := h.Store.Put(ctx, rel, bytes.NewReader([]byte("x")), 1, nil); err == nil {
				t.Errorf("Put(%q) succeeded", rel)
			}
		}
		if k, err := h.Store.Key("syslog/v2/2026-10/_MONTH.json"); err != nil || k != h.Prefix+"/syslog/v2/2026-10/_MONTH.json" {
			t.Fatalf("Key = %q, %v", k, err)
		}
	})
}
