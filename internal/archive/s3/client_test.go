package s3

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- test computes the expected S3 ETag
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"

	"firewall-mon/internal/archive/s3/s3test"
	"firewall-mon/internal/config"
)

const (
	testBucket = "example-bucket"
	testPrefix = "fwmon-test/archive"
	testSecret = "TESTSECRETdoNotLeak0123456789abcdefABCDEF"
	testPart   = 5 << 20
)

func testConfig(endpoint string) config.ArchiveConfig {
	return config.ArchiveConfig{
		SyslogEnabled:        true,
		Endpoint:             endpoint,
		Region:               "us-east-005",
		Bucket:               testBucket,
		Prefix:               testPrefix,
		AccessKeyID:          "005exampleKeyID",
		SecretAccessKey:      config.Secret(testSecret),
		PathStyle:            true,
		ObjectLockDays:       400,
		ObjectLockMode:       "GOVERNANCE",
		MinAgeHours:          2,
		AllowPrivateEndpoint: true, // the fake listens on 127.0.0.1
	}
}

func certPool(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

func withRoots(p *x509.CertPool) option     { return func(s *settings) { s.rootCAs = p } }
func withPartSize(n int64) option           { return func(s *settings) { s.partSize = n } }
func withNow(f func() time.Time) option     { return func(s *settings) { s.now = f } }
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func newFakeClient(t *testing.T, cfg func(*config.ArchiveConfig)) (*Client, *s3test.Server) {
	t.Helper()
	srv := s3test.NewB2Strict(t, testBucket)
	c := testConfig(srv.URL)
	if cfg != nil {
		cfg(&c)
	}
	cl, err := New(c, withRoots(certPool(srv.Server)), withPartSize(testPart))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cl, srv
}

func payload(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// TestPut_B2Strict_SingleAndMultipart uploads a small object (PutObject) and
// an 11 MiB one (3 parts of 5 MiB) through the B2-strict fake and checks what
// was sent and what is reported back: Content-MD5 on every upload request,
// no checksum headers, Object Lock on every create, the S3 ETags, both
// verify helpers, and no delete.
func TestPut_B2Strict_SingleAndMultipart(t *testing.T) {
	cl, srv := newFakeClient(t, nil)
	ctx := context.Background()
	start := time.Now().UTC()

	small := payload(1000, 1)
	large := payload(11<<20, 2)
	meta := map[string]string{"fwmon-archive-schema": "v1"}

	rs, err := cl.Put(ctx, "syslog/v1/2026-10/2026-10-04/device-7.ndjson.gz", bytes.NewReader(small), int64(len(small)), meta)
	if err != nil {
		t.Fatalf("Put small: %v", err)
	}
	rl, err := cl.Put(ctx, "sflow/v1/2026-10/2026-10-04T13/flows.ndjson.gz", bytes.NewReader(large), int64(len(large)), meta)
	if err != nil {
		t.Fatalf("Put large: %v", err)
	}

	smallMD5 := md5.Sum(small) // #nosec G401
	if rs.Parts != 0 || rs.ETag != hex.EncodeToString(smallMD5[:]) {
		t.Errorf("small: parts=%d etag=%q, want 0 / md5 %x", rs.Parts, rs.ETag, smallMD5)
	}
	var partMD5s [][]byte
	for off := 0; off < len(large); off += testPart {
		s := md5.Sum(large[off:min(off+testPart, len(large))]) // #nosec G401
		partMD5s = append(partMD5s, s[:])
	}
	if rl.Parts != 3 || rl.ETag != MultipartETag(partMD5s) || !strings.HasSuffix(rl.ETag, "-3") {
		t.Errorf("large: parts=%d etag=%q, want 3 / %s", rl.Parts, rl.ETag, MultipartETag(partMD5s))
	}
	for _, c := range []struct {
		res  PutResult
		data []byte
	}{{rs, small}, {rl, large}} {
		sum := sha256.Sum256(c.data)
		if c.res.SHA256 != hex.EncodeToString(sum[:]) || c.res.Size != int64(len(c.data)) {
			t.Errorf("%s: sha256/size = %s/%d", c.res.Key, c.res.SHA256, c.res.Size)
		}
		if !strings.HasPrefix(c.res.Key, testPrefix+"/") {
			t.Errorf("key %q is outside the prefix", c.res.Key)
		}
		if err := cl.VerifyHead(ctx, c.res); err != nil {
			t.Errorf("VerifyHead: %v", err)
		}
		var got bytes.Buffer
		if err := cl.VerifyFull(ctx, c.res, &got); err != nil {
			t.Errorf("VerifyFull: %v", err)
		}
		if !bytes.Equal(got.Bytes(), c.data) {
			t.Errorf("%s: read-back bytes differ from what was uploaded", c.res.Key)
		}
		ret, ok := srv.RetentionOf(c.res.Key)
		if !ok || ret.Mode != "GOVERNANCE" {
			t.Errorf("%s: retention = %+v, %v; want GOVERNANCE", c.res.Key, ret, ok)
		}
		if lo, hi := start.Add(400*24*time.Hour-time.Second), time.Now().Add(400*24*time.Hour); ret.RetainUntil.Before(lo) || ret.RetainUntil.After(hi) || !ret.RetainUntil.Equal(c.res.RetainUntil) {
			t.Errorf("%s: retain-until %s (result %s), want now+400d", c.res.Key, ret.RetainUntil, c.res.RetainUntil)
		}
	}
	info, err := cl.Head(ctx, rs.Rel, "")
	if err != nil || info.Metadata["fwmon-archive-schema"] != "v1" {
		t.Errorf("Head metadata = %v, %v", info.Metadata, err)
	}

	uploads := 0
	for _, r := range srv.Requests() {
		if r.Status >= 300 {
			t.Errorf("%s %s answered %d", r.Op, r.Key, r.Status)
		}
		for name := range r.Header {
			if l := strings.ToLower(name); strings.HasPrefix(l, "x-amz-checksum") || strings.HasPrefix(l, "x-amz-sdk-checksum") {
				t.Errorf("%s sent %s", r.Op, name)
			}
		}
		switch r.Op {
		case s3test.OpPutObject, s3test.OpUploadPart:
			uploads++
			if r.Header.Get("Content-Md5") == "" {
				t.Errorf("%s without Content-MD5", r.Op)
			}
		}
		switch r.Op {
		case s3test.OpPutObject, s3test.OpCreateUpload:
			if r.Header.Get("X-Amz-Object-Lock-Mode") != "GOVERNANCE" || r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date") == "" {
				t.Errorf("%s without Object Lock headers", r.Op)
			}
		}
	}
	if uploads != 4 || srv.Count(s3test.OpCompleteUpload) != 1 {
		t.Errorf("uploads=%d completes=%d, want 4 (1 put + 3 parts) / 1", uploads, srv.Count(s3test.OpCompleteUpload))
	}
	if n := srv.Count(s3test.OpDeleteObject) + srv.Count(s3test.OpDeleteObjects); n != 0 {
		t.Errorf("%d delete requests", n)
	}
}

// TestPut_NoObjectLockWhenDaysZero: with ARCHIVE_OBJECT_LOCK_DAYS=0 no lock
// header is sent, and Content-MD5 still is.
func TestPut_NoObjectLockWhenDaysZero(t *testing.T) {
	cl, srv := newFakeClient(t, func(c *config.ArchiveConfig) { c.ObjectLockDays, c.ObjectLockMode = 0, "" })
	data := payload(100, 3)
	res, err := cl.Put(context.Background(), "x/a.json", bytes.NewReader(data), int64(len(data)), nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !res.RetainUntil.IsZero() {
		t.Errorf("RetainUntil = %s, want zero", res.RetainUntil)
	}
	if _, ok := srv.RetentionOf(res.Key); ok {
		t.Error("retention recorded with lock days 0")
	}
	for _, r := range srv.Requests() {
		if r.Op == s3test.OpPutObject && (r.Header.Get("X-Amz-Object-Lock-Mode") != "" || r.Header.Get("Content-Md5") == "") {
			t.Errorf("PutObject headers: lock=%q md5=%q", r.Header.Get("X-Amz-Object-Lock-Mode"), r.Header.Get("Content-Md5"))
		}
	}
}

// TestPut_RetainUntilFromClock pins retain-until to the client's clock + days.
func TestPut_RetainUntilFromClock(t *testing.T) {
	srv := s3test.NewB2Strict(t, testBucket)
	now := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	cl, err := New(testConfig(srv.URL), withRoots(certPool(srv.Server)), withNow(fixedNow(now)))
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.Put(context.Background(), "x/b.json", bytes.NewReader([]byte("{}\n")), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(400 * 24 * time.Hour); !res.RetainUntil.Equal(want) {
		t.Errorf("RetainUntil = %s, want %s", res.RetainUntil, want)
	}
}

// TestPut_MultipartFailureAborts: a part rejected by the service fails Put
// and aborts the upload, without completing it.
func TestPut_MultipartFailureAborts(t *testing.T) {
	cl, srv := newFakeClient(t, nil)
	srv.Fail = func(op s3test.Op, r *http.Request) (int, string) {
		if op == s3test.OpUploadPart && r.URL.Query().Get("partNumber") == "2" {
			return http.StatusForbidden, "AccessDenied"
		}
		return 0, ""
	}
	data := payload(11<<20, 4)
	_, err := cl.Put(context.Background(), "x/c.ndjson.gz", bytes.NewReader(data), int64(len(data)), nil)
	if err == nil || !strings.Contains(err.Error(), "upload part 2") {
		t.Fatalf("Put err = %v, want an upload part 2 failure", err)
	}
	aborted := 0
	for _, r := range srv.Requests() {
		if r.Op == s3test.OpAbortUpload && r.Status < 300 {
			aborted++
		}
	}
	if c := srv.Count(s3test.OpCompleteUpload); aborted != 1 || c != 0 {
		t.Errorf("successful aborts=%d completes=%d, want 1/0", aborted, c)
	}
}

// TestPut_RejectsKeysOutsidePrefix: nothing is sent for a bad key path.
func TestPut_RejectsKeysOutsidePrefix(t *testing.T) {
	cl, srv := newFakeClient(t, nil)
	for _, rel := range []string{"", "/a", "a/", "a//b", "../a", "a/../b", "a/./b", "a b", "a\\b", "a?b"} {
		if _, err := cl.Put(context.Background(), rel, bytes.NewReader(nil), 0, nil); err == nil {
			t.Errorf("Put(%q) succeeded", rel)
		}
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid keys", n)
	}
}

// TestVerify_DetectsReplacedObject: once the key holds different bytes, both
// verify helpers reject the earlier result.
func TestVerify_DetectsReplacedObject(t *testing.T) {
	cl, _ := newFakeClient(t, nil)
	ctx := context.Background()
	a, b := payload(2000, 5), payload(2000, 6)
	ra, err := cl.Put(ctx, "x/d.json", bytes.NewReader(a), int64(len(a)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Put(ctx, "x/d.json", bytes.NewReader(b), int64(len(b)), nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.VerifyHead(ctx, ra); err == nil || !strings.Contains(err.Error(), "ETag") {
		t.Errorf("VerifyHead = %v, want an ETag mismatch", err)
	}
	if err := cl.VerifyFull(ctx, ra, nil); err == nil {
		t.Error("VerifyFull accepted replaced content")
	}
}

// TestVerifyFull_DetectsHashMismatch: the full read-back compares SHA-256,
// not only the ETag.
func TestVerifyFull_DetectsHashMismatch(t *testing.T) {
	cl, _ := newFakeClient(t, nil)
	data := payload(500, 7)
	res, err := cl.Put(context.Background(), "x/e.json", bytes.NewReader(data), int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := res
	bad.SHA256 = strings.Repeat("0", 64)
	if err := cl.VerifyFull(context.Background(), bad, nil); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("VerifyFull = %v, want a sha256 mismatch", err)
	}
	short := res
	short.Size++
	if err := cl.VerifyFull(context.Background(), short, nil); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("VerifyFull = %v, want a length mismatch", err)
	}
}

// TestNew_PrivateEndpointPinned: without ARCHIVE_ALLOW_PRIVATE_ENDPOINT a
// literal private address is refused up front and a name resolving to one is
// refused at dial time; with it, the same endpoint works.
func TestNew_PrivateEndpointPinned(t *testing.T) {
	srv := s3test.NewB2Strict(t, testBucket)
	roots := withRoots(certPool(srv.Server))

	cfg := testConfig(srv.URL)
	cfg.AllowPrivateEndpoint = false
	if _, err := New(cfg, roots); err == nil || !strings.Contains(err.Error(), "ARCHIVE_ALLOW_PRIVATE_ENDPOINT") {
		t.Errorf("New(literal 127.0.0.1) = %v, want refusal", err)
	}

	cfg.Endpoint = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	cl, err := New(cfg, roots)
	if err != nil {
		t.Fatalf("New(localhost): %v", err)
	}
	if err := cl.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing to dial blocked address") {
		t.Errorf("Preflight via localhost = %v, want a pinned-dial refusal", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests reached the server", n)
	}

	// The httptest certificate names 127.0.0.1, not localhost.
	cfg.AllowPrivateEndpoint, cfg.Endpoint = true, srv.URL
	cl, err = New(cfg, roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Preflight(context.Background()); err != nil {
		t.Errorf("Preflight with ARCHIVE_ALLOW_PRIVATE_ENDPOINT: %v", err)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 || reqs[0].Op != s3test.OpListObjects || !strings.Contains(reqs[0].Query, "max-keys=1") ||
		!strings.Contains(reqs[0].Query, "prefix="+strings.ReplaceAll(testPrefix, "/", "%2F")+"%2F") {
		t.Errorf("preflight requests = %+v, want one ListObjectsV2 max-keys=1 under the prefix", reqs)
	}
}

// TestClient_DoesNotFollowRedirects: a 307 from the endpoint is not followed.
func TestClient_DoesNotFollowRedirects(t *testing.T) {
	target := s3test.NewB2Strict(t, testBucket)
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	roots := certPool(redir)
	roots.AddCert(target.Certificate())
	cl, err := New(testConfig(redir.URL), withRoots(roots))
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Preflight(context.Background()); err == nil {
		t.Error("Preflight succeeded through a redirect")
	}
	if n := len(target.Requests()); n != 0 {
		t.Errorf("redirect followed: target saw %d requests", n)
	}
}

// TestClient_ErrorsRedactSecret: a service error that echoes the secret is
// masked in the returned error, which still unwraps to the API error.
func TestClient_ErrorsRedactSecret(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>SignatureDoesNotMatch</Code><Message>bad secret %s</Message></Error>`, testSecret)
	}))
	defer srv.Close()
	cl, err := New(testConfig(srv.URL), withRoots(certPool(srv)))
	if err != nil {
		t.Fatal(err)
	}
	err = cl.Preflight(context.Background())
	if err == nil {
		t.Fatal("Preflight succeeded")
	}
	if strings.Contains(err.Error(), testSecret) || !strings.Contains(err.Error(), config.RedactedSecret) {
		t.Errorf("error not redacted: %v", err)
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "SignatureDoesNotMatch" {
		t.Errorf("errors.As(APIError) = %v", apiErr)
	}
}

// TestNew_ValidatesConfig: New refuses an incomplete configuration, and its
// error does not carry the secret.
func TestNew_ValidatesConfig(t *testing.T) {
	cfg := testConfig("https://s3.example.com")
	cfg.Bucket = ""
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "ARCHIVE_S3_BUCKET") {
		t.Errorf("New without bucket = %v", err)
	}
	cfg = testConfig("https://user:" + testSecret + "@s3.example.com")
	if _, err := New(cfg); err == nil || strings.Contains(err.Error(), testSecret) {
		t.Errorf("New with userinfo endpoint = %v", err)
	}
	if _, err := New(testConfig("https://s3.example.com"), withPartSize(1<<20)); err == nil {
		t.Error("New accepted a part size below 5 MiB")
	}
}
