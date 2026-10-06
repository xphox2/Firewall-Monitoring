// Package s3test is an in-process S3 server for tests: gofakes3 (MIT, memory
// backend) behind a "B2-strict" wrapper that reproduces the Backblaze B2
// behaviour a generic fake does not, so a client that would fail against B2
// fails here first. It is test support only; no binary imports it.
//
// What the wrapper enforces or adds (research/web-archive.md, B2 docs):
//   - any x-amz-checksum-*, x-amz-sdk-checksum-algorithm or x-amz-trailer
//     header is a 400 InvalidArgument "Unsupported header ... received for
//     this API call." (B2's answer to aws-sdk-go-v2 >= v1.73 defaults);
//   - Content-Encoding aws-chunked or a STREAMING-* x-amz-content-sha256 is a
//     400 (chunked / trailer uploads);
//   - every PutObject and UploadPart must carry Content-MD5, and it must match
//     the body (B2 requires it whenever Object Lock applies; the archive sends
//     it always, so the fake requires it always);
//   - Object Lock headers must come as a valid pair (GOVERNANCE|COMPLIANCE and
//     a future RFC 3339 date) and are refused on a bucket without Object Lock
//     (WithoutObjectLock); they are recorded per key and reported back on
//     HEAD / GET, which gofakes3 does not do. GetObjectLockConfiguration
//     answers from the same flag;
//   - every multipart part except the last must be at least 5 MiB
//     (EntityTooSmall at CompleteMultipartUpload);
//   - HEAD / GET of a multipart object report the S3 composite ETag
//     ("<md5 of part md5s>-<n>") as B2 and S3 do (gofakes3 reports the MD5
//     of the whole body);
//   - DeleteObject / DeleteObjects are 403 AccessDenied and counted: the
//     archive's key has no deleteFiles and the app never deletes.
//
// Fail lets a test inject an error response for chosen requests, and
// SetMutateGet a read-back that differs from what was stored.
package s3test

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- S3 Content-MD5 check
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

// Op names the S3 operation of a request.
type Op string

// Operations the wrapper distinguishes.
const (
	OpPutObject      Op = "PutObject"
	OpCreateUpload   Op = "CreateMultipartUpload"
	OpUploadPart     Op = "UploadPart"
	OpCompleteUpload Op = "CompleteMultipartUpload"
	OpAbortUpload    Op = "AbortMultipartUpload"
	OpHeadObject     Op = "HeadObject"
	OpGetObject      Op = "GetObject"
	OpListObjects    Op = "ListObjects"
	OpGetLockConfig  Op = "GetObjectLockConfiguration"
	OpDeleteObject   Op = "DeleteObject"
	OpDeleteObjects  Op = "DeleteObjects"
	OpOther          Op = "Other"
)

// Request is one request the server saw (after the wrapper's checks).
type Request struct {
	Op     Op
	Key    string // object key ("" for bucket-level requests)
	Query  string
	Header http.Header
	Status int // status returned to the client
}

// Retention is the Object Lock state recorded for a key.
type Retention struct {
	Mode        string
	RetainUntil time.Time
}

// Server is the wrapped fake. Its embedded httptest.Server speaks TLS with
// the httptest certificate (valid for 127.0.0.1 and localhost); clients trust
// it through Certificate().
type Server struct {
	*httptest.Server
	Bucket string

	// Fail, when set, is consulted for every request after the B2 checks; a
	// non-zero status is returned as an S3 error with the given code instead
	// of passing the request on.
	Fail func(op Op, r *http.Request) (status int, code string)

	mutateGet func(key string, body []byte) []byte // SetMutateGet

	inner      http.Handler
	objectLock bool // bucket created with Object Lock enabled
	mu         sync.Mutex
	reqs       []Request
	lock       map[string]Retention
	etags      map[string]string        // multipart composite ETag by key
	partSizes  map[string]map[int]int64 // uploadId -> part number -> bytes
}

// MinPartSize is the smallest multipart part B2 accepts, except the last.
const MinPartSize = 5 << 20

// Option configures NewB2Strict.
type Option func(*Server)

// WithoutObjectLock creates the bucket without Object Lock: lock headers are
// refused and GetObjectLockConfiguration reports none.
func WithoutObjectLock() Option { return func(s *Server) { s.objectLock = false } }

// NewB2Strict starts a server with one empty bucket (Object Lock enabled
// unless WithoutObjectLock). It is closed when the test ends.
func NewB2Strict(t testing.TB, bucket string, opts ...Option) *Server {
	t.Helper()
	backend := s3mem.New()
	if err := backend.CreateBucket(bucket); err != nil {
		t.Fatalf("s3test: create bucket: %v", err)
	}
	fake := gofakes3.New(backend,
		gofakes3.WithLogger(gofakes3.DiscardLog()),
		gofakes3.WithIntegrityCheck(true),
		gofakes3.WithoutVersioning(),
	)
	s := &Server{
		Bucket:     bucket,
		inner:      fake.Server(),
		objectLock: true,
		lock:       map[string]Retention{},
		etags:      map[string]string{},
		partSizes:  map[string]map[int]int64{},
	}
	for _, o := range opts {
		o(s)
	}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	// Handshake failures are what some tests provoke; keep them out of the log.
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// SetFail replaces Fail under the server's lock, so a test may change it
// while a client it started is still talking to the server.
func (s *Server) SetFail(f func(op Op, r *http.Request) (status int, code string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Fail = f
}

// SetMutateGet passes the body of every successful GetObject through f
// (given a copy; its result is sent with the original headers): a stored
// object that no longer matches what was uploaded. nil turns it off.
func (s *Server) SetMutateGet(f func(key string, body []byte) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutateGet = f
}

// Requests returns a copy of every request seen so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Count returns how many requests of op were seen.
func (s *Server) Count(op Op) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Op == op {
			n++
		}
	}
	return n
}

// RetentionOf returns the Object Lock state recorded for key.
func (s *Server) RetentionOf(key string) (Retention, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.lock[key]
	return r, ok
}

func classify(r *http.Request, bucket string) (Op, string) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	key := ""
	if rest, ok := strings.CutPrefix(path, bucket+"/"); ok {
		key = rest
	}
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodPut && key != "" && q.Has("uploadId") && q.Has("partNumber"):
		return OpUploadPart, key
	case r.Method == http.MethodPut && key != "" && r.Header.Get("X-Amz-Copy-Source") == "":
		return OpPutObject, key
	case r.Method == http.MethodPost && key != "" && q.Has("uploads"):
		return OpCreateUpload, key
	case r.Method == http.MethodPost && key != "" && q.Has("uploadId"):
		return OpCompleteUpload, key
	case r.Method == http.MethodPost && key == "" && q.Has("delete"):
		return OpDeleteObjects, key
	case r.Method == http.MethodDelete && key != "" && q.Has("uploadId"):
		return OpAbortUpload, key
	case r.Method == http.MethodDelete && key != "":
		return OpDeleteObject, key
	case r.Method == http.MethodHead && key != "":
		return OpHeadObject, key
	case r.Method == http.MethodGet && key != "":
		return OpGetObject, key
	case r.Method == http.MethodGet && key == "" && q.Has("object-lock"):
		return OpGetLockConfig, key
	case r.Method == http.MethodGet && key == "":
		return OpListObjects, key
	}
	return OpOther, key
}

func (s *Server) record(op Op, key string, r *http.Request, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, Request{Op: op, Key: key, Query: r.URL.RawQuery, Header: r.Header.Clone(), Status: status})
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, xmlEscape(msg))
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// check applies the B2 rules. It returns a non-zero status to reject.
func (s *Server) check(op Op, r *http.Request, body []byte) (int, string, string) {
	for name := range r.Header {
		l := strings.ToLower(name)
		if strings.HasPrefix(l, "x-amz-checksum-") || l == "x-amz-sdk-checksum-algorithm" || l == "x-amz-trailer" {
			return http.StatusBadRequest, "InvalidArgument", fmt.Sprintf("Unsupported header '%s' received for this API call.", l)
		}
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked") ||
		strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
		return http.StatusBadRequest, "InvalidArgument", "Unsupported chunked (aws-chunked / STREAMING-*) upload."
	}
	switch op {
	case OpPutObject, OpUploadPart:
		md5b64 := r.Header.Get("Content-Md5")
		if md5b64 == "" {
			return http.StatusBadRequest, "InvalidRequest", "Missing required header for this request: Content-MD5"
		}
		sum := md5.Sum(body) // #nosec G401 -- S3 Content-MD5 check
		if md5b64 != base64.StdEncoding.EncodeToString(sum[:]) {
			return http.StatusBadRequest, "BadDigest", "The Content-MD5 you specified did not match what was received."
		}
	}
	switch op {
	case OpPutObject, OpCreateUpload:
		mode, until := r.Header.Get("X-Amz-Object-Lock-Mode"), r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")
		if mode == "" && until == "" {
			break
		}
		if !s.objectLock {
			return http.StatusBadRequest, "InvalidRequest", "Bucket is missing Object Lock Configuration"
		}
		if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
			return http.StatusBadRequest, "InvalidArgument", fmt.Sprintf("Invalid object lock mode %q", mode)
		}
		ts, err := time.Parse(time.RFC3339, until)
		if err != nil || !ts.After(time.Now()) {
			return http.StatusBadRequest, "InvalidArgument", fmt.Sprintf("Invalid retain-until date %q", until)
		}
	case OpCompleteUpload:
		s.mu.Lock()
		sizes := s.partSizes[r.URL.Query().Get("uploadId")]
		last := 0
		for n := range sizes {
			last = max(last, n)
		}
		for n, size := range sizes {
			if n != last && size < MinPartSize {
				s.mu.Unlock()
				return http.StatusBadRequest, "EntityTooSmall", fmt.Sprintf("Part %d is %d bytes; the minimum is %d except for the last part.", n, size, MinPartSize)
			}
		}
		s.mu.Unlock()
	}
	return 0, "", ""
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	op, key := classify(r, s.Bucket)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IncompleteBody", err.Error())
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	if status, code, msg := s.check(op, r, body); status != 0 {
		s.record(op, key, r, status)
		writeError(w, status, code, msg)
		return
	}
	if op == OpGetLockConfig {
		if !s.objectLock {
			s.record(op, key, r, http.StatusNotFound)
			writeError(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket")
			return
		}
		s.record(op, key, r, http.StatusOK)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
		return
	}
	if op == OpDeleteObject || op == OpDeleteObjects {
		s.record(op, key, r, http.StatusForbidden)
		writeError(w, http.StatusForbidden, "AccessDenied", "The archive key has no deleteFiles capability.")
		return
	}
	s.mu.Lock()
	fail, mutate := s.Fail, s.mutateGet
	s.mu.Unlock()
	if fail != nil {
		if status, code := fail(op, r); status != 0 {
			s.record(op, key, r, status)
			writeError(w, status, code, "injected failure")
			return
		}
	}

	rec := httptest.NewRecorder()
	s.inner.ServeHTTP(rec, r)
	res := rec.Result()
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)

	if res.StatusCode < 300 {
		s.after(op, key, r, res.Header, out)
		if op == OpGetObject && mutate != nil {
			out = mutate(key, append([]byte(nil), out...))
		}
	}
	s.record(op, key, r, res.StatusCode)
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = w.Write(out)
	}
}

// after updates the recorded lock / ETag state for a successful request and
// decorates HEAD / GET responses with it.
func (s *Server) after(op Op, key string, r *http.Request, h http.Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch op {
	case OpPutObject, OpCreateUpload:
		if mode := r.Header.Get("X-Amz-Object-Lock-Mode"); mode != "" {
			ts, _ := time.Parse(time.RFC3339, r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
			s.lock[key] = Retention{Mode: mode, RetainUntil: ts.UTC()}
		} else {
			delete(s.lock, key)
		}
		if op == OpPutObject {
			delete(s.etags, key)
		}
	case OpUploadPart:
		id := r.URL.Query().Get("uploadId")
		if s.partSizes[id] == nil {
			s.partSizes[id] = map[int]int64{}
		}
		var n int
		_, _ = fmt.Sscan(r.URL.Query().Get("partNumber"), &n)
		s.partSizes[id][n] = r.ContentLength
	case OpCompleteUpload:
		var res struct {
			ETag string `xml:"ETag"`
		}
		if xml.Unmarshal(body, &res) == nil && res.ETag != "" {
			s.etags[key] = res.ETag
		}
	case OpHeadObject, OpGetObject:
		if etag, ok := s.etags[key]; ok {
			h.Set("ETag", etag)
		}
		if l, ok := s.lock[key]; ok {
			h.Set("X-Amz-Object-Lock-Mode", l.Mode)
			h.Set("X-Amz-Object-Lock-Retain-Until-Date", l.RetainUntil.Format(time.RFC3339))
		}
	}
}
