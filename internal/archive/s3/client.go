// Package s3 is the archive's client for S3-compatible object storage
// (Backblaze B2, AWS S3, Wasabi, R2, MinIO, ...), built on the low-level
// aws-sdk-go-v2 service/s3 calls only.
//
// It is deliberately narrow, and every choice below is about not losing or
// mis-verifying data on a non-AWS backend:
//
//   - Request checksums are calculated and response checksums validated only
//     "when required". Since service/s3 v1.73.0 the SDK otherwise sends CRC32
//     x-amz-checksum-* headers or aws-chunked trailers on every upload, which
//     B2 rejects ("Unsupported header 'x-amz-checksum-crc32'"). The upload
//     helpers in feature/s3/manager and feature/s3/transfermanager ignore that
//     setting, so they are not used: multipart is driven here.
//   - Every PutObject and UploadPart carries Content-MD5. It is the integrity
//     check the setting above turns off, and B2 and AWS require it whenever
//     Object Lock retention applies.
//   - Object Lock mode and retain-until are set on every PutObject and
//     CreateMultipartUpload when ARCHIVE_OBJECT_LOCK_DAYS > 0.
//   - Every key is "<ARCHIVE_S3_PREFIX>/<rel>"; nothing can be written outside
//     the prefix.
//   - There is no delete. The archive never removes an object (a failed
//     multipart upload is aborted, which deletes only its unfinished parts);
//     a guardrail test keeps DeleteObject out of the tree.
//   - The endpoint is operator configuration, but unless
//     ARCHIVE_ALLOW_PRIVATE_ENDPOINT is set every dial is pinned to a
//     validated public address (httputil.SafeDialContext, the webhook rule),
//     redirects are never followed, and TLS uses the system roots.
//   - HTTP(S)_PROXY / NO_PROXY are ignored: a proxy would resolve and dial the
//     endpoint itself, out of reach of the pinned dial (and a private proxy
//     address would push operators to ARCHIVE_ALLOW_PRIVATE_ENDPOINT). The
//     archive always connects to the endpoint directly.
//   - No "Expect: 100-continue" (its handling by non-AWS services is
//     unverified); the body follows the headers.
//   - SDK logging is off, and the secret is masked in every error returned.
package s3

import (
	"context"
	"crypto/md5" // #nosec G501 -- Content-MD5 / ETag are the S3 protocol's integrity fields, not a security hash
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"

	"firewall-mon/internal/config"
	"firewall-mon/internal/httputil"
)

const (
	// DefaultPartSize is the upload part size. Objects up to this size are a
	// single PutObject; larger ones are multipart in parts of this size (B2:
	// 5 MB minimum except the last part, 10 000 parts at most).
	DefaultPartSize int64 = 16 << 20
	maxParts              = 10000
	minPartSize     int64 = 5 << 20

	dialTimeout           = 30 * time.Second
	responseHeaderTimeout = 2 * time.Minute
	abortTimeout          = 30 * time.Second
)

// Client talks to one bucket under one prefix.
type Client struct {
	api      *awss3.Client
	bucket   string
	prefix   string
	lockDays int
	lockMode types.ObjectLockMode
	secret   config.Secret // only for masking errors; Reveal()ed for the signer in New
	partSize int64
	now      func() time.Time
}

// settings are construction knobs the tests use.
type settings struct {
	rootCAs     *x509.CertPool
	partSize    int64
	now         func() time.Time
	maxAttempts int // 0 = the SDK default (3 attempts with backoff)
}

// Option is a construction knob. Production passes none; tests use them to
// reach an in-process fake (internal/archive/s3/s3test).
type Option func(*settings)

// WithRootCAs trusts pool for the endpoint's TLS certificate (a test server's
// self-signed one) instead of the system roots.
func WithRootCAs(pool *x509.CertPool) Option { return func(s *settings) { s.rootCAs = pool } }

// WithPartSize sets the multipart part size (at least 5 MiB; default 16 MiB).
func WithPartSize(n int64) Option { return func(s *settings) { s.partSize = n } }

// WithMaxAttempts sets the SDK's attempts per request (0 = its default, 3).
func WithMaxAttempts(n int) Option { return func(s *settings) { s.maxAttempts = n } }

// New builds a client from the archive configuration. It validates the S3
// keys (config.ArchiveConfig.ValidateS3) and refuses an endpoint whose host is
// a literal loopback / private / link-local address unless
// ARCHIVE_ALLOW_PRIVATE_ENDPOINT is set. It makes no network call.
func New(cfg config.ArchiveConfig, opts ...Option) (*Client, error) {
	s := settings{partSize: DefaultPartSize, now: time.Now}
	for _, o := range opts {
		o(&s)
	}
	if s.partSize < minPartSize {
		return nil, fmt.Errorf("archive s3: part size %d is below the 5 MiB minimum", s.partSize)
	}
	if err := cfg.ValidateS3(); err != nil {
		return nil, err
	}
	endpoint, err := cfg.EndpointURL()
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(endpoint.Hostname()); ip != nil && httputil.IsBlockedIP(ip) && !cfg.AllowPrivateEndpoint {
		return nil, fmt.Errorf("ARCHIVE_S3_ENDPOINT host %s is a private, loopback or link-local address; set ARCHIVE_ALLOW_PRIVATE_ENDPOINT=true for a self-hosted endpoint", ip)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // see the package doc: never via an environment proxy
	if !cfg.AllowPrivateEndpoint {
		tr.DialContext = httputil.SafeDialContext(dialTimeout)
	}
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.rootCAs}
	tr.ResponseHeaderTimeout = responseHeaderTimeout
	hc := &http.Client{
		Transport: tr,
		// A redirect would send a signed request somewhere the operator did
		// not configure. S3 APIs answer with an error, never a redirect, so
		// the 3xx is returned to the SDK as the response.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	api := awss3.New(awss3.Options{
		Region:       cfg.Region,
		BaseEndpoint: aws.String(endpoint.String()),
		UsePathStyle: cfg.PathStyle,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey.Reveal(), ""),
		HTTPClient:   hc,
		// See the package doc: never send x-amz-checksum-* / aws-chunked.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
		Logger:                     logging.Nop{},
		ClientLogMode:              0,
		// Never send "Expect: 100-continue" (the SDK does above 2 MiB).
		ContinueHeaderThresholdBytes: -1,
		RetryMaxAttempts:             s.maxAttempts,
		DisableS3ExpressSessionAuth:  aws.Bool(true),
	})

	c := &Client{
		api:      api,
		bucket:   cfg.Bucket,
		prefix:   cfg.Prefix,
		secret:   cfg.SecretAccessKey,
		partSize: s.partSize,
		now:      s.now,
	}
	if cfg.ObjectLockDays > 0 {
		c.lockDays = cfg.ObjectLockDays
		c.lockMode = types.ObjectLockMode(cfg.LockMode())
	}
	return c, nil
}

// Key returns the full object key for rel ("<prefix>/<rel>"). rel follows the
// prefix's rule: slash-separated [A-Za-z0-9._-] segments, no "." or "..".
func (c *Client) Key(rel string) (string, error) {
	if !config.ValidArchiveKeyPath(rel) {
		return "", fmt.Errorf("archive s3: invalid object key path %q", rel)
	}
	return c.prefix + "/" + rel, nil
}

// PutResult describes an uploaded object. The verify helpers compare against
// it, so callers store it (the manifest) rather than re-deriving it.
type PutResult struct {
	Rel         string    // key below the prefix, as passed to Put
	Key         string    // full object key
	Size        int64     // bytes uploaded
	SHA256      string    // hex sha256 of the bytes uploaded (sha256_object)
	ETag        string    // ETag without quotes: md5 hex, or "<md5 of part md5s>-<parts>"
	Parts       int       // 0 for a single PutObject, else the multipart part count
	VersionID   string    // as returned by the service ("" if unversioned)
	RetainUntil time.Time // Object Lock retain-until sent (zero when lock is off)
}

// Put uploads size bytes of body to rel with Content-MD5 on every request and
// the configured Object Lock retention. body is read twice per part (hash,
// then send), so it must be a stable file or buffer. It returns an error
// unless the service's ETag matches the MD5 the client computed. A failed
// multipart upload is aborted.
func (c *Client) Put(ctx context.Context, rel string, body io.ReaderAt, size int64, meta map[string]string) (PutResult, error) {
	key, err := c.Key(rel)
	if err != nil {
		return PutResult{}, err
	}
	if size < 0 {
		return PutResult{}, fmt.Errorf("archive s3: negative size %d for %s", size, key)
	}
	parts := 1
	if size > c.partSize {
		parts = int((size + c.partSize - 1) / c.partSize)
		if parts > maxParts {
			return PutResult{}, fmt.Errorf("archive s3: %s is %d bytes, more than %d parts of %d", key, size, maxParts, c.partSize)
		}
	}

	// Hash pass: MD5 per part for Content-MD5, SHA-256 of the whole object.
	whole := sha256.New()
	md5s := make([][]byte, parts)
	for i := range md5s {
		off, n := c.partRange(i, size)
		h := md5.New() // #nosec G401 -- S3 Content-MD5
		if got, err := io.Copy(io.MultiWriter(h, whole), io.NewSectionReader(body, off, n)); err != nil {
			return PutResult{}, fmt.Errorf("archive s3: read %s part %d: %w", key, i+1, err)
		} else if got != n {
			return PutResult{}, fmt.Errorf("archive s3: read %s part %d: got %d of %d bytes", key, i+1, got, n)
		}
		md5s[i] = h.Sum(nil)
	}

	res := PutResult{Rel: rel, Key: key, Size: size, SHA256: hex.EncodeToString(whole.Sum(nil))}
	var lockUntil *time.Time
	if c.lockDays > 0 {
		res.RetainUntil = c.now().UTC().Add(time.Duration(c.lockDays) * 24 * time.Hour).Truncate(time.Second)
		lockUntil = aws.Time(res.RetainUntil)
	}

	if size <= c.partSize {
		out, err := c.api.PutObject(ctx, &awss3.PutObjectInput{
			Bucket:                    aws.String(c.bucket),
			Key:                       aws.String(key),
			Body:                      io.NewSectionReader(body, 0, size),
			ContentLength:             aws.Int64(size),
			ContentMD5:                aws.String(base64.StdEncoding.EncodeToString(md5s[0])),
			Metadata:                  meta,
			ObjectLockMode:            c.lockMode,
			ObjectLockRetainUntilDate: lockUntil,
		})
		if err != nil {
			return PutResult{}, c.wrap("put", key, err)
		}
		res.ETag = trimETag(aws.ToString(out.ETag))
		res.VersionID = aws.ToString(out.VersionId)
		if want := hex.EncodeToString(md5s[0]); res.ETag != want {
			return PutResult{}, fmt.Errorf("archive s3: put %s: service ETag %q, want MD5 %s", key, res.ETag, want)
		}
		return res, nil
	}

	res.Parts = parts
	created, err := c.api.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
		Bucket:                    aws.String(c.bucket),
		Key:                       aws.String(key),
		Metadata:                  meta,
		ObjectLockMode:            c.lockMode,
		ObjectLockRetainUntilDate: lockUntil,
	})
	if err != nil {
		return PutResult{}, c.wrap("create multipart upload", key, err)
	}
	uploadID := created.UploadId
	etag, versionID, err := c.uploadParts(ctx, key, uploadID, body, size, md5s)
	if err != nil {
		// The parent context may be the reason for the failure; the abort
		// still has to reach the service.
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
		defer cancel()
		if _, aerr := c.api.AbortMultipartUpload(actx, &awss3.AbortMultipartUploadInput{
			Bucket: aws.String(c.bucket), Key: aws.String(key), UploadId: uploadID,
		}); aerr != nil {
			err = errors.Join(err, c.wrap("abort multipart upload", key, aerr))
		}
		return PutResult{}, err
	}
	res.ETag, res.VersionID = etag, versionID
	return res, nil
}

// uploadParts sends every part and completes the upload, checking each
// part's ETag and the final composite ETag against the computed MD5s.
func (c *Client) uploadParts(ctx context.Context, key string, uploadID *string, body io.ReaderAt, size int64, md5s [][]byte) (etag, versionID string, err error) {
	done := make([]types.CompletedPart, len(md5s))
	for i, sum := range md5s {
		off, n := c.partRange(i, size)
		out, err := c.api.UploadPart(ctx, &awss3.UploadPartInput{
			Bucket:        aws.String(c.bucket),
			Key:           aws.String(key),
			UploadId:      uploadID,
			PartNumber:    aws.Int32(int32(i + 1)),
			Body:          io.NewSectionReader(body, off, n),
			ContentLength: aws.Int64(n),
			ContentMD5:    aws.String(base64.StdEncoding.EncodeToString(sum)),
		})
		if err != nil {
			return "", "", c.wrap(fmt.Sprintf("upload part %d of", i+1), key, err)
		}
		if got, want := trimETag(aws.ToString(out.ETag)), hex.EncodeToString(sum); got != want {
			return "", "", fmt.Errorf("archive s3: upload part %d of %s: service ETag %q, want MD5 %s", i+1, key, got, want)
		}
		done[i] = types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(int32(i + 1))}
	}
	out, err := c.api.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{
		Bucket:          aws.String(c.bucket),
		Key:             aws.String(key),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: done},
	})
	if err != nil {
		return "", "", c.wrap("complete multipart upload", key, err)
	}
	want := MultipartETag(md5s)
	if got := trimETag(aws.ToString(out.ETag)); got != want {
		return "", "", fmt.Errorf("archive s3: complete %s: service ETag %q, want %s", key, got, want)
	}
	return want, aws.ToString(out.VersionId), nil
}

// MultipartETag is the S3 composite ETag of a multipart object: the hex MD5 of
// the concatenated binary part MD5s, then "-<part count>".
func MultipartETag(partMD5s [][]byte) string {
	h := md5.New() // #nosec G401 -- S3 multipart ETag
	for _, s := range partMD5s {
		h.Write(s)
	}
	return fmt.Sprintf("%s-%d", hex.EncodeToString(h.Sum(nil)), len(partMD5s))
}

func (c *Client) partRange(i int, size int64) (off, n int64) {
	off = int64(i) * c.partSize
	n = min(c.partSize, size-off)
	return off, n
}

func trimETag(s string) string { return strings.Trim(s, `"`) }

// ObjectInfo is what HEAD reports about an object.
type ObjectInfo struct {
	Key         string
	Size        int64
	ETag        string // without quotes
	VersionID   string
	LockMode    string    // "" when the service does not report it
	RetainUntil time.Time // zero when the service does not report it
	Metadata    map[string]string
}

// Head returns an object's metadata. A non-empty versionID addresses that
// version.
func (c *Client) Head(ctx context.Context, rel, versionID string) (ObjectInfo, error) {
	key, err := c.Key(rel)
	if err != nil {
		return ObjectInfo{}, err
	}
	in := &awss3.HeadObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)}
	if versionID != "" {
		in.VersionId = aws.String(versionID)
	}
	out, err := c.api.HeadObject(ctx, in)
	if err != nil {
		return ObjectInfo{}, c.wrap("head", key, err)
	}
	info := ObjectInfo{
		Key:       key,
		Size:      aws.ToInt64(out.ContentLength),
		ETag:      trimETag(aws.ToString(out.ETag)),
		VersionID: aws.ToString(out.VersionId),
		LockMode:  string(out.ObjectLockMode),
		Metadata:  out.Metadata,
	}
	if out.ObjectLockRetainUntilDate != nil {
		info.RetainUntil = out.ObjectLockRetainUntilDate.UTC()
	}
	return info, nil
}

// VerifyHead checks the stored object against want with one HEAD: size and
// ETag, plus the Object Lock mode and retain-until when the service reports
// them (B2 does when the key may read file retentions).
func (c *Client) VerifyHead(ctx context.Context, want PutResult) error {
	info, err := c.Head(ctx, want.Rel, want.VersionID)
	if err != nil {
		return err
	}
	switch {
	case info.Size != want.Size:
		return fmt.Errorf("archive s3: verify %s: size %d, want %d", want.Key, info.Size, want.Size)
	case info.ETag != want.ETag:
		return fmt.Errorf("archive s3: verify %s: ETag %q, want %q", want.Key, info.ETag, want.ETag)
	}
	if c.lockDays > 0 {
		if info.LockMode != "" && info.LockMode != string(c.lockMode) {
			return fmt.Errorf("archive s3: verify %s: Object Lock mode %q, want %q", want.Key, info.LockMode, c.lockMode)
		}
		if !info.RetainUntil.IsZero() && info.RetainUntil.Before(want.RetainUntil) {
			return fmt.Errorf("archive s3: verify %s: Object Lock retain-until %s, want at least %s",
				want.Key, info.RetainUntil.Format(time.RFC3339), want.RetainUntil.Format(time.RFC3339))
		}
	}
	return nil
}

// VerifyFull reads the whole object back (the version Put wrote, when the
// service is versioned) and checks its length and SHA-256 against want. Every
// byte read is also written to w (nil discards), so a caller can decompress
// and parse the same stream; whatever w concludes is valid only if VerifyFull
// returns nil.
func (c *Client) VerifyFull(ctx context.Context, want PutResult, w io.Writer) error {
	key, err := c.Key(want.Rel)
	if err != nil {
		return err
	}
	in := &awss3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)}
	if want.VersionID != "" {
		in.VersionId = aws.String(want.VersionID)
	}
	out, err := c.api.GetObject(ctx, in)
	if err != nil {
		return c.wrap("get", key, err)
	}
	defer out.Body.Close()
	if etag := trimETag(aws.ToString(out.ETag)); etag != "" && etag != want.ETag {
		return fmt.Errorf("archive s3: verify %s: GET ETag %q, want %q", want.Key, etag, want.ETag)
	}
	h := sha256.New()
	dst := io.Writer(h)
	if w != nil {
		dst = io.MultiWriter(h, w)
	}
	n, err := io.Copy(dst, out.Body)
	if err != nil {
		return c.wrap("read back", want.Key, err)
	}
	if n != want.Size {
		return fmt.Errorf("archive s3: verify %s: read %d bytes, want %d", want.Key, n, want.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want.SHA256 {
		return fmt.Errorf("archive s3: verify %s: sha256 %s, want %s", want.Key, got, want.SHA256)
	}
	return nil
}

// Preflight lists at most one key under the prefix, which proves the
// credentials, bucket and prefix scope work without writing anything. When
// ARCHIVE_OBJECT_LOCK_DAYS > 0 it also reads the bucket's Object Lock
// configuration (B2 key capability readBucketRetentions) and fails unless
// Object Lock is enabled: a PUT with lock headers to a bucket without it is
// rejected, and finding that out on the first chunk is too late.
func (c *Client) Preflight(ctx context.Context) error {
	_, err := c.api.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{
		Bucket:  aws.String(c.bucket),
		Prefix:  aws.String(c.prefix + "/"),
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return c.wrap("preflight list", c.prefix+"/", err)
	}
	if c.lockDays == 0 {
		return nil
	}
	out, err := c.api.GetObjectLockConfiguration(ctx, &awss3.GetObjectLockConfigurationInput{Bucket: aws.String(c.bucket)})
	if err != nil {
		return c.wrap("preflight object lock configuration of bucket", c.bucket, err)
	}
	if out.ObjectLockConfiguration == nil || out.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return fmt.Errorf("archive s3: bucket %s does not have Object Lock enabled, but ARCHIVE_OBJECT_LOCK_DAYS=%d; enable it on the bucket or set the days to 0", c.bucket, c.lockDays)
	}
	return nil
}

// redactedError masks the secret in an error's text while keeping the chain
// for errors.Is / errors.As.
type redactedError struct {
	err    error
	secret config.Secret
}

func (e *redactedError) Error() string {
	msg := e.err.Error()
	if s := e.secret.Reveal(); s != "" {
		msg = strings.ReplaceAll(msg, s, config.RedactedSecret)
	}
	return msg
}

func (e *redactedError) Unwrap() error { return e.err }

func (c *Client) wrap(op, key string, err error) error {
	return &redactedError{err: fmt.Errorf("archive s3: %s %s: %w", op, key, err), secret: c.secret}
}
