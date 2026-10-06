package s3test

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- S3 Content-MD5
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// rawClient is a plain aws-sdk-go-v2 client against the fake, with the SDK's
// default checksum behaviour unless whenRequired is set.
func rawClient(t *testing.T, s *Server, whenRequired bool) *awss3.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	return awss3.New(awss3.Options{
		Region:       "us-east-005",
		BaseEndpoint: aws.String(s.URL),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("id", "secret", ""),
		HTTPClient:   hc,
		RequestChecksumCalculation: map[bool]aws.RequestChecksumCalculation{
			true: aws.RequestChecksumCalculationWhenRequired, false: aws.RequestChecksumCalculationWhenSupported,
		}[whenRequired],
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
}

// TestB2Strict_RejectsWhatB2Rejects proves the wrapper reproduces the B2
// failures the archive client is built to avoid, so a regression in the
// client's settings fails against this fake rather than in production.
func TestB2Strict_RejectsWhatB2Rejects(t *testing.T) {
	s := NewB2Strict(t, "example-bucket")
	ctx := context.Background()
	body := []byte("hello\n")
	sum := md5.Sum(body) // #nosec G401
	md5b64 := base64.StdEncoding.EncodeToString(sum[:])

	put := func(c *awss3.Client, in awss3.PutObjectInput) error {
		in.Bucket, in.Body = aws.String("example-bucket"), bytes.NewReader(body)
		_, err := c.PutObject(ctx, &in)
		return err
	}

	// The SDK's default (checksum "when supported") sends x-amz-checksum-*.
	if err := put(rawClient(t, s, false), awss3.PutObjectInput{Key: aws.String("a"), ContentMD5: aws.String(md5b64)}); err == nil ||
		!strings.Contains(err.Error(), "Unsupported header 'x-amz-") {
		t.Errorf("default-checksum PutObject = %v, want B2's Unsupported header", err)
	}
	strict := rawClient(t, s, true)
	if err := put(strict, awss3.PutObjectInput{Key: aws.String("b")}); err == nil || !strings.Contains(err.Error(), "Missing required header for this request: Content-MD5") {
		t.Errorf("PutObject without Content-MD5 = %v, want Missing required header", err)
	}
	if err := put(strict, awss3.PutObjectInput{Key: aws.String("c"), ContentMD5: aws.String(base64.StdEncoding.EncodeToString(make([]byte, 16)))}); err == nil || !strings.Contains(err.Error(), "BadDigest") {
		t.Errorf("PutObject with a wrong Content-MD5 = %v, want BadDigest", err)
	}
	if err := put(strict, awss3.PutObjectInput{Key: aws.String("d"), ContentMD5: aws.String(md5b64), ObjectLockMode: types.ObjectLockModeGovernance}); err == nil {
		t.Error("PutObject with a lock mode but no retain-until succeeded")
	}
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := put(strict, awss3.PutObjectInput{Key: aws.String("e"), ContentMD5: aws.String(md5b64),
		ObjectLockMode: types.ObjectLockModeGovernance, ObjectLockRetainUntilDate: aws.Time(until)}); err != nil {
		t.Fatalf("valid PutObject: %v", err)
	}
	if r, ok := s.RetentionOf("e"); !ok || r.Mode != "GOVERNANCE" || !r.RetainUntil.Equal(until) {
		t.Errorf("retention of e = %+v, %v", r, ok)
	}
	head, err := strict.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String("example-bucket"), Key: aws.String("e")})
	if err != nil || head.ObjectLockMode != types.ObjectLockModeGovernance || head.ObjectLockRetainUntilDate == nil || !head.ObjectLockRetainUntilDate.Equal(until) {
		t.Errorf("HEAD lock = %v %v, %v", head.ObjectLockMode, head.ObjectLockRetainUntilDate, err)
	}
	if _, err := strict.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String("example-bucket"), Key: aws.String("e")}); err == nil {
		t.Error("DeleteObject succeeded")
	}
	if s.Count(OpDeleteObject) != 1 {
		t.Errorf("delete count = %d, want 1", s.Count(OpDeleteObject))
	}
}

// TestB2Strict_ObjectLockBucketAndPartSize: lock headers are refused on a
// bucket without Object Lock, and a multipart upload with a non-final part
// under 5 MiB is refused at completion.
func TestB2Strict_ObjectLockBucketAndPartSize(t *testing.T) {
	ctx := context.Background()
	s := NewB2Strict(t, "example-bucket", WithoutObjectLock())
	c := rawClient(t, s, true)
	body := []byte("x")
	sum := md5.Sum(body) // #nosec G401
	_, err := c.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("example-bucket"), Key: aws.String("a"), Body: bytes.NewReader(body),
		ContentMD5: aws.String(base64.StdEncoding.EncodeToString(sum[:])), ObjectLockMode: types.ObjectLockModeGovernance,
		ObjectLockRetainUntilDate: aws.Time(time.Now().Add(time.Hour)),
	})
	if err == nil || !strings.Contains(err.Error(), "Object Lock") {
		t.Errorf("locked PutObject on a bucket without Object Lock = %v", err)
	}
	if _, err := c.GetObjectLockConfiguration(ctx, &awss3.GetObjectLockConfigurationInput{Bucket: aws.String("example-bucket")}); err == nil {
		t.Error("GetObjectLockConfiguration succeeded on a bucket without Object Lock")
	}

	up, err := c.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{Bucket: aws.String("example-bucket"), Key: aws.String("m")})
	if err != nil {
		t.Fatal(err)
	}
	var parts []types.CompletedPart
	for i, n := range []int{1 << 20, 1 << 20} {
		b := bytes.Repeat([]byte{byte(i)}, n)
		ps := md5.Sum(b) // #nosec G401
		out, err := c.UploadPart(ctx, &awss3.UploadPartInput{Bucket: aws.String("example-bucket"), Key: aws.String("m"),
			UploadId: up.UploadId, PartNumber: aws.Int32(int32(i + 1)), Body: bytes.NewReader(b),
			ContentMD5: aws.String(base64.StdEncoding.EncodeToString(ps[:]))})
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(int32(i + 1))})
	}
	_, err = c.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{Bucket: aws.String("example-bucket"), Key: aws.String("m"),
		UploadId: up.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: parts}})
	if err == nil || !strings.Contains(err.Error(), "EntityTooSmall") {
		t.Errorf("complete with a 1 MiB first part = %v, want EntityTooSmall", err)
	}
}
