package guardrails

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// archiveForbiddenRe matches S3 calls the archive must never make from
// shipped code:
//   - deleting objects (the app never deletes; its key should not be able to,
//     and Object Lock is the backstop), or bypassing governance retention;
//   - the feature/s3/manager and feature/s3/transfermanager uploaders, which
//     ignore RequestChecksumCalculation=WhenRequired and send aws-chunked
//     CRC32 trailers that Backblaze B2 rejects.
var archiveForbiddenRe = regexp.MustCompile(`\.DeleteObjects?\(|DeleteObjects?Input\b|DeleteBucket|BypassGovernanceRetention|aws-sdk-go-v2/feature/s3/(?:manager|transfermanager)`)

// TestArchive_NoDeleteNoManagerUploader scans every non-test Go file under
// cmd/ and internal/ (archive plan PR 2: "the application never calls
// DeleteObject; a guardrail grep enforces it").
func TestArchive_NoDeleteNoManagerUploader(t *testing.T) {
	scanned := 0
	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for i, line := range strings.Split(string(src), "\n") {
				if m := archiveForbiddenRe.FindString(line); m != "" {
					t.Errorf("%s:%d uses %q — the archive never deletes objects or bypasses retention, and must not use the s3 manager/transfermanager uploaders (B2 rejects their checksum trailers)", path, i+1, m)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files — the walk roots are wrong", scanned)
	}
}

// TestArchive_ClientChecksumSettings pins the two client settings whose loss
// would make every upload fail against B2, and Content-MD5 on both upload
// calls. The behavioural proof is internal/archive/s3's B2-strict tests; this
// keeps a refactor from dropping a line those tests might not reach.
func TestArchive_ClientChecksumSettings(t *testing.T) {
	src, err := os.ReadFile("../../internal/archive/s3/client.go")
	if err != nil {
		t.Fatalf("read client.go: %v", err)
	}
	body := string(src)
	for _, want := range []string{
		`RequestChecksumCalculation:\s+aws\.RequestChecksumCalculationWhenRequired,`,
		`ResponseChecksumValidation:\s+aws\.ResponseChecksumValidationWhenRequired,`,
		`CheckRedirect:\s+func\(\*http\.Request, \[\]\*http\.Request\) error \{ return http\.ErrUseLastResponse \}`,
		`tr\.DialContext = httputil\.SafeDialContext\(`,
		`tr\.Proxy = nil`,
		`ContinueHeaderThresholdBytes:\s+-1,`,
	} {
		if !regexp.MustCompile(want).MatchString(body) {
			t.Errorf("internal/archive/s3/client.go lost %s", want)
		}
	}
	if n := strings.Count(body, "ContentMD5:"); n != 2 {
		t.Errorf("internal/archive/s3/client.go sets ContentMD5 %d times, want 2 (PutObject and UploadPart)", n)
	}
}

// TestArchive_NoServiceDefaults: no ARCHIVE_* connection key may default to a
// value — the project names no storage service, bucket, region or prefix
// (public repo; required configuration is intended).
func TestArchive_NoServiceDefaults(t *testing.T) {
	src, err := os.ReadFile("../../internal/config/config.go")
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	re := regexp.MustCompile(`getEnv\("(ARCHIVE_[A-Z0-9_]+)",\s*"([^"]*)"\)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 7 {
		t.Fatalf("found %d ARCHIVE_* string reads in config.go, want at least 7 — the regex or the loader moved", len(matches))
	}
	for _, m := range matches {
		if m[2] != "" {
			t.Errorf("%s defaults to %q; archive connection keys must have no default", m[1], m[2])
		}
	}
}
