package classify

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxMindDownloadURL is MaxMind's edition download endpoint. The same URL serves
// both free GeoLite2 and paid GeoIP2 editions — only the edition_id and the
// license key differ — so one code path covers the free-key and paid-key users.
const maxMindDownloadURL = "https://download.maxmind.com/app/geoip_download"

// maxGeoDownloadBytes caps a single edition download (GeoIP2-City is ~70 MB;
// this leaves generous headroom while refusing a runaway response).
const maxGeoDownloadBytes = 512 << 20

// MaxMindUpdater downloads GeoIP editions into a destination directory (the geo
// resolver's live dir), where they take precedence over the embedded bundle. It
// is nil-safe: a nil updater's methods are no-ops, so callers never branch on
// whether a license key was configured.
type MaxMindUpdater struct {
	licenseKey string
	accountID  string
	editions   []string
	destDir    string
	client     *http.Client
}

// NewMaxMindUpdater returns an updater, or nil when no license key is set (the
// free/bundle-only case). editionIDs is a comma-separated list.
func NewMaxMindUpdater(licenseKey, accountID, editionIDs, destDir string) *MaxMindUpdater {
	if strings.TrimSpace(licenseKey) == "" {
		return nil
	}
	var editions []string
	for _, e := range strings.Split(editionIDs, ",") {
		if e = strings.TrimSpace(e); e != "" {
			editions = append(editions, e)
		}
	}
	if len(editions) == 0 {
		return nil
	}
	return &MaxMindUpdater{
		licenseKey: strings.TrimSpace(licenseKey),
		accountID:  strings.TrimSpace(accountID),
		editions:   editions,
		destDir:    destDir,
		client:     &http.Client{Timeout: 5 * time.Minute},
	}
}

// UpdateAll downloads every configured edition, isolating per-edition failures so
// one bad edition doesn't block the rest. Returns the number that updated and the
// first error encountered (for logging).
func (u *MaxMindUpdater) UpdateAll(ctx context.Context) (int, error) {
	if u == nil {
		return 0, nil
	}
	if err := os.MkdirAll(u.destDir, 0o750); err != nil {
		return 0, fmt.Errorf("geoip live dir %q: %w", u.destDir, err)
	}
	var firstErr error
	updated := 0
	for _, edition := range u.editions {
		if err := u.download(ctx, edition); err != nil {
			log.Printf("geoip-update: %s: %v", edition, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		updated++
		log.Printf("geoip-update: %s → %s/%s.mmdb", edition, u.destDir, edition)
	}
	return updated, firstErr
}

// download fetches one edition's tar.gz, verifies its sha256, extracts the sole
// .mmdb entry, and writes it atomically as <destDir>/<edition>.mmdb.
func (u *MaxMindUpdater) download(ctx context.Context, edition string) error {
	want, err := u.fetchSHA256(ctx, edition)
	if err != nil {
		return fmt.Errorf("sha256: %w", err)
	}
	req, err := u.newRequest(ctx, edition, "tar.gz")
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	// Buffer to a temp file while hashing, so we can verify before extracting.
	tmpGz, err := os.CreateTemp(u.destDir, "."+edition+"-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmpGz.Name())
	defer tmpGz.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmpGz, h), io.LimitReader(resp.Body, maxGeoDownloadBytes))
	if err != nil {
		return err
	}
	if n >= maxGeoDownloadBytes {
		return fmt.Errorf("download exceeded %d bytes", maxGeoDownloadBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}
	if _, err := tmpGz.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return u.extractMMDB(tmpGz, edition)
}

// extractMMDB pulls the single .mmdb out of the tar.gz and atomically renames it
// into place as <edition>.mmdb.
func (u *MaxMindUpdater) extractMMDB(r io.Reader, edition string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("no .mmdb in archive")
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		dst := filepath.Join(u.destDir, edition+".mmdb")
		tmp, err := os.CreateTemp(u.destDir, "."+edition+"-*.mmdb")
		if err != nil {
			return err
		}
		if _, err := io.Copy(tmp, io.LimitReader(tr, maxGeoDownloadBytes)); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return err
		}
		tmp.Close()
		// Atomic rename so the reload ticker never observes a half-written file.
		if err := os.Rename(tmp.Name(), dst); err != nil {
			os.Remove(tmp.Name())
			return err
		}
		return nil
	}
}

// fetchSHA256 downloads the edition's .sha256 sidecar and returns the hex digest.
func (u *MaxMindUpdater) fetchSHA256(ctx context.Context, edition string) (string, error) {
	req, err := u.newRequest(ctx, edition, "tar.gz.sha256")
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	// Format: "<64-hex>  <filename>".
	fields := strings.Fields(string(body))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return "", fmt.Errorf("unexpected sha256 body")
	}
	return fields[0], nil
}

func (u *MaxMindUpdater) newRequest(ctx context.Context, edition, suffix string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, maxMindDownloadURL, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("edition_id", edition)
	q.Set("license_key", u.licenseKey)
	q.Set("suffix", suffix)
	req.URL.RawQuery = q.Encode()
	// MaxMind also accepts account-id + license-key via HTTP Basic auth; set it
	// when an account id is configured (harmless alongside the query-param key).
	if u.accountID != "" {
		req.SetBasicAuth(u.accountID, u.licenseKey)
	}
	return req, nil
}
