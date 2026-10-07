package local

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"firewall-mon/internal/config"
)

// ResolveUnderRoot resolves p's symbolic links and checks that the result is
// an existing directory at or under root (resolved the same way) and outside
// the database volume (config.ArchiveDatabaseDir): a link inside the allowed
// root that leads out of it is refused. It returns the resolved path.
func ResolveUnderRoot(root, p string) (string, error) {
	rroot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", describe("ARCHIVE_ALLOWED_ROOT", root, err)
	}
	rp, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", describe("directory", p, err)
	}
	if !within(rp, rroot) {
		return "", fmt.Errorf("archive local: %s resolves to %s, outside ARCHIVE_ALLOWED_ROOT %s (a symbolic link leads out of it)", p, rp, root)
	}
	if rdb, err := filepath.EvalSymlinks(config.ArchiveDatabaseDir); err == nil && within(rp, rdb) {
		return "", fmt.Errorf("archive local: %s resolves to %s, on the database volume %s", p, rp, config.ArchiveDatabaseDir)
	}
	fi, err := os.Stat(rp)
	if err != nil {
		return "", describe("stat", p, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("archive local: %s is not a directory", p)
	}
	return rp, nil
}

// within reports whether p is dir or below it (both clean and absolute).
func within(p, dir string) bool {
	if dir == string(filepath.Separator) {
		return true
	}
	return p == dir || len(p) > len(dir) && p[:len(dir)] == dir && p[len(dir)] == filepath.Separator
}

// probeResult is what probeWrite measured.
type probeResult struct {
	write, read      time.Duration
	dirSyncSupported bool
	readOnly         bool   // chmod 0444 took effect
	commit           string // how the no-replace commit was done (commitNoReplace)
}

// probeWrite exercises what a write of the archive does, in dir, with n
// bytes: a temporary file written and fsynced (timed), committed under a new
// name, a second commit to that name refused (no overwrite), made read-only,
// the directory fsynced, the file read back and compared (timed). Both files
// are removed.
func probeWrite(ctx context.Context, dir string, n int) (probeResult, error) {
	var res probeResult
	body := make([]byte, n)
	_, _ = rand.Read(body)
	want := sha256.Sum256(body)
	name := ".fwmon-probe-" + randomSuffix()
	final := filepath.Join(dir, name)

	start := time.Now()
	tmp, _, _, err := writeTemp(ctx, dir, name, bytes.NewReader(body), int64(n))
	if err != nil {
		return res, err
	}
	res.write = time.Since(start)
	defer os.Remove(tmp)
	how, err := commitNoReplace(tmp, final)
	if err != nil {
		return res, describe("commit a test file in", dir, err)
	}
	res.commit = how
	defer func() {
		_ = os.Chmod(final, 0o600) // an SMB server refuses to delete a read-only file
		_ = os.Remove(final)
	}()
	tmp2, _, _, err := writeTemp(ctx, dir, name, bytes.NewReader(body[:1]), 1)
	if err != nil {
		return res, err
	}
	defer os.Remove(tmp2)
	switch _, err := commitNoReplace(tmp2, final); {
	case errors.Is(err, errExists):
	case err == nil:
		return res, fmt.Errorf("archive local: %s: a rename replaced an existing file; the archive needs a filesystem that refuses it (hard links or an atomic rename)", dir)
	default:
		return res, describe("commit a second test file in", dir, err)
	}
	if err := os.Chmod(final, objectMode); err == nil {
		if fi, err := os.Stat(final); err == nil && fi.Mode().Perm()&0o222 == 0 {
			res.readOnly = true
		}
	}
	unsupported, err := syncDir(dir)
	if err != nil {
		return res, describe("fsync directory", dir, err)
	}
	res.dirSyncSupported = !unsupported
	start = time.Now()
	got, err := os.ReadFile(final) // #nosec G304 -- the probe's own file
	if err != nil {
		return res, describe("read back a test file in", dir, err)
	}
	res.read = time.Since(start)
	if sum := sha256.Sum256(got); sum != want {
		return res, fmt.Errorf("archive local: %s: a test file read back differs from what was written", dir)
	}
	return res, nil
}

// Check is one line of a Probe report.
type Check struct {
	Name string `json:"name"`
	// OK false is a failure; Warn a finding that does not stop the archive.
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn,omitempty"`
	Detail string `json:"detail"`
}

// Report is what Probe found about a directory.
type Report struct {
	Dir      string  `json:"dir"`
	Resolved string  `json:"resolved,omitempty"`
	OK       bool    `json:"ok"`
	Checks   []Check `json:"checks"`
	FS       *FSInfo `json:"-"`
	FSType   string  `json:"fs_type,omitempty"`
	Free     uint64  `json:"free_bytes,omitempty"`
}

func (r *Report) add(c Check) {
	r.Checks = append(r.Checks, c)
	if !c.OK {
		r.OK = false
	}
}

// probeBytes is the size of the probe's test file.
const probeBytes = 1 << 20

// slowWrite is the write + fsync time of the 1 MiB test file above which the
// probe warns.
const slowWrite = 2 * time.Second

// Probe checks dir for use by the archive (the local target or the staging
// directory): it resolves under root, is a directory, and a 1 MiB test file
// can be written, fsynced, committed without overwriting, read back and
// removed (timed); it reports the filesystem type, free space (below
// minFree is a failure), whether read-only files and directory fsync work.
// It never writes outside dir and leaves nothing behind.
func Probe(ctx context.Context, root, dir string, minFree uint64) *Report {
	r := &Report{Dir: dir, OK: true}
	rp, err := ResolveUnderRoot(root, dir)
	if err != nil {
		r.add(Check{Name: "location", Detail: err.Error()})
		return r
	}
	r.Resolved = rp
	r.add(Check{Name: "location", OK: true, Detail: fmt.Sprintf("%s is a directory under %s", dir, root)})
	if fi, err := StatFS(rp); err != nil {
		r.add(Check{Name: "filesystem", OK: true, Warn: true, Detail: "type and free space unknown: " + err.Error()})
	} else {
		r.FS, r.FSType, r.Free = &fi, fi.Type, fi.FreeBytes
		c := Check{Name: "filesystem", OK: true, Detail: fmt.Sprintf("%s, %s free of %s", fi.Type, gib(fi.FreeBytes), gib(fi.TotalBytes))}
		switch {
		case fi.Type == "overlay" || fi.Type == "tmpfs":
			c.OK, c.Detail = false, fmt.Sprintf("%s is on %s: the container's writable layer or memory, lost with the container; bind-mount a host directory there", dir, fi.Type)
		case fi.Network():
			c.Warn, c.Detail = true, c.Detail+": a network share — the archive waits while it is unreachable (no unarchived row is deleted meanwhile); mount it on the host with _netdev and nofail"
		}
		r.add(c)
		if minFree > 0 && fi.FreeBytes < minFree {
			r.add(Check{Name: "free space", Detail: fmt.Sprintf("%s free, below the %s needed", gib(fi.FreeBytes), gib(minFree))})
		}
	}
	res, err := probeWrite(ctx, rp, probeBytes)
	if err != nil {
		r.add(Check{Name: "write", Detail: err.Error()})
		return r
	}
	w := Check{Name: "write", OK: true, Detail: fmt.Sprintf("1 MiB written and fsynced in %s, committed by %s, a second commit onto the same name refused, read back in %s",
		ms(res.write), res.commit, ms(res.read))}
	if res.write > slowWrite {
		w.Warn, w.Detail = true, w.Detail+": slow — a day of syslog is 0.3-0.7 GB"
	}
	r.add(w)
	if res.commit == commitCheckedRename {
		r.add(Check{Name: "no-replace", OK: true, Warn: true, Detail: "neither hard links nor RENAME_NOREPLACE work here: an object is committed by a rename after checking its name is free, which is not atomic; safe only with one writer per archive directory (the install id in the marker enforces that)"})
	}
	if !res.dirSyncSupported {
		r.add(Check{Name: "directory fsync", OK: true, Warn: true, Detail: "the filesystem does not fsync directories (usual on SMB): a new name's durability is the server's"})
	}
	if !res.readOnly {
		r.add(Check{Name: "read-only files", OK: true, Warn: true, Detail: "chmod 0444 has no effect here (an SMB mount without permission support keeps its file_mode): objects stay writable by the mount's owner"})
	}
	return r
}

func gib(b uint64) string { return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30)) }

func ms(d time.Duration) string { return fmt.Sprintf("%d ms", d.Milliseconds()) }

// SameFS reports whether two filesystems are the same one.
func SameFS(a, b *FSInfo) bool { return a != nil && b != nil && a.Device == b.Device }
