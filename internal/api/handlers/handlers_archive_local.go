package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/archive/local"
	"firewall-mon/internal/archive/objstore"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"

	"github.com/gin-gonic/gin"
)

// A local or network-share target (ARCHIVE_TARGET=local) and the directories
// the admin form may choose: the local target's ARCHIVE_LOCAL_DIR and the
// staging directory. Both must be under ARCHIVE_ALLOWED_ROOT (environment
// only), the directory the host's archive partition or share is bind-mounted
// on; the server never mounts anything. The routes:
//
//   - GET /admin/api/archive/settings/folders?path=<dir>: the folder picker —
//     the subdirectories of one directory under the root, symbolic links
//     followed only when they stay under it, hidden entries left out. File
//     names are never listed.
//   - The Test and the save of the settings form (handlers_archive_settings.go)
//     probe a chosen directory (local.Probe: write, fsync, rename without
//     overwrite, read back, free space, filesystem type) and compare the
//     filesystems of the target, the staging directory and the database
//     volume.

// archiveFolderLimit bounds the folder picker's listing.
const archiveFolderLimit = 500

// archiveFolder is one subdirectory in the picker.
type archiveFolder struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// ListArchiveFolders lists the subdirectories of a directory under
// ARCHIVE_ALLOWED_ROOT for the folder picker. A path outside the root (by
// its text, or through a symbolic link) is refused.
// GET /admin/api/archive/settings/folders?path=<dir> (admin-only).
func (h *Handler) ListArchiveFolders(c *gin.Context) {
	a := h.archiveSettingsEnv()
	if err := a.ValidateAllowedRoot(); err != nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"ok": false, "message": err.Error()}))
		return
	}
	root := a.Root()
	p := strings.TrimSpace(c.Query("path"))
	if p == "" {
		p = root
	}
	if err := a.CheckArchivePath("path", p); err != nil {
		c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		return
	}
	out := gin.H{"ok": true, "root": root, "path": p, "dirs": []archiveFolder{}}
	if p != root {
		out["parent"] = filepath.Dir(p)
	}
	if mounted, err := local.IsMountPoint(root); err == nil {
		out["root_mounted"] = mounted
	}
	rp, err := local.ResolveUnderRoot(root, p)
	if err != nil {
		out["ok"], out["message"] = false, err.Error()
		c.JSON(http.StatusOK, response.Success(out))
		return
	}
	if fi, err := local.StatFS(rp); err == nil {
		out["fs_type"], out["free_bytes"] = fi.Type, fi.FreeBytes
	}
	ents, err := os.ReadDir(rp)
	if err != nil {
		out["ok"], out["message"] = false, fmt.Sprintf("cannot list %s: %v", p, err)
		c.JSON(http.StatusOK, response.Success(out))
		return
	}
	dirs := []archiveFolder{}
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		full := filepath.Join(p, name)
		switch {
		case e.IsDir():
		case e.Type()&os.ModeSymlink != 0:
			// Listed only when it stays under the root (and leads to a
			// directory): the picker never shows a way out.
			if _, err := local.ResolveUnderRoot(root, full); err != nil {
				continue
			}
		default:
			continue
		}
		dirs = append(dirs, archiveFolder{Name: name, Path: full})
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	if len(dirs) > archiveFolderLimit {
		dirs = dirs[:archiveFolderLimit]
		out["truncated"] = true
	}
	out["dirs"] = dirs
	c.JSON(http.StatusOK, response.Success(out))
}

// archiveDirCheck is the probe of one directory as Test reports it.
type archiveDirCheck struct {
	report *local.Report
}

// archiveRootMounted checks that ARCHIVE_ALLOWED_ROOT is a mount point (the
// bind mount of the host's volume): a directory chosen under a root that is
// not one sits in the container's writable layer.
func archiveRootMounted(root string) error {
	mounted, err := local.IsMountPoint(root)
	if err != nil {
		return fmt.Errorf("ARCHIVE_ALLOWED_ROOT %s: %v", root, err)
	}
	if !mounted {
		return fmt.Errorf("ARCHIVE_ALLOWED_ROOT %s is not a mount point: a directory under it is in the container's writable layer; bind-mount the host's archive partition or share there (docs/OPERATIONS.md, \"Raw archive: a local or network-share target\")", root)
	}
	return nil
}

// probeArchiveDir probes dir (the local target or the staging directory)
// under ARCHIVE_ALLOWED_ROOT. Probes write test files, and they write only
// under the root: a directory outside it (a staging directory set before
// 0.11.315 and kept) is reported as not probed.
func probeArchiveDir(ctx context.Context, a config.ArchiveConfig, dir string) archiveDirCheck {
	if a.CheckArchivePath("dir", dir) != nil {
		return archiveDirCheck{report: &local.Report{Dir: dir, OK: true, Checks: []local.Check{{Name: "location", OK: true, Warn: true,
			Detail: dir + " is outside ARCHIVE_ALLOWED_ROOT " + a.Root() + ": kept from before 0.11.315, not probed (nothing is written outside the root); choose a directory under the root to have it checked"}}}}
	}
	r := local.Probe(ctx, a.Root(), dir, 0)
	if err := archiveRootMounted(a.Root()); err != nil {
		r.Checks = append([]local.Check{{Name: "mount", Detail: err.Error()}}, r.Checks...)
		r.OK = false
	}
	return archiveDirCheck{report: r}
}

// failed is the first failed check's detail ("" when every check passed).
func (d archiveDirCheck) failed() string {
	for _, c := range d.report.Checks {
		if !c.OK {
			return c.Detail
		}
	}
	return ""
}

// archiveFSWarnings compares the filesystems of the target, the staging
// directory and the database volume: an archive on the database's disk is no
// separate copy and competes for the space the retention protects; target
// and staging on one filesystem share their free space.
func archiveFSWarnings(target, staging *local.FSInfo) []string {
	var w []string
	var db *local.FSInfo
	if fi, err := local.StatFS(config.ArchiveDatabaseDir); err == nil {
		db = &fi
	}
	if local.SameFS(target, db) {
		w = append(w, "The archive target is on the same filesystem as the database volume "+config.ArchiveDatabaseDir+": it is no separate copy, and it fills the disk the retention protects. Use another disk or a share.")
	}
	if local.SameFS(staging, db) {
		w = append(w, "The staging directory is on the same filesystem as the database volume "+config.ArchiveDatabaseDir+": a day of compressed syslog is written there before the upload.")
	}
	if local.SameFS(target, staging) {
		w = append(w, "The archive target and the staging directory are on the same filesystem: they share its free space (and a failing disk takes both).")
	}
	return w
}

// testLocalTarget is Test connection for a local target: the configuration,
// the root's mount, the directory probe and its marker. It fills out (ok,
// message, checks) and returns the target's filesystem.
func testLocalTarget(ctx context.Context, db database.Store, a config.ArchiveConfig, out gin.H) *local.FSInfo {
	if err := a.ValidateLocal(); err != nil {
		out["ok"], out["message"] = false, err.Error()
		return nil
	}
	pc := probeArchiveDir(ctx, a, a.LocalDir)
	out["checks"] = pc.report.Checks
	if msg := pc.failed(); msg != "" {
		out["ok"], out["message"] = false, "The directory cannot hold the archive: "+msg
		return pc.report.FS
	}
	note, err := archiveLocalPreflight(ctx, db, a)
	if err != nil {
		out["ok"], out["message"] = false, err.Error()
		return pc.report.FS
	}
	out["message"] = fmt.Sprintf("%s is writable (%s). %s Object Lock does not exist on a directory: make the storage immutable (ZFS snapshots, a WORM share).", a.LocalBase(), pc.report.FSType, note)
	return pc.report.FS
}

// archiveLocalPreflight runs the local target's preflight. A directory
// without the marker passes while the archive holds no chunk (the worker
// initialises it on its first pass); with chunks it is refused — the share
// holding them is probably not mounted. note says which.
func archiveLocalPreflight(ctx context.Context, db database.Store, a config.ArchiveConfig) (note string, err error) {
	st, err := local.New(a)
	if err != nil {
		return "", err
	}
	id, err := db.ArchiveInstallID(ctx)
	if err != nil {
		return "", err
	}
	st.SetInstallID(id)
	err = st.Preflight(ctx)
	switch {
	case err == nil:
		return "The archive's marker is there.", nil
	case !errors.Is(err, objstore.ErrUninitialized):
		return "", err
	}
	has, herr := db.ArchiveHasChunks(ctx)
	if herr != nil {
		return "", herr
	}
	if has {
		return "", fmt.Errorf("%v; the archive holds chunks, so a directory without the marker is not where they are: mount the share holding them", err)
	}
	if _, perr := local.ResolveUnderRoot(a.Root(), a.LocalDir); perr != nil {
		return "", perr
	}
	return "The archive worker initialises " + a.LocalBase() + " (and its marker " + local.MarkerName + ") on its first pass.", nil
}

// testStaging is Test connection's staging part: the probe of the staging
// directory (under the root, or set before outside it and unchanged) and the
// worker's free space floor. It fills out["staging"] and
// out["staging_checks"] and returns the directory's filesystem.
func testStaging(ctx context.Context, d *archiveDraft, out gin.H) *local.FSInfo {
	a := d.after
	if a.StagingDir == "" {
		return nil
	}
	under := a.CheckArchivePath("ARCHIVE_STAGING_DIR", a.StagingDir)
	if d.newStaging() && under != nil {
		out["staging"] = under.Error()
		return nil
	}
	pc := probeArchiveDir(ctx, a, a.StagingDir)
	out["staging_checks"] = pc.report.Checks
	if msg := pc.failed(); msg != "" {
		logArchiveSettingsRefusal("Test connection (staging directory)", http.StatusOK, msg)
		out["staging"] = "Staging directory " + a.StagingDir + ": " + msg
		return pc.report.FS
	}
	if err := archiveStagingCheck(ctx, a.StagingDir, under == nil); err != nil {
		logArchiveSettingsRefusal("Test connection (staging directory)", http.StatusOK, err.Error())
		out["staging"] = err.Error()
		return pc.report.FS
	}
	if under != nil {
		out["staging"] = "Staging directory " + a.StagingDir + " (outside the allowed root, kept: not probed for writing) has enough free space."
		return pc.report.FS
	}
	out["staging"] = "Staging directory " + a.StagingDir + " is writable with enough free space."
	return pc.report.FS
}

// archiveDirsForSave checks, for a re-authenticated save, every directory the
// draft chooses: a changed staging directory and a local target that is new
// or changed (probe; under a mounted root). The first failure is returned.
func archiveDirsForSave(ctx context.Context, d *archiveDraft) error {
	a := d.after
	if d.newStaging() {
		if msg := probeArchiveDir(ctx, a, a.StagingDir).failed(); msg != "" {
			return fmt.Errorf("staging directory %s: %s", a.StagingDir, msg)
		}
	}
	if a.IsLocal() && a.LocalDir != "" && (!d.before.IsLocal() || a.LocalDir != d.before.LocalDir) {
		if msg := probeArchiveDir(ctx, a, a.LocalDir).failed(); msg != "" {
			return fmt.Errorf("archive directory %s: %s", a.LocalDir, msg)
		}
	}
	return nil
}

// archiveRootProblem says why the allowed root cannot be used ("" when it
// can), for the settings view.
func archiveRootProblem(a config.ArchiveConfig) string {
	if err := a.ValidateAllowedRoot(); err != nil {
		return err.Error()
	}
	return ""
}
