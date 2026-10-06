package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/archive/worker"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v4/disk"
)

// The raw archive's admin-UI settings (A-10): every ARCHIVE_* key can be set
// on Settings → Retention; a stored setting wins over the environment, which
// stays the default (config/archive_fields.go, database/archive_settings.go).
//
//   - GET  /admin/api/archive/settings: every field's value in effect, its
//     source (ui / env / default) and the environment's value. The secret
//     access key is write-only: only whether it is set, and the last four
//     characters of the KEY ID as its hint.
//   - POST /admin/api/archive/settings/test: Test connection — the bucket
//     preflight (list under the prefix, Object Lock check) with the form's
//     values, nothing saved. The secret is the stored one unless the form
//     replaces it — and it must be typed in to test another endpoint or
//     key ID; it is never echoed. A staging directory typed into the form
//     is probed only by the save.
//   - POST /admin/api/archive/settings: save. Checks in order, the cheap ones
//     before the step-up: the body and every value (400, the same
//     validation as the environment: config.ValidateDraft / Validate); a
//     change of the objects' location once a chunk exists (409); then the
//     caller's password + TOTP (403); then the staging directory of an
//     enabled stream (422) and, when a stream is switched on or the
//     connection of an enabled stream changes, the bucket preflight (422).
//     One transaction stores the values (the secret encrypted) and opens the
//     disabled interval of every stream switched off. Audited with the field
//     names only.
//
// The poller picks a save up without a restart: its workers resolve the
// configuration every tick, the retention gate within 30 s.

// archiveSettingMaxLen bounds one value.
const archiveSettingMaxLen = 1024

// archivePreflightTimeout bounds Test connection and the save's preflight.
const archivePreflightTimeout = 30 * time.Second

// archiveS3Options, when non-nil, adds client options to every bucket
// connection these routes make (tests: the fake's TLS root). nil in production.
var archiveS3Options func() []s3.Option

// archiveStagingFree reports the free bytes of dir's filesystem; a variable so
// tests can stand in for it.
var archiveStagingFree = func(ctx context.Context, dir string) (uint64, error) {
	u, err := disk.UsageWithContext(ctx, dir)
	if err != nil {
		return 0, err
	}
	return u.Free, nil
}

// Sources of an archive field's value.
const (
	archiveSourceUI      = "ui"
	archiveSourceEnv     = "env"
	archiveSourceDefault = "default"
)

// archiveFieldView is one field as GET reports it.
type archiveFieldView struct {
	Key        string `json:"key"`
	Kind       string `json:"kind"`
	Section    string `json:"section"`
	Location   bool   `json:"location"`
	Connection bool   `json:"connection"`
	// Value in effect ("" for the secret, always).
	Value string `json:"value"`
	// Source of Value: ui (an admin setting), env, or default (built in).
	Source string `json:"source"`
	// EnvValue is what the field reverts to: the environment's value, or the
	// built-in default ("" for the secret).
	EnvValue string `json:"env_value"`
	// Secret only: whether a value is set, and the key id's last four
	// characters as its hint.
	Set  bool   `json:"set,omitempty"`
	Hint string `json:"hint,omitempty"`
}

// archiveSettingsView is GET's body.
type archiveSettingsView struct {
	Fields []archiveFieldView `json:"fields"`
	// LocationLocked: the archive has chunks, so endpoint, bucket and
	// prefix cannot change from here (OPERATIONS.md).
	LocationLocked bool `json:"location_locked"`
	SyslogEnabled  bool `json:"syslog_enabled"`
	FlowsEnabled   bool `json:"flows_enabled"`
	// Problem: why the configuration in effect is refused ("" = valid).
	Problem string `json:"problem,omitempty"`
	// StagingMinFree is the free space an enabled stream's staging
	// directory needs.
	StagingMinFree uint64 `json:"staging_min_free"`
}

// archiveSettingsRequest is the body of the save and of Test connection.
type archiveSettingsRequest struct {
	// Set maps ARCHIVE_* keys to the values to store.
	Set map[string]string `json:"set"`
	// Revert lists the ARCHIVE_* keys whose admin setting is removed (the
	// environment's value applies again).
	Revert   []string `json:"revert"`
	Password string   `json:"password"`
	TOTPCode string   `json:"totp_code"`
}

// archiveDraft is a request applied to the configuration in effect.
type archiveDraft struct {
	env, before, after config.ArchiveConfig
	beforeUI           map[string]bool
	set                map[string]string
	revert             []string
}

// archiveKeyHint is "…" + the last four characters of a key id ("" when unset).
func archiveKeyHint(keyID string) string {
	r := []rune(keyID)
	if len(r) == 0 {
		return ""
	}
	return "…" + string(r[max(0, len(r)-4):])
}

func (h *Handler) archiveSettingsEnv() config.ArchiveConfig {
	if h.config == nil {
		return config.ArchiveConfig{}
	}
	return h.config.Archive
}

// archiveSettingsView builds GET's body.
func (h *Handler) archiveSettingsView(ctx context.Context, db database.Store) (*archiveSettingsView, error) {
	env := h.archiveSettingsEnv()
	res, err := db.ResolveArchiveConfig(ctx, env)
	if err != nil {
		return nil, err
	}
	locked, err := db.ArchiveHasChunks(ctx)
	if err != nil {
		return nil, err
	}
	a := res.Config
	v := &archiveSettingsView{Fields: []archiveFieldView{}, LocationLocked: locked, SyslogEnabled: a.SyslogEnabled,
		FlowsEnabled: a.FlowsEnabled, StagingMinFree: worker.StagingMinFree()}
	for _, f := range config.ArchiveFields {
		fv := archiveFieldView{Key: f.Env, Kind: f.Kind, Section: f.Section, Location: f.Location, Connection: f.Connection,
			Value: a.Value(f), EnvValue: env.Value(f), Source: archiveSourceDefault}
		switch {
		case res.UI[f.Env]:
			fv.Source = archiveSourceUI
		case env.EnvSet(f.Env):
			fv.Source = archiveSourceEnv
		}
		if f.Kind == config.ArchiveKindSecret {
			fv.Set = a.SecretAccessKey != ""
			if fv.Set {
				fv.Hint = archiveKeyHint(a.AccessKeyID)
			}
		}
		v.Fields = append(v.Fields, fv)
	}
	if err := a.ValidateDraft(); err != nil {
		v.Problem = err.Error()
	}
	return v, nil
}

// GetArchiveSettings reports the archive configuration for the admin form.
// GET /admin/api/archive/settings (admin-only).
func (h *Handler) GetArchiveSettings(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	v, err := h.archiveSettingsView(c.Request.Context(), db)
	if err != nil {
		httputil.InternalError(c, "Failed to read the archive settings", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(v))
}

// errArchiveDraft is a request refused before anything else is checked.
type errArchiveDraft struct{ msg string }

func (e errArchiveDraft) Error() string { return e.msg }

// draft applies req to the configuration in effect. An error is a 400 (an
// errArchiveDraft) or a database failure.
func (h *Handler) draft(ctx context.Context, db database.Store, req archiveSettingsRequest) (*archiveDraft, error) {
	bad := func(format string, args ...any) error { return errArchiveDraft{fmt.Sprintf(format, args...)} }
	if len(req.Set) == 0 && len(req.Revert) == 0 {
		return nil, bad("nothing to change")
	}
	d := &archiveDraft{env: h.archiveSettingsEnv(), set: map[string]string{}}
	res, err := db.ResolveArchiveConfig(ctx, d.env)
	if err != nil {
		return nil, err
	}
	d.before, d.beforeUI = res.Config, res.UI
	reverted := map[string]string{}
	seen := map[string]bool{}
	for _, k := range req.Revert {
		f, ok := config.ArchiveFieldByEnv(k)
		if !ok {
			return nil, bad("unknown archive setting %q", k)
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		if _, both := req.Set[k]; both {
			return nil, bad("%s is both set and reverted", k)
		}
		d.revert = append(d.revert, k)
		if f.Kind == config.ArchiveKindSecret {
			reverted[k] = d.env.SecretAccessKey.Reveal()
		} else {
			reverted[k] = d.env.Value(f)
		}
	}
	for k, raw := range req.Set {
		f, ok := config.ArchiveFieldByEnv(k)
		if !ok {
			return nil, bad("unknown archive setting %q", k)
		}
		if len(raw) > archiveSettingMaxLen || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
			return nil, bad("%s must be at most %d characters with no control characters", k, archiveSettingMaxLen)
		}
		v, set, perr := config.ParseArchiveValue(f, raw)
		switch {
		case perr != nil:
			return nil, bad("%v", perr)
		case !set:
			return nil, bad("%s needs a value (revert it to use the environment's)", k)
		case f.Kind == config.ArchiveKindSecret && v == "":
			return nil, bad("%s cannot be empty: revert it to use the environment's, or enter the key", k)
		case f.Kind == config.ArchiveKindSecret && (v == httputil.RedactedMask || strings.HasPrefix(v, "{enc}")):
			return nil, bad("%s is not a secret access key", k)
		}
		d.set[k] = v
	}
	sort.Strings(d.revert)
	d.after = d.before.WithSettings(reverted).WithSettings(d.set)
	if err := d.after.ValidateDraft(); err != nil {
		return nil, bad("%v", err)
	}
	return d, nil
}

// changedKeys lists, sorted, the keys the draft changes (stored or reverted).
func (d *archiveDraft) changedKeys() []string {
	keys := append([]string(nil), d.revert...)
	for k := range d.set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// switched lists the gate streams the draft turns on or off.
func (d *archiveDraft) switched(on bool) []string {
	var out []string
	for _, s := range database.ArchiveGateStreams {
		if database.ArchiveStreamEnabled(d.after, s) == on && database.ArchiveStreamEnabled(d.before, s) != on {
			out = append(out, s)
		}
	}
	return out
}

// connectionChanged reports whether the draft changes how the bucket is
// reached (any Connection field, the secret included).
func (d *archiveDraft) connectionChanged() bool {
	if d.before.SecretAccessKey.Reveal() != d.after.SecretAccessKey.Reveal() {
		return true
	}
	for _, f := range config.ArchiveFields {
		if f.Connection && d.before.Value(f) != d.after.Value(f) {
			return true
		}
	}
	return false
}

// archivePreflight connects with a and runs the bucket preflight. The error
// text never carries the secret.
func archivePreflight(ctx context.Context, a config.ArchiveConfig) error {
	var opts []s3.Option
	if archiveS3Options != nil {
		opts = archiveS3Options()
	}
	client, err := s3.New(a, append(opts, s3.WithMaxAttempts(1))...)
	if err == nil {
		ctx, cancel := context.WithTimeout(ctx, archivePreflightTimeout)
		defer cancel()
		err = client.Preflight(ctx)
	}
	if err == nil {
		return nil
	}
	msg := err.Error()
	if s := a.SecretAccessKey.Reveal(); s != "" {
		msg = strings.ReplaceAll(msg, s, config.RedactedSecret)
	}
	return errors.New(msg)
}

// archiveStagingCheck checks an enabled stream's staging directory: it
// exists, is a directory this process can write, and has the worker's free
// space floor.
func archiveStagingCheck(ctx context.Context, dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("staging directory %s: %v (create it on a volume with room for a day of compressed syslog)", dir, errors.Unwrap(err))
	}
	if !st.IsDir() {
		return fmt.Errorf("staging directory %s is not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".fwmon-write-check-*")
	if err != nil {
		return fmt.Errorf("staging directory %s is not writable by the server: %v", dir, errors.Unwrap(err))
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	free, err := archiveStagingFree(ctx, dir)
	if err != nil {
		return fmt.Errorf("staging directory %s: free space unknown: %v", dir, err)
	}
	if floor := worker.StagingMinFree(); free < floor {
		return fmt.Errorf("staging directory %s has %d MiB free, below the %d MiB the worker needs to export a chunk", dir, free>>20, floor>>20)
	}
	return nil
}

// TestArchiveSettings runs the bucket preflight with the form's values,
// saving nothing (an empty body tests the configuration in effect). The
// Advanced flags (http, private endpoint) must be the saved ones: widening
// where the server connects needs the re-authenticated save.
// A refused configuration or a failed preflight is a 200 with ok false.
// POST /admin/api/archive/settings/test (admin-only).
func (h *Handler) TestArchiveSettings(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req archiveSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	d, err := h.draftOrEffective(c.Request.Context(), db, req)
	if err != nil {
		var bad errArchiveDraft
		if errors.As(err, &bad) {
			c.JSON(http.StatusOK, response.Success(gin.H{"ok": false, "message": bad.msg}))
			return
		}
		httputil.InternalError(c, "Failed to read the archive settings", err)
		return
	}
	if d.after.AllowHTTP != d.before.AllowHTTP || d.after.AllowPrivateEndpoint != d.before.AllowPrivateEndpoint {
		c.JSON(http.StatusOK, response.Success(gin.H{"ok": false,
			"message": "Save the Advanced settings first: Test connection uses the saved ARCHIVE_ALLOW_HTTP / ARCHIVE_ALLOW_PRIVATE_ENDPOINT"}))
		return
	}
	// The stored secret is only ever sent to the saved endpoint under the
	// saved key ID: testing another endpoint or key ID needs the secret typed
	// into the form (an admin session alone must not make the server sign
	// requests to an arbitrary host with it).
	_, typed := d.set["ARCHIVE_S3_SECRET_ACCESS_KEY"]
	if !typed && (canonicalArchiveEndpoint(d.after) != canonicalArchiveEndpoint(d.before) || d.after.AccessKeyID != d.before.AccessKeyID) {
		c.JSON(http.StatusOK, response.Success(gin.H{"ok": false,
			"message": "Enter the secret access key to test a different endpoint or key ID: the stored secret is only used with the saved ones"}))
		return
	}
	a := d.after
	if err := a.ValidateS3(); err != nil {
		c.JSON(http.StatusOK, response.Success(gin.H{"ok": false, "message": err.Error()}))
		return
	}
	out := gin.H{"ok": true}
	if err := archivePreflight(c.Request.Context(), a); err != nil {
		out["ok"], out["message"] = false, err.Error()
	} else if a.ObjectLockDays > 0 {
		out["message"] = fmt.Sprintf("Listed %s/%s/ and the bucket has Object Lock enabled (%s %d days will be applied).", a.Bucket, a.Prefix, a.LockMode(), a.ObjectLockDays)
	} else {
		out["message"] = fmt.Sprintf("Listed %s/%s/. Object Lock is off (ARCHIVE_OBJECT_LOCK_DAYS 0): not checked.", a.Bucket, a.Prefix)
	}
	switch {
	case a.StagingDir == "":
	case a.StagingDir != d.before.StagingDir:
		// Probing a path typed into the form (stat, a test file) is left to
		// the re-authenticated save.
		out["staging"] = "Staging directory " + a.StagingDir + " is checked when you save."
	default:
		if err := archiveStagingCheck(c.Request.Context(), a.StagingDir); err != nil {
			out["staging"] = err.Error()
		} else {
			out["staging"] = "Staging directory " + a.StagingDir + " is writable with enough free space."
		}
	}
	c.JSON(http.StatusOK, response.Success(out))
}

// draftOrEffective is draft, or — for an empty request — the configuration in
// effect unchanged.
func (h *Handler) draftOrEffective(ctx context.Context, db database.Store, req archiveSettingsRequest) (*archiveDraft, error) {
	if len(req.Set) > 0 || len(req.Revert) > 0 {
		return h.draft(ctx, db, req)
	}
	res, err := db.ResolveArchiveConfig(ctx, h.archiveSettingsEnv())
	if err != nil {
		return nil, err
	}
	return &archiveDraft{env: h.archiveSettingsEnv(), before: res.Config, after: res.Config, beforeUI: res.UI}, nil
}

// SaveArchiveSettings stores the admin archive settings (see the top of this
// file for the order of the checks). POST /admin/api/archive/settings
// (admin-only, password + TOTP).
func (h *Handler) SaveArchiveSettings(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req archiveSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	ctx := c.Request.Context()
	d, err := h.draft(ctx, db, req)
	if err != nil {
		var bad errArchiveDraft
		if errors.As(err, &bad) {
			c.JSON(http.StatusBadRequest, response.Error(bad.msg))
			return
		}
		httputil.InternalError(c, "Failed to read the archive settings", err)
		return
	}
	if _, ok := d.set["ARCHIVE_S3_SECRET_ACCESS_KEY"]; ok && !db.CanEncryptSettings() {
		c.JSON(http.StatusConflict, response.Error("This server has no encryption key, so the secret access key cannot be stored encrypted; set it in the environment instead"))
		return
	}
	if !d.before.SameLocation(d.after) {
		locked, err := db.ArchiveHasChunks(ctx)
		if err != nil {
			httputil.InternalError(c, "Failed to read the archive manifest", err)
			return
		}
		if locked {
			c.JSON(http.StatusConflict, response.Error("The archive already holds chunks at "+archiveLocation(d.before)+
				": the endpoint, bucket and prefix cannot change here, or the manifest would point at objects that are not there. "+
				"See docs/OPERATIONS.md, \"Raw archive: moving the bucket\", for the manual migration."))
			return
		}
	}
	enabling := d.switched(true)
	username, userID, ok := h.reauthCaller(c, db, req.Password, req.TOTPCode)
	if !ok {
		return
	}
	// The staging probe (stat, a test file in the directory) runs only for a
	// re-authenticated caller.
	if d.after.Enabled() && (len(enabling) > 0 || d.before.StagingDir != d.after.StagingDir) {
		if err := archiveStagingCheck(ctx, d.after.StagingDir); err != nil {
			c.JSON(http.StatusUnprocessableEntity, response.Error("Not saved: "+err.Error()))
			return
		}
	}
	if d.after.Enabled() && (len(enabling) > 0 || d.connectionChanged()) {
		if err := archivePreflight(ctx, d.after); err != nil {
			c.JSON(http.StatusUnprocessableEntity, response.Error("Not saved: the bucket preflight failed: "+err.Error()))
			return
		}
	}
	disabling := d.switched(false)
	if err := db.SaveArchiveSettings(ctx, d.set, d.revert, disabling, time.Now()); err != nil {
		httputil.InternalError(c, "Failed to save the archive settings", err)
		return
	}
	target := "changed=" + strings.Join(d.changedKeys(), ",")
	if len(enabling) > 0 {
		target += " enabled=" + strings.Join(enabling, ",")
	}
	if len(disabling) > 0 {
		target += " disabled=" + strings.Join(disabling, ",")
	}
	purgeAuditLog(c, db, username, userID, "archive_settings_update", target, http.StatusOK)

	var warnings []string
	for _, s := range disabling {
		warnings = append(warnings, fmt.Sprintf("Archiving of %s is off: its raw rows are deleted without waiting for the archive, "+
			"and every month from now until it is switched back on is sealed partial.", s))
	}
	v, err := h.archiveSettingsView(ctx, db)
	if err != nil {
		httputil.InternalError(c, "Failed to read the archive settings", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"settings": v, "warnings": warnings,
		"message": "Saved. The poller applies it within a minute, without a restart."}))
}

// archiveLocation is "<endpoint>/<bucket>/<prefix>/" for messages.
func archiveLocation(a config.ArchiveConfig) string { return a.Location() }

// canonicalArchiveEndpoint is a's endpoint as the location compares it.
func canonicalArchiveEndpoint(a config.ArchiveConfig) string {
	return config.ArchiveConfig{Endpoint: a.Endpoint, AllowHTTP: true}.Location()
}
