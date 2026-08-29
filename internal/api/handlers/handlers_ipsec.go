package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/ipsec"
	"firewall-mon/internal/ipsec/conformance"
	_ "firewall-mon/internal/ipsec/vendors" // register fortigate + opnsense drivers
	"firewall-mon/internal/models"
	"firewall-mon/internal/netclass"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IPSec tunnel provisioning-wizard handlers (PR-A: intent CRUD + capabilities +
// per-vendor preview; NO live device writes). The PSK is generated server-side
// when absent, encrypted at rest by the store, and masked in every response.

const ipsecPSKMask = "********"

// tunnelResponse is the masked API view of a stored tunnel plus its validation.
type tunnelResponse struct {
	Intent     *ipsec.TunnelIntent `json:"intent"`
	Status     string              `json:"status"`
	LastError  string              `json:"last_error,omitempty"`
	Validation []ipsec.Finding     `json:"validation,omitempty"`
}

// resolveCaps returns both ends' capability descriptors, or a non-nil error if a
// vendor has no provisioning driver. It returns an ERROR (not a bad-vendor
// string) so an EMPTY vendor — which is a valid "no driver" case — can't collide
// with the "" all-good sentinel and slip a nil-driver intent through to Render.
func resolveCaps(intent *ipsec.TunnelIntent) (caps [2]ipsec.CapabilityDescriptor, err error) {
	for i := range intent.Ends {
		c, e := ipsec.Capabilities(intent.Ends[i].Vendor)
		if e != nil {
			return caps, fmt.Errorf("end %c: %v", 'A'+i, e)
		}
		caps[i] = c
	}
	return caps, nil
}

// hydrateDerived fills the ID-derived, wizard-owned fields (name, VTI addressing,
// reqids) deterministically so both ends stay consistent and a redeploy is
// stable. Called after the row has an ID.
func hydrateDerived(intent *ipsec.TunnelIntent) {
	id := intent.ID
	intent.Name = fmt.Sprintf("fwm-t%d", id)
	cidr, innerA, innerB := ipsec.AllocateVTI(id)
	// VTI addressing is allocated in BOTH modes: the FortiGate driver keeps the
	// VTI + routes for policy-based too (FortiOS 7.6 removed no-VTI mode), so its
	// render needs InnerIP on every intent. OPNsense's policy render ignores
	// these fields. Allocating unconditionally also fixes tunnels persisted
	// before policy-mode allocation shipped (re-save rehydrates them).
	intent.VTISubnet = cidr
	intent.Ends[0].InnerIP = innerA
	intent.Ends[1].InnerIP = innerB
	// A per-tunnel reqid keeps both ends' child SA / VTI aligned. Derived
	// deterministically from the tunnel ID (no live device read-back); the
	// preflight collision-check is what guards against a clash on the device.
	intent.Ends[0].Reqid = int(id)
	intent.Ends[1].Reqid = int(id)
	// Normalize the LAN interface list on save and mirror the head back into the
	// legacy singular, so the stored JSON stays readable by anything still using
	// it (the wizard's edit path, older builds). Nothing DEPENDS on this having
	// run — EffectiveLANIfaces resolves the same thing on every read path,
	// including the deploy path, which never hydrates.
	for i := range intent.Ends {
		eff := intent.Ends[i].EffectiveLANIfaces()
		intent.Ends[i].LANIfaces = eff
		if len(eff) > 0 {
			intent.Ends[i].LANIface = eff[0]
		}
	}
}

// CreateIPSecTunnel persists a new tunnel intent (draft). Generates a PSK if
// absent, validates, and returns the masked intent + validation findings. No
// device is touched.
func (h *Handler) CreateIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var intent ipsec.TunnelIntent
	if err := c.ShouldBindJSON(&intent); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	intent.ID = 0 // the server assigns the ID; never trust a client-supplied one
	if _, err := resolveCaps(&intent); err != nil {
		c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		return
	}
	// Generate a PSK when absent OR when the client round-tripped the mask.
	if intent.PSK == "" || intent.PSK == ipsecPSKMask {
		psk, err := ipsec.GeneratePSK()
		if err != nil {
			httputil.InternalError(c, "Failed to generate PSK", err)
			return
		}
		intent.PSK = psk
	}

	m, err := database.IPSecIntentToModel(&intent)
	if err != nil {
		httputil.InternalError(c, "Failed to encode tunnel", err)
		return
	}
	// Insert with a UNIQUE placeholder name so concurrent creates can't collide
	// on an empty name; then rename to fwm-t<ID>. On failure the placeholder row
	// is removed so it can't linger.
	m.Name = "fwm-new-" + uuid.NewString()
	if err := db.CreateIPSecTunnel(m); err != nil {
		httputil.InternalError(c, "Failed to create tunnel", err)
		return
	}
	intent.ID = m.ID
	hydrateDerived(&intent)
	// Coerce IKE identity types to ones both ends can render identically (e.g.
	// OPNsense can't encode keyid) BEFORE persisting, so the stored intent is clean.
	if caps, cerr := resolveCaps(&intent); cerr == nil {
		ipsec.NormalizeIdentities(&intent, caps)
	}
	m2, err := database.IPSecIntentToModel(&intent)
	if err != nil {
		_ = db.DeleteIPSecTunnel(m.ID)
		httputil.InternalError(c, "Failed to encode tunnel", err)
		return
	}
	m2.ID = m.ID
	m2.Status = "draft"
	if err := db.UpdateIPSecTunnel(m2); err != nil {
		_ = db.DeleteIPSecTunnel(m.ID)
		httputil.InternalError(c, "Failed to finalize tunnel", err)
		return
	}

	caps, _ := resolveCaps(&intent)
	findings := ipsec.Validate(&intent, caps)
	// Device-fact findings (warn-only) live outside ipsec.Validate, which is pure
	// by design. Not appended at the deploy gate, which stays a blocking check.
	findings = append(findings, h.lanCoherenceFindings(db, &intent)...)
	intent.PSK = ipsecPSKMask
	c.JSON(http.StatusCreated, response.Success(tunnelResponse{Intent: &intent, Status: "draft", Validation: findings}))
}

// ListIPSecTunnels returns all tunnels (no intent/PSK detail).
func (h *Handler) ListIPSecTunnels(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	list, err := db.ListIPSecTunnels()
	if err != nil {
		httputil.InternalError(c, "Failed to list tunnels", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(list))
}

// GetIPSecTunnel returns one tunnel's intent (PSK masked) + current validation.
func (h *Handler) GetIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	intent, err := database.IPSecModelToIntent(m)
	if err != nil {
		httputil.InternalError(c, "Failed to decode tunnel", err)
		return
	}
	var findings []ipsec.Finding
	if caps, err := resolveCaps(intent); err == nil {
		findings = ipsec.Validate(intent, caps)
		findings = append(findings, h.lanCoherenceFindings(db, intent)...)
	}
	intent.PSK = ipsecPSKMask
	c.JSON(http.StatusOK, response.Success(tunnelResponse{Intent: intent, Status: m.Status, LastError: m.LastError, Validation: findings}))
}

// UpdateIPSecTunnel replaces a tunnel's intent. A masked PSK is left unchanged.
func (h *Handler) UpdateIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	existing, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	// A deployed tunnel must be rolled back before its config can change — editing
	// the intent would leave the device objects (rendered from the OLD intent)
	// orphaned and the rollback snapshot mismatched.
	if !ipsecEditable(existing) {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("tunnel is %s — roll back the deployment before editing", existing.Status)))
		return
	}
	var intent ipsec.TunnelIntent
	if err := c.ShouldBindJSON(&intent); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if _, err := resolveCaps(&intent); err != nil {
		c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		return
	}
	// A masked/empty PSK means "unchanged": fold the real stored (decrypted) key
	// back in so validation sees a valid PSK and the store re-persists it. The
	// store's mask-guard also protects direct model writes.
	if intent.PSK == "" || intent.PSK == ipsecPSKMask {
		intent.PSK = existing.PSK
	}
	intent.ID = id
	hydrateDerived(&intent)
	// Coerce IKE identity types to ones both ends can render identically (e.g.
	// OPNsense can't encode keyid) BEFORE persisting, so the stored intent is clean.
	if caps, cerr := resolveCaps(&intent); cerr == nil {
		ipsec.NormalizeIdentities(&intent, caps)
	}
	m, err := database.IPSecIntentToModel(&intent)
	if err != nil {
		httputil.InternalError(c, "Failed to encode tunnel", err)
		return
	}
	m.ID = id
	m.Status = "draft" // config changed → back to draft until re-deployed
	if err := db.UpdateIPSecTunnel(m); err != nil {
		httputil.InternalError(c, "Failed to update tunnel", err)
		return
	}
	caps, _ := resolveCaps(&intent)
	findings := ipsec.Validate(&intent, caps)
	// Device-fact findings (warn-only) live outside ipsec.Validate, which is pure
	// by design. Not appended at the deploy gate, which stays a blocking check.
	findings = append(findings, h.lanCoherenceFindings(db, &intent)...)
	intent.PSK = ipsecPSKMask
	c.JSON(http.StatusOK, response.Success(tunnelResponse{Intent: &intent, Status: "draft", Validation: findings}))
}

// DeleteIPSecTunnel removes a draft tunnel.
func (h *Handler) DeleteIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	existing, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	// Deleting a deployed tunnel would orphan its device objects (the remove
	// snapshot in DeployJSON is the only thing that can reverse them). Require a
	// rollback first — delete is allowed only from a clean/rolled-back state.
	if !ipsecDeletable(existing) {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("tunnel is %s with an active deployment — roll back before deleting", existing.Status)))
		return
	}
	if err := db.DeleteIPSecTunnel(id); err != nil {
		httputil.InternalError(c, "Failed to delete tunnel", err)
		return
	}
	c.JSON(http.StatusOK, response.Message("Tunnel deleted"))
}

// Tunnel lifecycle statuses that mean "config is live on a device" (or a deploy /
// rollback is in flight). Editing or deleting from these would orphan device
// objects or race an in-flight command.
const (
	ipsecStatusDraft          = "draft"
	ipsecStatusDeploying      = "deploying"
	ipsecStatusDegraded       = "degraded"
	ipsecStatusUp             = "up"
	ipsecStatusDown           = "down"
	ipsecStatusRollingBack    = "rolling_back"
	ipsecStatusRolledBack     = "rolled_back"
	ipsecStatusRollbackFailed = "rollback_failed"
	ipsecStatusError          = "error"
)

// ipsecHasDeployRecord reports whether a tunnel still carries a deploy record —
// i.e. device objects MAY be outstanding and only a rollback (which reverses the
// stored snapshot) can safely remove them. A successful rollback clears it; a
// pre-write failure (error before any enqueue) never wrote it. This is the single
// source of truth for edit/delete safety — keying on status alone was unsafe
// because editing a partially-deployed `error` tunnel reset it to `draft` (which
// then allowed delete + blocked rollback, orphaning the device objects).
func ipsecHasDeployRecord(m *models.IPSecTunnel) bool {
	return strings.TrimSpace(m.DeployJSON) != ""
}

// ipsecEditable / ipsecDeletable: an intent may be edited and the row deleted ONLY
// when no deploy record is present. This blocks deploying/degraded/up/
// rolling_back/rollback_failed (all carry a record) and a partially-deployed
// `error` (record kept), while allowing draft, rolled_back (record cleared), and a
// pre-write `error` (record never written). The operator's path out of a partial
// deploy is Rollback, never Edit/Delete.
func ipsecEditable(m *models.IPSecTunnel) bool  { return !ipsecHasDeployRecord(m) }
func ipsecDeletable(m *models.IPSecTunnel) bool { return !ipsecHasDeployRecord(m) }

// endPreview is one end's rendered config for the preview pane.
type endPreview struct {
	End         int      `json:"end"`
	Vendor      string   `json:"vendor"`
	Preview     string   `json:"preview"` // native syntax, PSK redacted
	AutoObjects []string `json:"auto_objects"`
	Steps       int      `json:"steps"`
}

// PreviewIPSecTunnel renders the exact per-vendor config each end will receive,
// with the PSK redacted, plus the validation findings. It performs NO device
// write — this is the "see exactly what each side gets before it goes live" step.
func (h *Handler) PreviewIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	intent, err := database.IPSecModelToIntent(m)
	if err != nil {
		httputil.InternalError(c, "Failed to decode tunnel", err)
		return
	}
	caps, cerr := resolveCaps(intent)
	if cerr != nil {
		c.JSON(http.StatusBadRequest, response.Error(cerr.Error()))
		return
	}
	ipsec.NormalizeIdentities(intent, caps) // coerce keyid→fqdn so the preview matches what deploy renders
	// Validate BEFORE rendering: the render is the thing most likely to fail on a
	// bad intent, and it used to bail before the findings that explain why had
	// even been computed.
	findings := ipsec.Validate(intent, caps)
	findings = append(findings, h.lanCoherenceFindings(db, intent)...)
	previews, findings := renderPreviewEnds(intent, findings)
	c.JSON(http.StatusOK, response.Success(gin.H{"ends": previews, "validation": findings}))
}

// renderPreviewEnds renders both ends for a PREVIEW response, converting a
// render failure into a blocking finding instead of an error.
//
// A failed render is not an HTTP error here. The preview exists to explain what
// is wrong with an intent, and a bad intent is precisely when the driver cannot
// render it — so returning 400 threw away the findings that name the offending
// field, and the wizard showed a dismissible toast instead of anchoring anything
// to the control the operator has to fix. Concretely: an empty IKE identity
// produces id_missing, and an unparseable gateway produces gateway_invalid, and
// neither ever reached the client.
//
// Empty ends is a valid preview: there is nothing to show yet, and the findings
// carry the answer.
//
// When the render fails but validation found nothing blocking, the error is
// surfaced as a synthetic blocking finding rather than swallowed. That case is a
// validation gap (the intent passed every linter yet cannot be rendered), and it
// must still gate Save — the client disables Save whenever any finding blocks.
//
// This is preview-only. The deploy gate keeps its hard error: refusing to deploy
// something that will not render is correct there.
func renderPreviewEnds(intent *ipsec.TunnelIntent, findings []ipsec.Finding) ([]endPreview, []ipsec.Finding) {
	previews, cfindings, rerr := renderBothEnds(intent)
	if rerr == nil {
		// Preview and Deploy must AGREE: the deploy path (DeployIPSecTunnel) runs
		// conformance.Validate on each rendered end and 400s on any violation, but
		// PreviewIPSecTunnel/PreviewIPSecIntent never did — so a FortiGate end with
		// e.g. child_lifetime=60 or dpd.delay=120 (which ipsec.Validate only WARNs
		// about, if at all) previewed green and then failed conformance on deploy,
		// leaving the tunnel undeployable via the wizard. Surfacing the same
		// conformance findings here makes a green preview imply a deployable config.
		return previews, append(findings, cfindings...)
	}
	if !ipsec.HasBlock(findings) {
		findings = append(findings, ipsec.Finding{
			Severity: ipsec.SeverityBlock,
			Code:     "render_failed",
			Message:  "this tunnel cannot be rendered as configuration: " + rerr.Error(),
		})
	}
	return nil, findings
}

// renderBothEnds renders each end's redacted preview. It returns ONLY endPreview
// (PreviewText + step count) — never the raw Artifact/Steps, which carry the
// plaintext PSK. Shared by the stored-tunnel and stateless preview handlers.
//
// It ALSO returns the per-vendor conformance findings for the rendered steps,
// mapped to blocking ipsec.Findings anchored to the end they belong to. This is
// the exact check DeployIPSecTunnel runs before dispatch, so the preview cannot
// show green for a config the deploy would reject on conformance (AUDIT-274/275).
// conformance.Validate is a no-op for a vendor with no spec, so it never
// over-blocks — and only fortigate/opnsense have render drivers anyway.
func renderBothEnds(intent *ipsec.TunnelIntent) ([]endPreview, []ipsec.Finding, error) {
	previews := make([]endPreview, 0, 2)
	var cfindings []ipsec.Finding
	for i := range intent.Ends {
		vendor := intent.Ends[i].Vendor
		d, ok := ipsec.Driver(vendor)
		if !ok {
			return nil, nil, fmt.Errorf("end %c (%q): no IPSec provisioning driver", 'A'+i, vendor)
		}
		art, err := d.Render(ipsec.ViewFor(intent, i))
		if err != nil {
			return nil, nil, fmt.Errorf("end %c (%s): %v", 'A'+i, vendor, err)
		}
		end := i // stable address per iteration for Finding.End
		for _, cf := range conformance.Validate(vendor, art.Steps) {
			cfindings = append(cfindings, ipsec.Finding{
				Severity: ipsec.SeverityBlock,
				Code:     "conformance",
				End:      &end,
				Subject:  cf.Field,
				Message:  fmt.Sprintf("end %c (%s): the device would reject this config — %s", 'A'+i, vendor, cf.String()),
			})
		}
		previews = append(previews, endPreview{
			End: i, Vendor: vendor, Preview: art.PreviewText,
			AutoObjects: art.AutoObjects, Steps: len(art.Steps),
		})
	}
	return previews, cfindings, nil
}

// ipsecPreviewPlaceholderPSK is a synthetic valid PSK used ONLY to render/validate
// a pre-save preview when the operator hasn't set one yet (it will be generated
// server-side on save). It is never rendered (PreviewText redacts) nor echoed.
const ipsecPreviewPlaceholderPSK = "preview_placeholder_psk_generated_on_save_00"

// PreviewIPSecIntent renders both ends' config + validation from a POSTed intent,
// WITHOUT persisting — the wizard's "preview before you save" step. PSK is never
// echoed; a blank/masked PSK is treated as "will be auto-generated on save". For
// a create preview (id=0) the derived names/VTI/reqid are PROVISIONAL — the UI
// labels them so, and re-fetches the authoritative /:id/preview after save.
func (h *Handler) PreviewIPSecIntent(c *gin.Context) {
	var intent ipsec.TunnelIntent
	if err := c.ShouldBindJSON(&intent); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	caps, cerr := resolveCaps(&intent)
	if cerr != nil {
		c.JSON(http.StatusBadRequest, response.Error(cerr.Error()))
		return
	}
	ipsec.NormalizeIdentities(&intent, caps) // coerce keyid→fqdn so the stateless preview matches deploy
	pskAutogen := intent.PSK == "" || intent.PSK == ipsecPSKMask
	if pskAutogen {
		intent.PSK = ipsecPreviewPlaceholderPSK // validate/render only; never returned
	}
	// Honor a client-supplied id for edit-mode previews (read-only endpoint —
	// trusting the id is harmless) so an edit preview is exact; id=0 → provisional.
	hydrateDerived(&intent)
	findings := ipsec.Validate(&intent, caps)
	// Device-fact findings (warn-only) live outside ipsec.Validate, which is pure
	// by design. Not appended at the deploy gate, which stays a blocking check.
	findings = append(findings, h.lanCoherenceFindings(h.reqDB(c), &intent)...)
	previews, findings := renderPreviewEnds(&intent, findings)
	c.JSON(http.StatusOK, response.Success(gin.H{
		"ends":        previews,
		"validation":  findings,
		"psk_autogen": pskAutogen,
		"provisional": intent.ID == 0, // names/VTI/reqid assigned on save
	}))
}

// IPSecCapabilities returns the option set BOTH selected vendors support (the
// intersection), so the wizard offers only mutually-honorable choices, plus each
// vendor's own descriptor.
func (h *Handler) IPSecCapabilities(c *gin.Context) {
	a, b := c.Query("a"), c.Query("b")
	capA, err := ipsec.Capabilities(a)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Unknown or unsupported vendor: "+a))
		return
	}
	capB, err := ipsec.Capabilities(b)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Unknown or unsupported vendor: "+b))
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"a":        capA,
		"b":        capB,
		"allowed":  ipsec.Intersect(capA, capB),
		"profiles": ipsec.Presets(),
	}))
}

// --- IPSec deploy preflight (READ-ONLY; PR-C1) --------------------------------
//
// PreflightIPSecTunnel enqueues a read-only REST preflight command to EACH end's
// collector: authenticate to the device API and GET the objects a deploy would
// create (name/VTI/connection collisions) — WITHOUT writing anything. It is the
// de-risking step before the apply saga (PR-C2). The API token is decrypted
// server-side, placed in the command payload, and re-encrypted at rest by
// EnqueueProbeCommand; it is delivered to the collector over TLS and never
// logged. Returns the per-end command IDs; poll the GET below for results.

// ipsecPreflightPayload is the JSON contract delivered to the collector. It
// carries ONLY read-only GET steps (from the driver's PreflightProbe) — no PSK,
// no write steps. The API token is the sole secret and rides the encrypted
// command payload.
type ipsecPreflightPayload struct {
	TunnelID   uint   `json:"tunnel_id"`
	TunnelName string `json:"tunnel_name"`
	End        int    `json:"end"` // 0=A, 1=B
	Vendor     string `json:"vendor"`
	DeviceID   uint   `json:"device_id"`
	BaseURL    string `json:"base_url"`
	// APIToken is deliberately marshaled — the collector needs it to
	// authenticate to the device API. This is not an API response: the payload
	// is encrypted at rest by EnqueueProbeCommand (AES-256-GCM), delivered over
	// TLS, and never logged. (The gosec G117 marshaled-secret finding is
	// suppressed at the json.Marshal call site, where it is raised.)
	APIToken    string                `json:"api_token"`
	InsecureTLS bool                  `json:"insecure_tls"`
	Steps       []ipsec.PreflightStep `json:"steps"`
}

type ipsecPreflightEnqueued struct {
	End       int    `json:"end"`
	DeviceID  uint   `json:"device_id"`
	Vendor    string `json:"vendor"`
	ProbeID   uint   `json:"probe_id"`
	CommandID string `json:"command_id"`
}

func (h *Handler) PreflightIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	intent, err := database.IPSecModelToIntent(m)
	if err != nil {
		httputil.InternalError(c, "Failed to decode tunnel", err)
		return
	}

	// A tunnel always has exactly two ends (create/hydrate enforce it); guard
	// defensively so a malformed stored intent can't panic the fixed-size index.
	if len(intent.Ends) != 2 {
		httputil.InternalError(c, "Malformed tunnel intent", fmt.Errorf("expected 2 ends, got %d", len(intent.Ends)))
		return
	}
	deviceIDs := [2]uint{m.ADeviceID, m.BDeviceID}
	enqueued := make([]ipsecPreflightEnqueued, 0, 2)
	// AUDIT-258: record each end's preflight command ID so the status poll reads
	// the EXACT command for this tunnel, not the device's latest preflight command
	// (which bleeds across two tunnels sharing a hub device). Same pattern as the
	// deploy path's DeployState.
	pfEnds := make([]ipsec.PreflightEndState, 0, 2)
	for i := range intent.Ends {
		dev, derr := db.GetDevice(deviceIDs[i])
		if derr != nil {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c device (id %d) not found", 'A'+i, deviceIDs[i])))
			return
		}
		if dev.ProbeID == nil || *dev.ProbeID == 0 {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%s): device has no collector assigned — preflight runs from the collector", 'A'+i, dev.Name)))
			return
		}
		if dev.APIToken == "" {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%s): no API token set — add one on the device before preflight", 'A'+i, dev.Name)))
			return
		}
		drv, ok := ipsec.Driver(intent.Ends[i].Vendor)
		if !ok {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%q): no IPSec driver", 'A'+i, intent.Ends[i].Vendor)))
			return
		}
		port := dev.APIPort
		if port == 0 {
			port = 443
		}
		payload := ipsecPreflightPayload{
			TunnelID:    m.ID,
			TunnelName:  intent.Name,
			End:         i,
			Vendor:      intent.Ends[i].Vendor,
			DeviceID:    dev.ID,
			BaseURL:     fmt.Sprintf("https://%s:%d", dev.IPAddress, port),
			APIToken:    dev.APIToken,
			InsecureTLS: dev.APIInsecureTLS,
			// Advisory reads ride the preflight command but are kept OUT of
			// PreflightProbe (and therefore out of the deploy saga's collision
			// precheck), so nothing derived from them can abort a write.
			Steps: append(drv.PreflightProbe(ipsec.ViewFor(intent, i)), drv.AdvisoryProbe(ipsec.ViewFor(intent, i))...),
		}
		// api_token is intentionally marshaled here: this is the collector command
		// payload (encrypted at rest by EnqueueProbeCommand, TLS-delivered, never
		// an API response), not a client-facing object. (gosec G117 is excluded in
		// CI — its inline #nosec is not honored for this rule.)
		buf, merr := json.Marshal(payload)
		if merr != nil {
			httputil.InternalError(c, "Failed to build preflight payload", merr)
			return
		}
		// Pre-generate the CommandID (honored by EnqueueProbeCommand) so it can be
		// recorded on the tunnel below, exactly as the deploy path does.
		commandID := uuid.NewString()
		cmd := &models.ProbeCommand{
			ProbeID:   *dev.ProbeID,
			DeviceID:  dev.ID,
			CommandID: commandID,
			Type:      database.ProbeCommandTypeIPSecPreflight,
			Payload:   string(buf),
		}
		if eerr := db.EnqueueProbeCommand(cmd); eerr != nil {
			httputil.InternalError(c, "Failed to enqueue preflight", eerr)
			return
		}
		pfEnds = append(pfEnds, ipsec.PreflightEndState{End: i, DeviceID: dev.ID, CommandID: cmd.CommandID})
		enqueued = append(enqueued, ipsecPreflightEnqueued{
			End: i, DeviceID: dev.ID, Vendor: intent.Ends[i].Vendor, ProbeID: *dev.ProbeID, CommandID: cmd.CommandID,
		})
	}

	// Persist the per-end command IDs for this run (AUDIT-258). A failure here is
	// non-fatal to the enqueue — the commands are already queued and will run — but
	// the poll would then fall back to the previous run's IDs, so log it loudly.
	pfState := ipsec.PreflightState{EnqueuedAt: time.Now().UTC().Format(time.RFC3339), Ends: pfEnds}
	if blob, merr := json.Marshal(&pfState); merr != nil {
		log.Printf("ipsec preflight: failed to encode preflight state for tunnel %d: %v", m.ID, merr)
	} else if serr := db.SetIPSecPreflightState(m.ID, string(blob)); serr != nil {
		log.Printf("ipsec preflight: failed to persist preflight state for tunnel %d: %v", m.ID, serr)
	}

	c.JSON(http.StatusOK, response.Success(gin.H{"tunnel_id": m.ID, "commands": enqueued}))
}

// GetIPSecPreflightResult returns the latest preflight command status + result
// for each of the tunnel's two ends, so the wizard can poll after enqueuing.
// The collector returns a structured JSON report as the command Result; it is
// passed through as an opaque object (no secrets — the report has no token/PSK).
func (h *Handler) GetIPSecPreflightResult(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	type endReport struct {
		End      int             `json:"end"`
		DeviceID uint            `json:"device_id"`
		Status   string          `json:"status"` // pending/dispatched/succeeded/failed/expired, or "none"
		Report   json.RawMessage `json:"report"` // structured collector report (when succeeded)
		// Advisories are NON-BLOCKING findings the server derives from the
		// advisory step bodies in Report. They are advice about pre-existing
		// device state, never a reason to withhold a deploy.
		Advisories []ipsec.Advisory `json:"advisories,omitempty"`
		RawResult  string           `json:"raw_result,omitempty"`
	}
	// The intent is only needed to derive advisories; a stored intent that no
	// longer decodes must not break reporting the preflight itself.
	intent, ierr := database.IPSecModelToIntent(m)

	// AUDIT-258: read the per-end command IDs recorded at enqueue so each end is
	// polled by its OWN command (tunnel-scoped), not the device's latest preflight
	// command — which, on a hub device terminating two tunnels, would return the
	// other tunnel's report. A tunnel not yet preflighted (or preflighted before
	// this field existed) has no recorded ID for an end, so it reports "none"
	// rather than another tunnel's stale result.
	// Key the recorded command by end AND the device it was preflighted against.
	// UpdateIPSecTunnel can reassign a_device_id/b_device_id without clearing
	// preflight_json, so a recorded end whose device no longer matches the
	// tunnel's current device is stale — report "none" rather than attribute
	// the old device's report (and advisories derived against the new intent) to
	// the new device.
	type pfRec struct {
		cmdID string
		devID uint
	}
	pfByEnd := map[int]pfRec{}
	if pf, perr := parsePreflightState(m); perr != nil {
		log.Printf("IPSec preflight: tunnel %d has unparsable preflight state: %v (reporting none)", m.ID, perr)
	} else if pf != nil {
		for _, e := range pf.Ends {
			pfByEnd[e.End] = pfRec{cmdID: e.CommandID, devID: e.DeviceID}
		}
	}

	out := make([]endReport, 0, 2)
	for i, devID := range [2]uint{m.ADeviceID, m.BDeviceID} {
		er := endReport{End: i, DeviceID: devID, Status: "none"}
		var cmd *models.ProbeCommand
		var cerr error
		if rec := pfByEnd[i]; rec.cmdID != "" && rec.devID == devID {
			cmd, cerr = db.GetProbeCommandByCommandID(rec.cmdID)
		}
		if cerr == nil && cmd != nil {
			er.Status = cmd.Status
			if json.Valid([]byte(cmd.Result)) {
				er.Report = json.RawMessage(cmd.Result)
				if ierr == nil && i < len(intent.Ends) {
					er.Advisories = preflightAdvisories(intent, i, []byte(cmd.Result))
				}
			} else if cmd.Result != "" {
				er.RawResult = cmd.Result
			}
		}
		out = append(out, er)
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"tunnel_id": m.ID, "ends": out}))
}

// preflightAdvisories derives an end's non-blocking advisories from the raw
// collector report. Advisory step bodies are echoed back under checks[].body
// (only for steps the driver marked ReturnBody), and the vendor parsing happens
// here on the server — mirroring StatusProbe/ParseStatus, so the collector stays
// a transport and vendor knowledge lives in one repo.
//
// Every failure mode degrades to "no advisories": a collector predating the body
// field, a step that errored, an unparseable body. An advisory is only ever
// raised from device state actually read.
func preflightAdvisories(intent *ipsec.TunnelIntent, end int, result []byte) []ipsec.Advisory {
	drv, ok := ipsec.Driver(intent.Ends[end].Vendor)
	if !ok {
		return nil
	}
	var rep struct {
		Checks []struct {
			Check string `json:"check"`
			Body  string `json:"body"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(result, &rep); err != nil {
		return nil
	}
	bodies := make(map[string]string, len(rep.Checks))
	for _, c := range rep.Checks {
		if c.Body != "" {
			bodies[c.Check] = c.Body
		}
	}
	if len(bodies) == 0 {
		return nil
	}
	return drv.Advisories(ipsec.ViewFor(intent, end), bodies)
}

// --- IPSec deploy / rollback (WRITES config; C2b-1: FortiGate end only) -------
//
// DeployIPSecTunnel renders each deployable end's config (PSK-bearing REST cmdb
// steps) and enqueues an apply_ipsec command to that end's collector, which
// checksum-verifies, collision-prechecks, writes, then verifies. RollbackIPSecTunnel
// reverses it from a stored remove-steps snapshot. The device write itself happens
// on the collector; the server only renders, gates (HasBlock + concurrency), and
// tracks status via a per-deploy record persisted on the tunnel (DeployJSON).
//
// C2b-1 deploys ONLY FortiGate ends (named cmdb objects, explicit mkeys). A
// FortiGate⇄OPNsense tunnel deploys its FortiGate end and leaves the OPNsense end
// for C2b-2 (status → degraded with an informational note). A tunnel with no
// FortiGate end is rejected (400) rather than silently doing nothing.

// ipsecApplyPayload is the JSON contract delivered to the collector for a write.
// Steps are the exact bytes to apply (PSK injected — this is why the payload is
// encrypted at rest + TLS-delivered + never logged); Checksum is verified before
// any write; CollisionSteps are the read-only ExpectAbsent GETs used to precheck
// (before) and verify (after); OwnerTag scopes the remove ownership check.
type ipsecApplyPayload struct {
	TunnelID   uint   `json:"tunnel_id"`
	TunnelName string `json:"tunnel_name"`
	End        int    `json:"end"`
	Vendor     string `json:"vendor"`
	DeviceID   uint   `json:"device_id"`
	BaseURL    string `json:"base_url"`
	Op         string `json:"op"` // "apply" | "remove"
	OwnerTag   string `json:"owner_tag"`
	// APIToken is deliberately marshaled — the collector authenticates with it.
	// Not an API response: encrypted at rest by EnqueueProbeCommand, TLS-delivered,
	// never logged. (gosec G117 is excluded in CI — inline #nosec isn't honored.)
	APIToken       string                `json:"api_token"`
	InsecureTLS    bool                  `json:"insecure_tls"`
	Steps          []ipsec.ApplyStep     `json:"steps"`
	Checksum       string                `json:"checksum"`
	CollisionSteps []ipsec.PreflightStep `json:"collision_steps,omitempty"`
	// ValidationSpec is the vendor's conformance spec (conformance.MarshalSpec),
	// so the collector re-validates every step's field VALUES before the first
	// write and aborts with the full findings list — defense-in-depth for the
	// server-side pre-dispatch guard, and it kills first-step failure masking.
	ValidationSpec json.RawMessage `json:"validation_spec,omitempty"`
	// Substitutions resolves <uuid:NAME> tokens for a REMOVE (the UUIDs captured at
	// apply, stored in the deploy record). Empty for apply (captured live) and for
	// FortiGate (no tokens).
	Substitutions map[string]string `json:"substitutions,omitempty"`
}

// ipsecApplyRunnerSupported reports whether the collector can APPLY this vendor.
// FortiGate (named objects, explicit mkeys) shipped in C2b-1; OPNsense (UUID
// chaining) in C2b-2a. The collector independently rejects anything else.
func ipsecApplyRunnerSupported(vendor string) bool {
	return vendor == "fortigate" || vendor == "opnsense"
}

// ipsecStatusPayload is the ipsec_status command payload (C2b-2b): a READ-ONLY
// SA-liveness probe of one deployed end. The collector runs the GET steps and
// returns the raw device documents; the SERVER parses them (driver ParseStatus)
// so the repos can never drift on what "up" means.
type ipsecStatusPayload struct {
	Vendor     string `json:"vendor"`
	DeviceID   uint   `json:"device_id,omitempty"`
	TunnelName string `json:"tunnel_name,omitempty"`
	BaseURL    string `json:"base_url"`
	// APIToken is deliberately marshaled — the collector authenticates with it.
	// Same contract as ipsecApplyPayload: encrypted at rest, TLS-delivered,
	// never logged (gosec G117 CI-excluded).
	APIToken    string            `json:"api_token"`
	InsecureTLS bool              `json:"insecure_tls,omitempty"`
	Steps       []ipsec.ProbeStep `json:"steps"`
}

// ipsecStatusReportView mirrors the collector's fwapi.StatusReport envelope.
type ipsecStatusReportView struct {
	Vendor string `json:"vendor"`
	Steps  []struct {
		Path   string `json:"path"`
		Status int    `json:"status"`
		Body   string `json:"body"`
		Note   string `json:"note"`
	} `json:"steps"`
	Error string `json:"error"`
}

// ipsecBuildStatusCmd builds the ipsec_status probe for one deployed end: the
// vendor driver's StatusProbe steps against the device's REST API. A build
// failure is NOT fatal to the deploy terminal — the caller falls back to a
// degraded-without-SA-check outcome.
func ipsecBuildStatusCmd(db database.Store, m *models.IPSecTunnel, intent *ipsec.TunnelIntent, e ipsec.DeployEndState) (*models.ProbeCommand, error) {
	dev, derr := db.GetDevice(e.DeviceID)
	if derr != nil {
		return nil, fmt.Errorf("end %c device (id %d) not found — cannot probe SA", 'A'+e.End, e.DeviceID)
	}
	if dev.ProbeID == nil || *dev.ProbeID == 0 {
		return nil, fmt.Errorf("end %c (%s): device has no collector assigned", 'A'+e.End, dev.Name)
	}
	drv, ok := ipsec.Driver(e.Vendor)
	if !ok {
		return nil, fmt.Errorf("end %c (%q): no IPSec driver", 'A'+e.End, e.Vendor)
	}
	steps := drv.StatusProbe(ipsec.ViewFor(intent, e.End))
	if len(steps) == 0 {
		return nil, fmt.Errorf("end %c (%s): driver ships no status probe", 'A'+e.End, e.Vendor)
	}
	port := dev.APIPort
	if port == 0 {
		port = 443
	}
	payload := ipsecStatusPayload{
		Vendor:      e.Vendor,
		DeviceID:    dev.ID,
		TunnelName:  m.Name,
		BaseURL:     fmt.Sprintf("https://%s:%d", dev.IPAddress, port),
		APIToken:    dev.APIToken,
		InsecureTLS: dev.APIInsecureTLS,
		Steps:       steps,
	}
	// api_token marshaled intentionally (gosec G117 CI-excluded).
	buf, merr := json.Marshal(payload)
	if merr != nil {
		return nil, merr
	}
	return &models.ProbeCommand{
		ProbeID:   *dev.ProbeID,
		DeviceID:  dev.ID,
		CommandID: uuid.NewString(),
		Type:      database.ProbeCommandTypeIPSecStatus,
		Payload:   string(buf),
	}, nil
}

// ipsecHasLiveCommand reports whether the tunnel's deploy record references any
// apply or rollback command that is still non-terminal (pending/dispatched) — the
// concurrency guard: deploy/rollback both refuse (409) while one is in flight.
func ipsecHasLiveCommand(db database.Store, st *ipsec.DeployState) (bool, error) {
	if st == nil {
		return false, nil
	}
	ids := make([]string, 0, len(st.Ends)+2)
	for _, e := range st.Ends {
		if e.CommandID != "" {
			ids = append(ids, e.CommandID)
		}
	}
	if st.Rollback != nil {
		ids = append(ids, st.Rollback.CommandIDs...)
	}
	for _, id := range ids {
		cmd, err := db.GetProbeCommandByCommandID(id)
		if err != nil {
			return false, err
		}
		if cmd != nil && !ipsecCommandTerminal(cmd.Status) {
			return true, nil
		}
	}
	return false, nil
}

func ipsecCommandTerminal(status string) bool {
	switch status {
	case database.ProbeCommandStatusSucceeded, database.ProbeCommandStatusFailed, database.ProbeCommandStatusExpired:
		return true
	}
	return false
}

// parseDeployState decodes a tunnel's DeployJSON (empty → nil, no error).
func parseDeployState(m *models.IPSecTunnel) (*ipsec.DeployState, error) {
	if strings.TrimSpace(m.DeployJSON) == "" {
		return nil, nil
	}
	var st ipsec.DeployState
	if err := json.Unmarshal([]byte(m.DeployJSON), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// parsePreflightState decodes a tunnel's PreflightJSON (empty → nil, no error).
func parsePreflightState(m *models.IPSecTunnel) (*ipsec.PreflightState, error) {
	if strings.TrimSpace(m.PreflightJSON) == "" {
		return nil, nil
	}
	var st ipsec.PreflightState
	if err := json.Unmarshal([]byte(m.PreflightJSON), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

type ipsecDeployEnqueued struct {
	End       int    `json:"end"`
	DeviceID  uint   `json:"device_id"`
	Vendor    string `json:"vendor"`
	ProbeID   uint   `json:"probe_id"`
	CommandID string `json:"command_id"`
}

func (h *Handler) DeployIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	intent, err := database.IPSecModelToIntent(m)
	if err != nil {
		httputil.InternalError(c, "Failed to decode tunnel", err)
		return
	}
	if len(intent.Ends) != 2 {
		httputil.InternalError(c, "Malformed tunnel intent", fmt.Errorf("expected 2 ends, got %d", len(intent.Ends)))
		return
	}

	// (a) VALIDATE everything up front — nothing is enqueued until every check
	// passes, so a guard failure can't leave a half-deployed tunnel.
	caps, cerr := resolveCaps(intent)
	if cerr != nil {
		c.JSON(http.StatusBadRequest, response.Error(cerr.Error()))
		return
	}
	// Coerce IKE identity types to ones both ends render identically before the
	// deploy renders each end — this is what fixes a tunnel stored with keyid
	// (which OPNsense can't encode) on redeploy, with no manual field edit.
	ipsec.NormalizeIdentities(intent, caps)
	if ipsec.HasBlock(ipsec.Validate(intent, caps)) {
		c.JSON(http.StatusConflict, response.Error("tunnel has blocking validation findings — resolve them before deploying"))
		return
	}

	// Deploy is blocked while a deploy record exists (F4): a re-deploy would
	// overwrite deploy_json and, for OPNsense, destroy the captured-UUID map that
	// rollback needs → orphaned device objects. Roll back (which clears the record)
	// before re-deploying. This also subsumes the in-flight guard (deploying/
	// rolling_back always carry a record).
	if ipsecHasDeployRecord(m) {
		c.JSON(http.StatusConflict, response.Error(fmt.Sprintf("tunnel is %s with an active deploy record — roll back before re-deploying", m.Status)))
		return
	}

	deviceIDs := [2]uint{m.ADeviceID, m.BDeviceID}
	type prepared struct {
		cmd   *models.ProbeCommand
		state ipsec.DeployEndState
		probe uint
	}
	var preps []prepared
	for i := range intent.Ends {
		vendor := intent.Ends[i].Vendor
		if !ipsecApplyRunnerSupported(vendor) {
			continue // no apply runner for this vendor (neither fortigate nor opnsense)
		}
		dev, derr := db.GetDevice(deviceIDs[i])
		if derr != nil {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c device (id %d) not found", 'A'+i, deviceIDs[i])))
			return
		}
		if dev.ProbeID == nil || *dev.ProbeID == 0 {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%s): device has no collector assigned", 'A'+i, dev.Name)))
			return
		}
		if dev.APIToken == "" {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%s): no API token set", 'A'+i, dev.Name)))
			return
		}
		drv, ok := ipsec.Driver(vendor)
		if !ok {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%q): no IPSec driver", 'A'+i, vendor)))
			return
		}
		view := ipsec.ViewFor(intent, i)
		applyArt, rerr := drv.Render(view)
		if rerr != nil {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%s): render failed: %v", 'A'+i, vendor, rerr)))
			return
		}
		// Pre-dispatch conformance guard: refuse to send a render whose field VALUES
		// this vendor's device would reject (the fwm-t3 class). A non-conformant
		// render never reaches a device — the operator gets the offending fields up
		// front instead of a silent rollback.
		if findings := conformance.Validate(vendor, applyArt.Steps); len(findings) > 0 {
			msgs := make([]string, 0, len(findings))
			for _, f := range findings {
				msgs = append(msgs, f.String())
			}
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf(
				"end %c (%s): render failed conformance (%d issue(s)): %s",
				'A'+i, vendor, len(findings), strings.Join(msgs, "; "))))
			return
		}
		removeArt, rrerr := drv.RenderRemove(view)
		if rrerr != nil {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%s): render-remove failed: %v", 'A'+i, vendor, rrerr)))
			return
		}
		port := dev.APIPort
		if port == 0 {
			port = 443
		}
		commandID := uuid.NewString() // pre-generated so it's recorded before enqueue (atomic persist)
		payload := ipsecApplyPayload{
			TunnelID:       m.ID,
			TunnelName:     intent.Name,
			End:            i,
			Vendor:         vendor,
			DeviceID:       dev.ID,
			BaseURL:        fmt.Sprintf("https://%s:%d", dev.IPAddress, port),
			Op:             "apply",
			OwnerTag:       intent.Name,
			APIToken:       dev.APIToken,
			InsecureTLS:    dev.APIInsecureTLS,
			Steps:          applyArt.Steps,
			Checksum:       applyArt.Checksum,
			CollisionSteps: drv.PreflightProbe(view),
		}
		if spec, ok := conformance.MarshalSpec(vendor); ok {
			payload.ValidationSpec = spec
		}
		// api_token marshaled intentionally (see payload doc; gosec G117 CI-excluded).
		buf, merr := json.Marshal(payload)
		if merr != nil {
			httputil.InternalError(c, "Failed to build apply payload", merr)
			return
		}
		preps = append(preps, prepared{
			cmd: &models.ProbeCommand{
				ProbeID:   *dev.ProbeID,
				DeviceID:  dev.ID,
				CommandID: commandID,
				Type:      database.ProbeCommandTypeIPSecApply,
				Payload:   string(buf),
			},
			state: ipsec.DeployEndState{
				End: i, DeviceID: dev.ID, Vendor: vendor, CommandID: commandID,
				RemoveSteps: removeArt.Steps, RemoveChecksum: removeArt.Checksum,
			},
			probe: *dev.ProbeID,
		})
	}
	if len(preps) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("no deployable end — the tunnel has no FortiGate or OPNsense end with an apply runner"))
		return
	}

	// (b) PERSIST the deploy record + ENQUEUE the commands atomically, guarded on
	// the current status (optimistic lock → 409 on a concurrent deploy).
	st := ipsec.DeployState{DeployedAt: time.Now().UTC().Format(time.RFC3339)}
	cmds := make([]*models.ProbeCommand, 0, len(preps))
	enqueued := make([]ipsecDeployEnqueued, 0, len(preps))
	for _, p := range preps {
		st.Ends = append(st.Ends, p.state)
		cmds = append(cmds, p.cmd)
	}
	blob, merr := json.Marshal(&st)
	if merr != nil {
		httputil.InternalError(c, "Failed to encode deploy state", merr)
		return
	}
	// fromStatuses excludes error (deploy is now blocked whenever a record exists —
	// F4 — so a re-deploy only ever starts from a clean draft/rolled_back).
	fromStatuses := []string{ipsecStatusDraft, ipsecStatusRolledBack}
	if terr := db.TransitionIPSecDeploy(id, fromStatuses, ipsecStatusDeploying, "", string(blob), false, cmds); terr != nil {
		if errors.Is(terr, database.ErrIPSecConcurrentDeploy) {
			c.JSON(http.StatusConflict, response.Error("tunnel is not in a deployable state (already deploying, deployed, or rolling back) — refresh and roll back first if needed"))
			return
		}
		httputil.InternalError(c, "Failed to start deploy", terr)
		return
	}
	for i, p := range preps {
		enqueued = append(enqueued, ipsecDeployEnqueued{
			End: p.state.End, DeviceID: p.state.DeviceID, Vendor: p.state.Vendor, ProbeID: p.probe, CommandID: cmds[i].CommandID,
		})
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"tunnel_id": m.ID, "status": ipsecStatusDeploying, "commands": enqueued}))
}

// GetIPSecDeployResult polls the deploy (or rollback) in progress: it reads each
// end's command by the EXACT command IDs recorded in DeployJSON (tunnel-scoped,
// so two tunnels on one device never cross-contaminate) and drives the tunnel's
// terminal status. A pruned/missing command row on a still-`deploying` tunnel is
// treated as terminal-unknown → error (never a permanent stuck state).
func (h *Handler) GetIPSecDeployResult(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	st, perr := parseDeployState(m)
	if perr != nil {
		httputil.InternalError(c, "Failed to read deploy state", perr)
		return
	}

	type endReport struct {
		End       int                 `json:"end"`
		DeviceID  uint                `json:"device_id"`
		Status    string              `json:"status"`
		Report    json.RawMessage     `json:"report,omitempty"`
		RawResult string              `json:"raw_result,omitempty"`
		SA        *ipsec.TunnelStatus `json:"sa,omitempty"`
	}
	out := make([]endReport, 0, 2)
	status := m.Status
	note := ""

	if m.Status == ipsecStatusRollingBack && st != nil && st.Rollback != nil {
		// Rollback in progress: terminal status is poll-driven from the per-end
		// remove commands (index-aligned with st.Ends) AND the RollbackUnproven
		// markers — a marked end forces rollback_failed even on a clean-looking
		// (all-skipped) remove report, because that skip proves nothing.
		done, anyFail, msg := 0, false, ""
		for i := range st.Ends {
			e := st.Ends[i]
			var cid string
			if i < len(st.Rollback.CommandIDs) {
				cid = st.Rollback.CommandIDs[i]
			}
			if cid == "" {
				done++
				anyFail, msg = true, firstNonEmpty(msg, "a rollback command was not recorded — verify the device")
				continue
			}
			cmd, cerr := db.GetProbeCommandByCommandID(cid)
			if cerr != nil {
				httputil.InternalError(c, "Failed to read command", cerr)
				return
			}
			if cmd == nil { // pruned/missing → terminal-unknown
				done++
				anyFail, msg = true, firstNonEmpty(msg, "a rollback command result was lost — verify the device")
				continue
			}
			switch cmd.Status {
			case database.ProbeCommandStatusSucceeded:
				done++
				var rv ipsecApplyReportView
				if json.Unmarshal([]byte(cmd.Result), &rv) != nil {
					anyFail, msg = true, firstNonEmpty(msg, "rollback report unparseable")
				} else if !rv.Applied {
					anyFail, msg = true, firstNonEmpty(msg, rv.Error, "some objects could not be removed")
				} else if e.RollbackUnproven {
					anyFail, msg = true, firstNonEmpty(msg, fmt.Sprintf("end %c apply outcome was unknown and rollback could not prove the device is clean — verify manually", 'A'+e.End))
				}
			case database.ProbeCommandStatusFailed, database.ProbeCommandStatusExpired:
				done++
				anyFail, msg = true, firstNonEmpty(msg, cmd.Result, "rollback command failed")
			}
		}
		// termReason is the reason surfaced to the UI on the terminal poll (as
		// `note`), so the failure banner shows WHY it rolled back instead of "No
		// further detail". Empty while still rolling back (the ends still carry the
		// apply error the frontend snapshots).
		termReason := ""
		if done >= len(st.Ends) {
			// One guarded write per terminal (never chain a second setter — F2).
			if anyFail {
				status = ipsecStatusRollbackFailed
				termReason = msg
				_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusRollingBack}, status, msg, m.DeployJSON, false, nil) // keep record for retry / reset
			} else {
				status = ipsecStatusRolledBack
				// Preserve WHY we rolled back. The deploy→rolling_back transition
				// already stored the deploy-failure reason in last_error; carry it
				// forward (the deploy_json record is still cleared) so the operator
				// isn't left with a bare "rolled_back" and no cause.
				reason := "rolled back — " + firstNonEmpty(m.LastError, "deploy failed")
				termReason = reason
				log.Printf("ipsec-deploy: tunnel %d auto-rolled-back cleanly: %s", id, reason)
				_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusRollingBack}, status, reason, "", false, nil)
			}
		}
		c.JSON(http.StatusOK, response.Success(gin.H{"tunnel_id": m.ID, "status": status, "op": "rollback", "auto": st.Rollback.Auto, "note": termReason}))
		return
	}

	// SA-liveness evaluation (C2b-2b): a deployed, object-verified tunnel sits at
	// degraded while its per-end ipsec_status probes are in flight; once they
	// all resolve, drive it to up (all ends' IKE+Child up) or down (any end
	// definitively not up). Inconclusive NEVER transitions — a guessed up/down
	// is worse than an honest degraded.
	if m.Status == ipsecStatusDegraded && st != nil && ipsecHasStatusChecks(st) {
		h.evalIPSecStatusChecks(c, db, m, st)
		return
	}

	if st == nil || len(st.Ends) == 0 {
		// Reopen / fresh-load after a terminal transition: the deploy record was
		// cleared, so there are no ends — surface the persisted last_error as the
		// reason so the banner isn't blank.
		c.JSON(http.StatusOK, response.Success(gin.H{"tunnel_id": m.ID, "status": status, "ends": out, "note": m.LastError}))
		return
	}

	// Classify each end from the COLLECTOR REPORT (a collision-abort or mid-write
	// failure is a *succeeded command* carrying aborted/conflict — command status
	// alone is not enough). Merge CapturedUUIDs from EVERY parseable report — a
	// FAILED end's partial captures are exactly what a compensating rollback needs.
	pending, anyGood, anyBad, allAbortedPreWrite := false, false, false, true
	failMsg := ""
	var collisions []string
	anyConflict := false
	unknown := make([]bool, len(st.Ends)) // outcome not provable (missing/expired/failed-cmd/unparseable)
	for i := range st.Ends {
		e := &st.Ends[i] // pointer: merge captured UUIDs into st for persistence
		er := endReport{End: e.End, DeviceID: e.DeviceID, Status: "none"}
		cmd, cerr := db.GetProbeCommandByCommandID(e.CommandID)
		if cerr != nil {
			httputil.InternalError(c, "Failed to read command", cerr)
			return
		}
		if cmd == nil { // pruned/missing while deploying → unknown (may have written)
			er.Status = "missing"
			anyBad, allAbortedPreWrite, unknown[i] = true, false, true
			out = append(out, er)
			continue
		}
		er.Status = cmd.Status
		if json.Valid([]byte(cmd.Result)) {
			er.Report = json.RawMessage(cmd.Result)
		} else if cmd.Result != "" {
			er.RawResult = cmd.Result
		}
		switch cmd.Status {
		case database.ProbeCommandStatusPending, database.ProbeCommandStatusDispatched:
			pending, allAbortedPreWrite = true, false
		case database.ProbeCommandStatusExpired:
			anyBad, allAbortedPreWrite, unknown[i] = true, false, true
		case database.ProbeCommandStatusFailed:
			anyBad, allAbortedPreWrite, unknown[i] = true, false, true
			failMsg = firstNonEmpty(failMsg, cmd.Result, "apply command failed")
			// AUDIT IP4: a Failed apply may still have created device objects
			// before it failed. Best-effort parse the result and merge any
			// captured UUIDs so auto-rollback can delete them — otherwise they
			// leak as orphans and the end is forced to RollbackUnproven.
			var frv ipsecApplyReportView
			if json.Unmarshal([]byte(cmd.Result), &frv) == nil && len(frv.CapturedUUIDs) > 0 {
				if e.CapturedUUIDs == nil {
					e.CapturedUUIDs = map[string]string{}
				}
				for k, v := range frv.CapturedUUIDs {
					e.CapturedUUIDs[k] = v
				}
			}
		case database.ProbeCommandStatusSucceeded:
			var rv ipsecApplyReportView
			if json.Unmarshal([]byte(cmd.Result), &rv) != nil {
				anyBad, allAbortedPreWrite, unknown[i] = true, false, true
				failMsg = firstNonEmpty(failMsg, "apply report unparseable")
				break
			}
			if len(rv.CapturedUUIDs) > 0 {
				if e.CapturedUUIDs == nil {
					e.CapturedUUIDs = map[string]string{}
				}
				for k, v := range rv.CapturedUUIDs {
					e.CapturedUUIDs[k] = v
				}
			}
			if rv.Conflict {
				anyConflict = true
				collisions = append(collisions, rv.Collisions...)
			}
			if rv.Applied && rv.Verified && !rv.Aborted && !rv.Conflict {
				anyGood, allAbortedPreWrite = true, false
			} else {
				anyBad = true
				failMsg = firstNonEmpty(failMsg, applyFailReason(rv), "apply did not complete")
				if !rv.Aborted { // applied-but-unverified / partial write ⇒ something was written
					allAbortedPreWrite = false
				}
			}
		}
		out = append(out, er)
	}

	// Only transition a non-terminal tunnel; never regress an already-terminal one.
	// Exactly ONE guarded write per outcome (F2).
	if m.Status == ipsecStatusDeploying {
		switch {
		case pending:
			// still deploying — no change
		case !anyBad && anyGood:
			// every deployable end applied + object-verified → SA-liveness
			// verification (C2b-2b): enqueue a read-only ipsec_status probe per
			// end IN THE SAME guarded write and keep polling degraded until they
			// resolve to up / down / inconclusive. A probe-build failure is not
			// fatal: that end gets no StatusCommandID and the degraded-eval
			// branch treats it as inconclusive, never a guessed transition.
			status = ipsecStatusDegraded
			note = "both ends deployed and object-verified; verifying SA liveness…"
			intent, ierr := database.IPSecModelToIntent(m)
			var sCmds []*models.ProbeCommand
			if ierr != nil {
				note = "both ends deployed and object-verified; SA liveness check unavailable (malformed intent)"
				log.Printf("ipsec-deploy: tunnel %d: cannot decode intent for SA probes: %v", id, ierr)
			} else {
				for i := range st.Ends {
					cmd, berr := ipsecBuildStatusCmd(db, m, intent, st.Ends[i])
					if berr != nil {
						note = "both ends deployed and object-verified; SA liveness check partially unavailable"
						log.Printf("ipsec-deploy: tunnel %d: SA probe build failed: %v", id, berr)
						continue
					}
					st.Ends[i].StatusCommandID = cmd.CommandID
					sCmds = append(sCmds, cmd)
				}
			}
			blob, _ := json.Marshal(st)
			_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusDeploying}, status, "", string(blob), true, sCmds)
		case allAbortedPreWrite:
			// nothing was written on any end → keep the record; NO auto-rollback
			// (there is nothing to reverse). Escape = operator rollback (clears it).
			status = ipsecStatusError
			blob, _ := json.Marshal(st)
			_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusDeploying}, status,
				firstNonEmpty(failMsg, "deploy aborted before any write"), string(blob), false, nil)
		default:
			// partial / some end wrote but not all-good → AUTO-ROLLBACK (compensate).
			// Mark unproven ends FIRST, to completion — the marker loop must not be
			// cut short by a build failure below, or a later unknown OPNsense end
			// would be left unmarked and a subsequent manual rollback would clear the
			// record over possible orphans. Only OPNsense removes rely on captured
			// UUIDs: an unknown-outcome OPNsense end with no captured UUIDs skips
			// every delete and reports a false-clean. FortiGate's remove is
			// self-proving (GET-before-DELETE by deterministic mkey), so an unknown
			// FortiGate end is NOT unproven.
			for i := range st.Ends {
				if unknown[i] && st.Ends[i].Vendor == "opnsense" && len(st.Ends[i].CapturedUUIDs) == 0 {
					st.Ends[i].RollbackUnproven = true
				}
			}
			rbCmds := make([]*models.ProbeCommand, 0, len(st.Ends))
			rbIDs := make([]string, 0, len(st.Ends))
			buildErr := ""
			for i := range st.Ends {
				cmd, berr := ipsecBuildRemoveCmd(db, m.ID, m.Name, st.Ends[i])
				if berr != nil {
					buildErr = berr.Error()
					break
				}
				rbCmds = append(rbCmds, cmd)
				rbIDs = append(rbIDs, cmd.CommandID)
			}
			if buildErr != "" {
				status = ipsecStatusError
				blob, _ := json.Marshal(st)
				_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusDeploying}, status,
					"deploy failed and the automatic rollback could not be built ("+buildErr+") — roll back manually", string(blob), false, nil)
			} else {
				st.Rollback = &ipsec.RollbackState{CommandIDs: rbIDs, StartedAt: time.Now().UTC().Format(time.RFC3339), Auto: true}
				status = ipsecStatusRollingBack
				note = "automatic rollback: a deploy end failed — reversing the tunnel"
				blob, _ := json.Marshal(st)
				_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusDeploying}, status,
					firstNonEmpty(failMsg, "deploy failed"), string(blob), false, rbCmds)
			}
		}
	}

	// A terminal down keeps its reason in last_error; surface it on re-polls
	// (the classify path only sets note on live transitions).
	if note == "" && m.Status == ipsecStatusDown {
		note = m.LastError
	}

	// On the deploying→degraded transition frame the SA probes were JUST
	// enqueued — flag them in flight so the deploy modal keeps polling for the
	// up/down resolution instead of stopping at the bare degraded frame.
	saPending := status == ipsecStatusDegraded && st != nil && ipsecHasStatusChecks(st)

	c.JSON(http.StatusOK, response.Success(gin.H{
		"tunnel_id": m.ID, "status": status, "note": note, "ends": out,
		"conflict": anyConflict, "collisions": collisions, "sa_pending": saPending,
	}))
}

// ipsecHasStatusChecks reports whether any deployed end carries an SA-liveness
// probe to evaluate (C2b-2b).
func ipsecHasStatusChecks(st *ipsec.DeployState) bool {
	for i := range st.Ends {
		if st.Ends[i].StatusCommandID != "" {
			return true
		}
	}
	return false
}

// evalIPSecStatusChecks drives a degraded tunnel to up / down / (stays)
// degraded from its per-end ipsec_status probes (C2b-2b). While any probe is
// still in flight it answers sa_pending so the deploy modal keeps polling. The
// RAW device document is parsed by the vendor driver's ParseStatus (server-side,
// tunnel-aware). Transition rules: EVERY end's IKE+Child up ⇒ up; ANY end
// definitively down ⇒ down; anything else (probe failed/lost/unparseable,
// collector too old to know ipsec_status, parser inconclusive) ⇒ STAY degraded —
// a guessed up/down is worse than an honest degraded. All transitions are ONE
// guarded write (F2); a lost race just re-polls.
func (h *Handler) evalIPSecStatusChecks(c *gin.Context, db database.Store, m *models.IPSecTunnel, st *ipsec.DeployState) {
	id := m.ID
	type saView struct {
		End      int                 `json:"end"`
		DeviceID uint                `json:"device_id"`
		Status   string              `json:"status"`
		SA       *ipsec.TunnelStatus `json:"sa,omitempty"`
	}
	out := make([]saView, 0, len(st.Ends))
	pending := false
	allUp, anyDown := true, false
	var downReasons, incReasons []string

	var intent *ipsec.TunnelIntent
	var ierr error
	intentDecoded := false

	for i := range st.Ends {
		e := &st.Ends[i]
		sv := saView{End: e.End, DeviceID: e.DeviceID, Status: "none"}
		lbl := fmt.Sprintf("end %c", 'A'+e.End)
		inconclusive := func(reason string) {
			allUp = false
			incReasons = append(incReasons, lbl+": "+reason)
		}
		if e.StatusCommandID == "" {
			inconclusive("no SA probe was enqueued")
			out = append(out, sv)
			continue
		}
		cmd, cerr := db.GetProbeCommandByCommandID(e.StatusCommandID)
		if cerr != nil {
			httputil.InternalError(c, "Failed to read command", cerr)
			return
		}
		if cmd == nil {
			inconclusive("SA probe result was lost")
			out = append(out, sv)
			continue
		}
		sv.Status = cmd.Status
		switch cmd.Status {
		case database.ProbeCommandStatusPending, database.ProbeCommandStatusDispatched:
			pending = true
		case database.ProbeCommandStatusSucceeded:
			var rv ipsecStatusReportView
			switch {
			case json.Unmarshal([]byte(cmd.Result), &rv) != nil:
				inconclusive("SA probe report unparseable")
			case rv.Error != "":
				inconclusive(rv.Error)
			case len(rv.Steps) == 0 || rv.Steps[0].Body == "":
				inconclusive("SA probe returned no device document")
			case rv.Steps[0].Status < 200 || rv.Steps[0].Status >= 300:
				inconclusive(fmt.Sprintf("SA probe got HTTP %d", rv.Steps[0].Status))
			default:
				if !intentDecoded {
					intent, ierr = database.IPSecModelToIntent(m)
					intentDecoded = true
				}
				drv, dok := ipsec.Driver(e.Vendor)
				switch {
				case ierr != nil:
					inconclusive("malformed intent")
				case !dok:
					inconclusive("no IPSec driver for " + e.Vendor)
				default:
					// Drivers emit exactly one probe step today; the definitive
					// document is steps[0] (FG monitor/vpn/ipsec, OPN
					// sessions/searchPhase1).
					ts, perr := drv.ParseStatus(rv.Steps[0].Body, ipsec.ViewFor(intent, e.End))
					switch {
					case perr != nil:
						inconclusive(perr.Error())
					default:
						sv.SA = &ts
						rs := fmt.Sprintf("%s ike=%s child=%s", lbl, ts.IKE, ts.Child)
						if ts.RawError != "" {
							rs += " (" + ts.RawError + ")"
						}
						switch {
						case ts.IKE == ipsec.SAUp && ts.Child == ipsec.SAUp:
							// end fully up
						case ts.IKE == ipsec.SADown || ts.Child == ipsec.SADown:
							anyDown, allUp = true, false
							downReasons = append(downReasons, rs)
						default:
							allUp = false
							incReasons = append(incReasons, rs)
						}
					}
				}
			}
		default: // failed / expired — incl. an old collector's "unknown command type"
			allUp = false
			msg := lbl + ": SA probe " + cmd.Status
			if cmd.Result != "" {
				msg += " — " + cmd.Result
			}
			incReasons = append(incReasons, msg)
		}
		out = append(out, sv)
	}

	if pending {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"tunnel_id": id, "status": m.Status, "sa_pending": true,
			"note": "deployed and object-verified — verifying SA liveness…", "ends": out,
		}))
		return
	}

	status := m.Status
	note := ""
	switch {
	case allUp && len(st.Ends) > 0:
		status = ipsecStatusUp
		note = "both ends deployed, object-verified, and SA up"
		blob, _ := json.Marshal(st)
		_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusDegraded}, status, "", string(blob), false, nil)
	case anyDown:
		status = ipsecStatusDown
		note = "SA did not come up — " + strings.Join(append(downReasons, incReasons...), "; ")
		blob, _ := json.Marshal(st)
		_ = db.TransitionIPSecDeploy(id, []string{ipsecStatusDegraded}, status, note, string(blob), false, nil)
	default:
		note = "SA liveness inconclusive — " + strings.Join(incReasons, "; ")
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"tunnel_id": id, "status": status, "note": note, "ends": out, "sa_pending": false,
	}))
}

// ipsecApplyReportView is the minimal shape of the collector's ApplyReport the
// server needs to decide per-end success. It carries no secrets.
type ipsecApplyReportView struct {
	Applied       bool                 `json:"applied"`
	Verified      bool                 `json:"verified"`
	Aborted       bool                 `json:"aborted"`
	Conflict      bool                 `json:"conflict"`
	Collisions    []string             `json:"collisions"`
	Error         string               `json:"error"`
	CapturedUUIDs map[string]string    `json:"captured_uuids"`
	Steps         []ipsecApplyStepView `json:"steps"`
}

type ipsecApplyStepView struct {
	Op   string `json:"op"`
	Path string `json:"path"`
	Note string `json:"note"`
	OK   bool   `json:"ok"`
}

// applyFailReason builds the deploy-failure reason from a report: the top-level
// error plus the FIRST failing step's endpoint (e.g. addGateway), so the
// persisted last_error names WHICH write the device rejected instead of only a
// generic message. Older collectors that omit `steps` degrade to just the error.
func applyFailReason(rv ipsecApplyReportView) string {
	var step string
	for _, s := range rv.Steps {
		if !s.OK {
			step = strings.TrimSpace(s.Op + " " + s.Path)
			if s.Note != "" {
				step = strings.TrimSpace(step + " — " + s.Note)
			}
			break
		}
	}
	switch {
	case rv.Error != "" && step != "":
		return rv.Error + " [" + step + "]"
	case step != "":
		return step
	default:
		return rv.Error
	}
}

// RollbackIPSecTunnel reverses a deploy from the stored per-end remove-steps
// snapshot (NOT a re-render — so a later intent edit can't change what gets
// removed). It enqueues remove_ipsec per deployed end and moves the tunnel to
// rolling_back; the terminal rolled_back/rollback_failed is poll-driven.
func (h *Handler) RollbackIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	st, perr := parseDeployState(m)
	if perr != nil {
		httputil.InternalError(c, "Failed to read deploy state", perr)
		return
	}
	if st == nil || len(st.Ends) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("nothing to roll back — no deploy record for this tunnel"))
		return
	}
	if live, lerr := ipsecHasLiveCommand(db, st); lerr != nil {
		httputil.InternalError(c, "Failed to check in-flight commands", lerr)
		return
	} else if live {
		c.JSON(http.StatusConflict, response.Error("a deploy or rollback is already in progress for this tunnel"))
		return
	}

	cmds := make([]*models.ProbeCommand, 0, len(st.Ends))
	rollbackIDs := make([]string, 0, len(st.Ends))
	for i := range st.Ends {
		cmd, berr := ipsecBuildRemoveCmd(db, m.ID, m.Name, st.Ends[i])
		if berr != nil {
			c.JSON(http.StatusBadRequest, response.Error(berr.Error()))
			return
		}
		cmds = append(cmds, cmd)
		rollbackIDs = append(rollbackIDs, cmd.CommandID)
	}

	st.Rollback = &ipsec.RollbackState{CommandIDs: rollbackIDs, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	blob, merr := json.Marshal(st)
	if merr != nil {
		httputil.InternalError(c, "Failed to encode deploy state", merr)
		return
	}
	fromStatuses := []string{ipsecStatusDegraded, ipsecStatusUp, ipsecStatusDown, ipsecStatusError, ipsecStatusRollbackFailed}
	// AUDIT IP3: carry an operator-initiated reason (not empty) so the terminal
	// banner reads "rolled back — operator-initiated rollback" instead of
	// synthesizing the misleading "deploy failed" when LastError is empty. The
	// auto-rollback path still carries the real deploy failure.
	if terr := db.TransitionIPSecDeploy(id, fromStatuses, ipsecStatusRollingBack, "operator-initiated rollback", string(blob), false, cmds); terr != nil {
		if errors.Is(terr, database.ErrIPSecConcurrentDeploy) {
			c.JSON(http.StatusConflict, response.Error("tunnel is not in a rollback-able state (nothing deployed, or a deploy/rollback is in progress)"))
			return
		}
		httputil.InternalError(c, "Failed to start rollback", terr)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"tunnel_id": m.ID, "status": ipsecStatusRollingBack, "commands": rollbackIDs}))
}

// RecheckIPSecTunnel re-runs SA-liveness verification on an already-deployed
// tunnel (C2b-2b): it re-enqueues the read-only ipsec_status probe per end and
// moves the tunnel back to degraded, so the existing deploy-poll eval drives it
// to up / down from the FRESH device state. This is the operator's recovery path
// for a tunnel that came up AFTER the one-shot post-deploy check (e.g. a slow
// dialup peer) and so is stuck reading down — no redeploy, no device mutation.
// Allowed only from a settled state (up/down/degraded) with no command in flight.
func (h *Handler) RecheckIPSecTunnel(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	st, perr := parseDeployState(m)
	if perr != nil {
		httputil.InternalError(c, "Failed to read deploy state", perr)
		return
	}
	if st == nil || len(st.Ends) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("nothing to recheck — no deploy record for this tunnel"))
		return
	}
	switch m.Status {
	case ipsecStatusUp, ipsecStatusDown, ipsecStatusDegraded:
		// settled — a recheck is meaningful
	default:
		c.JSON(http.StatusConflict, response.Error("tunnel is not in a re-checkable state (deploy or rollback in progress)"))
		return
	}
	if live, lerr := ipsecHasLiveCommand(db, st); lerr != nil {
		httputil.InternalError(c, "Failed to check in-flight commands", lerr)
		return
	} else if live {
		c.JSON(http.StatusConflict, response.Error("a deploy or rollback is already in progress for this tunnel"))
		return
	}

	intent, ierr := database.IPSecModelToIntent(m)
	if ierr != nil {
		c.JSON(http.StatusBadRequest, response.Error("cannot recheck — tunnel intent is malformed: "+ierr.Error()))
		return
	}
	// Build a fresh status probe per end. Best-effort per end (a device with no
	// collector yields no probe → that end evaluates inconclusive), but at least
	// one probe must build or there is nothing to recheck.
	var sCmds []*models.ProbeCommand
	var buildErrs []string
	for i := range st.Ends {
		st.Ends[i].StatusCommandID = "" // drop the stale probe id; re-set on success
		cmd, berr := ipsecBuildStatusCmd(db, m, intent, st.Ends[i])
		if berr != nil {
			buildErrs = append(buildErrs, berr.Error())
			continue
		}
		st.Ends[i].StatusCommandID = cmd.CommandID
		sCmds = append(sCmds, cmd)
	}
	if len(sCmds) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("cannot recheck — no SA probe could be built: "+strings.Join(buildErrs, "; ")))
		return
	}

	blob, merr := json.Marshal(st)
	if merr != nil {
		httputil.InternalError(c, "Failed to encode deploy state", merr)
		return
	}
	fromStatuses := []string{ipsecStatusUp, ipsecStatusDown, ipsecStatusDegraded}
	if terr := db.TransitionIPSecDeploy(id, fromStatuses, ipsecStatusDegraded, "", string(blob), false, sCmds); terr != nil {
		if errors.Is(terr, database.ErrIPSecConcurrentDeploy) {
			c.JSON(http.StatusConflict, response.Error("tunnel state changed — refresh and retry"))
			return
		}
		httputil.InternalError(c, "Failed to start recheck", terr)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"tunnel_id": m.ID, "status": ipsecStatusDegraded, "sa_pending": true,
		"note": "re-verifying SA liveness…",
	}))
}

// ipsecBuildRemoveCmd builds the remove_ipsec command for one deployed end from
// its stored RemoveSteps snapshot + captured-UUID substitutions (empty for
// FortiGate). Shared by manual RollbackIPSecTunnel and the poll's auto-rollback.
func ipsecBuildRemoveCmd(db database.Store, tunnelID uint, tunnelName string, e ipsec.DeployEndState) (*models.ProbeCommand, error) {
	dev, derr := db.GetDevice(e.DeviceID)
	if derr != nil {
		return nil, fmt.Errorf("end %c device (id %d) not found — cannot roll back", 'A'+e.End, e.DeviceID)
	}
	if dev.ProbeID == nil || *dev.ProbeID == 0 {
		return nil, fmt.Errorf("end %c (%s): device has no collector assigned", 'A'+e.End, dev.Name)
	}
	port := dev.APIPort
	if port == 0 {
		port = 443
	}
	payload := ipsecApplyPayload{
		TunnelID:      tunnelID,
		TunnelName:    tunnelName,
		End:           e.End,
		Vendor:        e.Vendor,
		DeviceID:      dev.ID,
		BaseURL:       fmt.Sprintf("https://%s:%d", dev.IPAddress, port),
		Op:            "remove",
		OwnerTag:      tunnelName,
		APIToken:      dev.APIToken,
		InsecureTLS:   dev.APIInsecureTLS,
		Steps:         e.RemoveSteps,
		Checksum:      e.RemoveChecksum,
		Substitutions: e.CapturedUUIDs, // resolve <uuid:NAME> deletes (OPNsense); nil for FortiGate
	}
	// api_token marshaled intentionally (gosec G117 CI-excluded).
	buf, merr := json.Marshal(payload)
	if merr != nil {
		return nil, merr
	}
	return &models.ProbeCommand{
		ProbeID:   *dev.ProbeID,
		DeviceID:  dev.ID,
		CommandID: uuid.NewString(),
		Type:      database.ProbeCommandTypeIPSecRemove,
		Payload:   string(buf),
	}, nil
}

// ForceResetIPSecDeploy is the operator escape from a wedged deploy record: it
// clears the record (→ draft) so the tunnel is deploy/edit/delete-able again.
// Needed because a RollbackUnproven-forced rollback_failed can NEVER self-clear
// (a retry re-skips and re-fails). It touches NO device — the operator explicitly
// acknowledges the device may still hold objects and must verify manually. Allowed
// ONLY from error/rollback_failed AND only when no command is in flight; audited.
func (h *Handler) ForceResetIPSecDeploy(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	m, err := db.GetIPSecTunnel(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	if m.Status != ipsecStatusError && m.Status != ipsecStatusRollbackFailed {
		c.JSON(http.StatusConflict, response.Error("reset is only allowed from error or rollback_failed — roll back a deployed tunnel instead of resetting it"))
		return
	}
	st, perr := parseDeployState(m)
	if perr != nil {
		httputil.InternalError(c, "Failed to read deploy state", perr)
		return
	}
	if live, lerr := ipsecHasLiveCommand(db, st); lerr != nil {
		httputil.InternalError(c, "Failed to check in-flight commands", lerr)
		return
	} else if live {
		c.JSON(http.StatusConflict, response.Error("a command is still in flight for this tunnel — wait for it to finish before resetting"))
		return
	}
	// One guarded clear (deploy_json → "") from the record-bearing terminal states.
	if terr := db.TransitionIPSecDeploy(id, []string{ipsecStatusError, ipsecStatusRollbackFailed}, ipsecStatusDraft, "", "", false, nil); terr != nil {
		if errors.Is(terr, database.ErrIPSecConcurrentDeploy) {
			c.JSON(http.StatusConflict, response.Error("tunnel state changed — refresh and retry"))
			return
		}
		httputil.InternalError(c, "Failed to reset deploy record", terr)
		return
	}
	// Forensic record: WHO force-cleared WHICH tunnel's deploy record (device state
	// unverified). Best-effort — a log failure must not block the recovery.
	usernameVal, _ := c.Get("username")
	userIDVal, _ := c.Get("user_id")
	usernameStr, _ := usernameVal.(string)
	userID, _ := userIDVal.(uint)
	if err := db.SaveAuditLog(&models.AuditLog{
		CreatedAt: time.Now(),
		Actor:     usernameStr,
		ActorID:   userID,
		Method:    "POST",
		Action:    "ipsec_deploy_reset",
		Target:    fmt.Sprintf("tunnel_id=%d prev_status=%s", m.ID, m.Status),
		Status:    http.StatusOK,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}); err != nil {
		log.Printf("ipsec-deploy-reset: audit log write failed for tunnel %d by %s: %v", m.ID, usernameStr, err)
	}
	c.JSON(http.StatusOK, response.Success(gin.H{
		"tunnel_id": m.ID, "status": ipsecStatusDraft,
		"warning": "Firewall-Mon's deploy record was cleared. The device MAY still hold objects for this tunnel — verify and remove them manually.",
	}))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// --- IPSec wizard "endpoint hints" (read-only) --------------------------------
//
// GetIPSecEndpointHints feeds the wizard the picked device's REAL interfaces +
// addresses (from the latest poll) so the operator selects egress/LAN interfaces
// from live values and gets WAN IP + LAN subnets auto-filled instead of typing
// them. Read-only; returns interface names/addresses only (no secrets). Admin-only.

type ipsecHintAddr struct {
	IP     string `json:"ip"`
	CIDR   string `json:"cidr,omitempty"` // network CIDR, absent for /30-/32 or unparseable
	Public bool   `json:"public"`         // globally-routable (a WAN/public endpoint candidate)
}

type ipsecHintIface struct {
	Name      string          `json:"name"`
	TypeName  string          `json:"type_name"`
	Status    string          `json:"status"`
	IsLAN     bool            `json:"is_lan"`
	Addresses []ipsecHintAddr `json:"addresses"`
}

type ipsecHintsResponse struct {
	WANIP           string           `json:"wan_ip"`
	Interfaces      []ipsecHintIface `json:"interfaces"`
	SuggestedEgress string           `json:"suggested_egress"`
	SuggestedLAN    string           `json:"suggested_lan"`
	SuggestedPeerIP string           `json:"suggested_peer_ip"` // best-guess public endpoint (egress iface's public addr)
	LANSubnets      []string         `json:"lan_subnets"`
}

func (h *Handler) GetIPSecEndpointHints(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	device, err := db.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}

	// Latest interface + address snapshot for THIS device (same latest-timestamp
	// pattern as GetDeviceDetail). A never-polled device yields empty slices — the
	// wizard falls back to its editable fields, so this must not error.
	gdb := db.Gorm()
	latest := func(table string) *gorm.DB {
		return gdb.Where("device_id = ? AND timestamp = (SELECT MAX(timestamp) FROM "+table+" WHERE device_id = ?)", id, id)
	}
	var ifaces []models.InterfaceStats
	if err := latest("interface_stats").Find(&ifaces).Error; err != nil {
		log.Printf("ipsec-hints: device %d interface stats: %v", id, err)
	}
	var addrs []models.InterfaceAddress
	if err := latest("interface_addresses").Find(&addrs).Error; err != nil {
		log.Printf("ipsec-hints: device %d interface addresses: %v", id, err)
	}

	addrsByIdx := make(map[int][]models.InterfaceAddress, len(addrs))
	for _, a := range addrs {
		addrsByIdx[a.IfIndex] = append(addrsByIdx[a.IfIndex], a)
	}

	resp := ipsecHintsResponse{
		WANIP:      device.IPAddress,
		Interfaces: []ipsecHintIface{},
		LANSubnets: []string{},
	}
	// Pass 1: build the interface list with per-address CIDR + public flags. (No
	// protected-subnet selection yet — that needs the WAN endpoint decided first.)
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	for _, iface := range ifaces {
		// A VPN/tunnel carrier (tun0, wg0, …) is never a LAN segment even when its
		// ifType reports propVirtual — exclude it from LAN classification + subnets.
		isLAN := netclass.IsLANType(iface.TypeName) && !netclass.IsVPNInterfaceName(iface.Name)
		hi := ipsecHintIface{
			Name:      iface.Name,
			TypeName:  iface.TypeName,
			Status:    iface.Status,
			IsLAN:     isLAN,
			Addresses: []ipsecHintAddr{},
		}
		for _, a := range addrsByIdx[iface.Index] {
			ha := ipsecHintAddr{IP: a.IPAddress, Public: netclass.IsPublicIP(a.IPAddress)}
			if cidr, ok := netclass.SubnetCIDR(a.IPAddress, a.NetMask); ok {
				ha.CIDR = cidr
			}
			hi.Addresses = append(hi.Addresses, ha)
		}
		resp.Interfaces = append(resp.Interfaces, hi)
	}

	upNonVPN := func(hi ipsecHintIface) bool {
		return strings.EqualFold(hi.Status, "up") && !netclass.IsVPNInterfaceName(hi.Name)
	}
	hasPublic := func(hi ipsecHintIface) bool {
		for _, a := range hi.Addresses {
			if a.Public {
				return true
			}
		}
		return false
	}
	bearsPolledIP := func(hi ipsecHintIface) bool {
		for _, a := range hi.Addresses {
			if a.IP == device.IPAddress {
				return true
			}
		}
		return false
	}
	pick := func(want func(ipsecHintIface) bool) {
		if resp.SuggestedEgress != "" {
			return
		}
		for _, hi := range resp.Interfaces {
			if want(hi) {
				resp.SuggestedEgress = hi.Name
				return
			}
		}
	}
	// Egress = the WAN uplink. Prefer an up, non-VPN interface that carries a PUBLIC
	// address (the real internet uplink) — NOT the interface that merely bears the
	// polling IP, so a device monitored over its LAN mgmt address doesn't pick the
	// LAN as its "egress". Order: public+polled → any public → bears-polled-IP
	// (all-private/lab box) → first up non-LAN non-VPN.
	pick(func(hi ipsecHintIface) bool { return upNonVPN(hi) && hasPublic(hi) && bearsPolledIP(hi) })
	pick(func(hi ipsecHintIface) bool { return upNonVPN(hi) && hasPublic(hi) })
	pick(func(hi ipsecHintIface) bool { return bearsPolledIP(hi) })
	pick(func(hi ipsecHintIface) bool { return !hi.IsLAN && upNonVPN(hi) })

	var egressIface *ipsecHintIface
	for i := range resp.Interfaces {
		if resp.Interfaces[i].Name == resp.SuggestedEgress {
			egressIface = &resp.Interfaces[i]
			break
		}
	}

	// Suggested peer IP = this end's own public endpoint: egress public → any public
	// → egress first addr → polled mgmt IP (behind NAT — operator overrides via
	// Custom…; the preview's peer_private warning nudges them).
	if egressIface != nil {
		for _, a := range egressIface.Addresses {
			if a.Public {
				resp.SuggestedPeerIP = a.IP
				break
			}
		}
	}
	if resp.SuggestedPeerIP == "" {
		for _, hi := range resp.Interfaces {
			for _, a := range hi.Addresses {
				if a.Public {
					resp.SuggestedPeerIP = a.IP
					break
				}
			}
			if resp.SuggestedPeerIP != "" {
				break
			}
		}
	}
	if resp.SuggestedPeerIP == "" && egressIface != nil && len(egressIface.Addresses) > 0 {
		resp.SuggestedPeerIP = egressIface.Addresses[0].IP
	}
	if resp.SuggestedPeerIP == "" {
		resp.SuggestedPeerIP = device.IPAddress
	}

	// Protected-subnet candidates = LAN-segment networks, EXCLUDING the egress (WAN)
	// interface's own subnets AND any subnet that contains this end's WAN endpoint
	// (suggested_peer_ip). The "contains the peer IP" rule is the bulletproof guard:
	// a protected subnet can never include the WAN endpoint, so the tunnel never
	// self-locks-out on the wizard's own suggestions — regardless of which address
	// the device is polled over. Fabric/link-local + /30–/32 are already filtered.
	peerIP := net.ParseIP(resp.SuggestedPeerIP)
	seenSubnet := map[string]bool{}
	for _, hi := range resp.Interfaces {
		if !hi.IsLAN || hi.Name == resp.SuggestedEgress {
			continue
		}
		for _, a := range hi.Addresses {
			if a.CIDR == "" || seenSubnet[a.CIDR] || netclass.IsFabricInterface(hi.Name, a.IP) {
				continue
			}
			// A protected LAN is a private network; a public address is a WAN/transit
			// or DMZ uplink, never an auto-suggested protected subnet (defends against
			// a mis-picked egress leaving another public interface's subnet in).
			if a.Public {
				continue
			}
			if _, n, err := net.ParseCIDR(a.CIDR); err == nil && peerIP != nil && n.Contains(peerIP) {
				continue // never protect a subnet that contains the WAN endpoint
			}
			seenSubnet[a.CIDR] = true
			resp.LANSubnets = append(resp.LANSubnets, a.CIDR)
		}
	}

	// LAN = first up LAN-type interface carrying an address, excluding the egress
	// (WAN) interface itself (fall back to any such interface if none report "up").
	for _, hi := range resp.Interfaces {
		if hi.Name != resp.SuggestedEgress && hi.IsLAN && strings.EqualFold(hi.Status, "up") && len(hi.Addresses) > 0 {
			resp.SuggestedLAN = hi.Name
			break
		}
	}
	if resp.SuggestedLAN == "" {
		for _, hi := range resp.Interfaces {
			if hi.Name != resp.SuggestedEgress && hi.IsLAN && len(hi.Addresses) > 0 {
				resp.SuggestedLAN = hi.Name
				break
			}
		}
	}

	c.JSON(http.StatusOK, response.Success(resp))
}

// --- LAN interface ⇄ protected subnet coherence (device facts) ---------------

// deviceIfaceNets is one interface and the networks its addresses sit on.
type deviceIfaceNets struct {
	Name  string
	IsLAN bool
	Nets  []*net.IPNet
}

// deviceInterfaceNets returns each interface with EVERY network its addresses
// carry — a port can hold several, and a subnet on a secondary address counts
// just as much as one on the primary.
//
// Same latest-snapshot join GetIPSecEndpointHints uses; a never-polled device
// yields nothing, which callers must treat as "cannot say", never as "wrong".
func (h *Handler) deviceInterfaceNets(db database.Store, deviceID uint) []deviceIfaceNets {
	if db == nil || deviceID == 0 {
		return nil
	}
	gdb := db.Gorm()
	latest := func(table string) *gorm.DB {
		return gdb.Where("device_id = ? AND timestamp = (SELECT MAX(timestamp) FROM "+table+" WHERE device_id = ?)", deviceID, deviceID)
	}
	var ifaces []models.InterfaceStats
	if err := latest("interface_stats").Find(&ifaces).Error; err != nil {
		log.Printf("lan coherence: device %d interface stats: %v", deviceID, err)
		return nil
	}
	var addrs []models.InterfaceAddress
	if err := latest("interface_addresses").Find(&addrs).Error; err != nil {
		log.Printf("lan coherence: device %d interface addresses: %v", deviceID, err)
		return nil
	}
	byIdx := make(map[int][]models.InterfaceAddress, len(addrs))
	for _, a := range addrs {
		byIdx[a.IfIndex] = append(byIdx[a.IfIndex], a)
	}
	out := make([]deviceIfaceNets, 0, len(ifaces))
	for _, iface := range ifaces {
		e := deviceIfaceNets{
			Name:  iface.Name,
			IsLAN: netclass.IsLANType(iface.TypeName) && !netclass.IsVPNInterfaceName(iface.Name),
		}
		for _, a := range byIdx[iface.Index] {
			// SubnetCIDR declines /30-/32 and IPv6; such an address simply does not
			// participate. Safe here because the finding requires a POSITIVE match on
			// another interface, so a blind spot loses sensitivity, never precision.
			cidr, ok := netclass.SubnetCIDR(a.IPAddress, a.NetMask)
			if !ok {
				continue
			}
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				e.Nets = append(e.Nets, n)
			}
		}
		out = append(out, e)
	}
	return out
}

// lanCoherenceFindings warns when a protected subnet is disjoint from every
// SELECTED LAN interface yet sits on some OTHER local interface — i.e. the
// policies will name a port the traffic never touches, so it is dropped while
// the tunnel reports healthy.
//
// Deliberately narrow. It stays silent when the subnet is on no local interface
// at all (routed via a downstream L3 device — legitimate and common), when it
// merely contains or is contained by a selected interface's network
// (containment counts as a match in either direction, so supernets are fine),
// and when the device has no interface data. A check that fired on those would
// be noise, and an advisory operators learn to ignore is worse than none.
func (h *Handler) lanCoherenceFindings(db database.Store, intent *ipsec.TunnelIntent) []ipsec.Finding {
	if intent == nil {
		return nil
	}
	var out []ipsec.Finding
	for i := range intent.Ends {
		end := &intent.Ends[i]
		drv, ok := ipsec.Driver(end.Vendor)
		if !ok || !drv.Capabilities().UsesLANIface {
			continue // this vendor's rules never name an interface
		}
		ifaces := h.deviceInterfaceNets(db, end.DeviceID)
		if len(ifaces) == 0 {
			continue // never polled — cannot say
		}
		selected := make(map[string]bool)
		for _, n := range end.EffectiveLANIfaces() {
			selected[n] = true
		}
		for _, s := range end.ProtectedSubnets {
			_, subnet, err := net.ParseCIDR(strings.TrimSpace(s))
			if err != nil {
				continue // subnet_invalid already covers this
			}
			onSelected, carrier := false, ""
			for _, ifc := range ifaces {
				for _, n := range ifc.Nets {
					if !n.Contains(subnet.IP) && !subnet.Contains(n.IP) {
						continue
					}
					if selected[ifc.Name] {
						onSelected = true
					} else if carrier == "" && ifc.IsLAN {
						carrier = ifc.Name
					}
				}
			}
			if onSelected || carrier == "" {
				continue
			}
			out = append(out, ipsec.Finding{
				Severity: ipsec.SeverityWarn,
				Code:     "lan_subnet_mismatch",
				End:      &i,
				// The subnet, so the UI can highlight the ONE lane this is about.
				// A code+end pair cannot distinguish two mismatches on the same end,
				// and digging it back out of Message would weld the client to prose.
				Subject: s,
				Message: fmt.Sprintf("%s: protected subnet %s is not on any selected LAN interface — it is on %s. "+
					"The firewall policies will name the selected interface(s), so traffic for %s is dropped even though the tunnel comes up.",
					endLabelForVendor(intent, i), s, carrier, s),
			})
		}
	}
	return out
}

// endLabelForVendor mirrors the validation package's end labelling so a finding
// from here reads identically to one from Validate.
func endLabelForVendor(intent *ipsec.TunnelIntent, i int) string {
	return fmt.Sprintf("end %c (%s)", 'A'+i, intent.Ends[i].Vendor)
}
