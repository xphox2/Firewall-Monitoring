package handlers

import (
	"fmt"
	"net/http"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/ipsec"
	_ "firewall-mon/internal/ipsec/vendors" // register fortigate + opnsense drivers

	"github.com/gin-gonic/gin"
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

// resolveCaps returns both ends' capability descriptors, or a client error if a
// vendor has no provisioning driver.
func resolveCaps(intent *ipsec.TunnelIntent) (caps [2]ipsec.CapabilityDescriptor, badVendor string) {
	for i := range intent.Ends {
		c, err := ipsec.Capabilities(intent.Ends[i].Vendor)
		if err != nil {
			return caps, intent.Ends[i].Vendor
		}
		caps[i] = c
	}
	return caps, ""
}

// hydrateDerived fills the ID-derived, wizard-owned fields (name, VTI addressing,
// reqids) deterministically so both ends stay consistent and a redeploy is
// stable. Called after the row has an ID.
func hydrateDerived(intent *ipsec.TunnelIntent) {
	id := intent.ID
	intent.Name = fmt.Sprintf("fwm-t%d", id)
	cidr, innerA, innerB := ipsec.AllocateVTI(id)
	if intent.Mode == ipsec.ModeRouteBased {
		intent.VTISubnet = cidr
		intent.Ends[0].InnerIP = innerA
		intent.Ends[1].InnerIP = innerB
	}
	// A per-tunnel reqid keeps both ends' child SA / VTI aligned; the collector
	// re-allocates against live device state at apply time if it collides.
	intent.Ends[0].Reqid = int(id)
	intent.Ends[1].Reqid = int(id)
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
	if _, bad := resolveCaps(&intent); bad != "" {
		c.JSON(http.StatusBadRequest, response.Error("No IPSec provisioning driver for vendor: "+bad))
		return
	}
	if intent.PSK == "" {
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
	if err := db.CreateIPSecTunnel(m); err != nil {
		httputil.InternalError(c, "Failed to create tunnel", err)
		return
	}
	// Backfill ID-derived fields and re-persist so the stored intent is complete.
	intent.ID = m.ID
	hydrateDerived(&intent)
	m2, _ := database.IPSecIntentToModel(&intent)
	m2.ID = m.ID
	m2.Status = "draft"
	if err := db.UpdateIPSecTunnel(m2); err != nil {
		httputil.InternalError(c, "Failed to finalize tunnel", err)
		return
	}

	caps, _ := resolveCaps(&intent)
	findings := ipsec.Validate(&intent, caps)
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
	if caps, bad := resolveCaps(intent); bad == "" {
		findings = ipsec.Validate(intent, caps)
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
	if _, err := db.GetIPSecTunnel(id); err != nil {
		c.JSON(http.StatusNotFound, response.Error("Tunnel not found"))
		return
	}
	var intent ipsec.TunnelIntent
	if err := c.ShouldBindJSON(&intent); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if _, bad := resolveCaps(&intent); bad != "" {
		c.JSON(http.StatusBadRequest, response.Error("No IPSec provisioning driver for vendor: "+bad))
		return
	}
	intent.ID = id
	hydrateDerived(&intent)
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
	if err := db.DeleteIPSecTunnel(id); err != nil {
		httputil.InternalError(c, "Failed to delete tunnel", err)
		return
	}
	c.JSON(http.StatusOK, response.Message("Tunnel deleted"))
}

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
	caps, bad := resolveCaps(intent)
	if bad != "" {
		c.JSON(http.StatusBadRequest, response.Error("No IPSec provisioning driver for vendor: "+bad))
		return
	}
	previews := make([]endPreview, 0, 2)
	for i := range intent.Ends {
		d, _ := ipsec.Driver(intent.Ends[i].Vendor)
		art, rerr := d.Render(ipsec.ViewFor(intent, i))
		if rerr != nil {
			c.JSON(http.StatusBadRequest, response.Error(fmt.Sprintf("end %c (%s): %v", 'A'+i, intent.Ends[i].Vendor, rerr)))
			return
		}
		previews = append(previews, endPreview{
			End: i, Vendor: intent.Ends[i].Vendor, Preview: art.PreviewText,
			AutoObjects: art.AutoObjects, Steps: len(art.Steps),
		})
	}
	findings := ipsec.Validate(intent, caps)
	c.JSON(http.StatusOK, response.Success(gin.H{"ends": previews, "validation": findings}))
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
