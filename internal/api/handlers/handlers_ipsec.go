package handlers

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/ipsec"
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
	caps, cerr := resolveCaps(intent)
	if cerr != nil {
		c.JSON(http.StatusBadRequest, response.Error(cerr.Error()))
		return
	}
	previews, rerr := renderBothEnds(intent)
	if rerr != nil {
		c.JSON(http.StatusBadRequest, response.Error(rerr.Error()))
		return
	}
	findings := ipsec.Validate(intent, caps)
	c.JSON(http.StatusOK, response.Success(gin.H{"ends": previews, "validation": findings}))
}

// renderBothEnds renders each end's redacted preview. It returns ONLY endPreview
// (PreviewText + step count) — never the raw Artifact/Steps, which carry the
// plaintext PSK. Shared by the stored-tunnel and stateless preview handlers.
func renderBothEnds(intent *ipsec.TunnelIntent) ([]endPreview, error) {
	previews := make([]endPreview, 0, 2)
	for i := range intent.Ends {
		d, ok := ipsec.Driver(intent.Ends[i].Vendor)
		if !ok {
			return nil, fmt.Errorf("end %c (%q): no IPSec provisioning driver", 'A'+i, intent.Ends[i].Vendor)
		}
		art, err := d.Render(ipsec.ViewFor(intent, i))
		if err != nil {
			return nil, fmt.Errorf("end %c (%s): %v", 'A'+i, intent.Ends[i].Vendor, err)
		}
		previews = append(previews, endPreview{
			End: i, Vendor: intent.Ends[i].Vendor, Preview: art.PreviewText,
			AutoObjects: art.AutoObjects, Steps: len(art.Steps),
		})
	}
	return previews, nil
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
	pskAutogen := intent.PSK == "" || intent.PSK == ipsecPSKMask
	if pskAutogen {
		intent.PSK = ipsecPreviewPlaceholderPSK // validate/render only; never returned
	}
	// Honor a client-supplied id for edit-mode previews (read-only endpoint —
	// trusting the id is harmless) so an edit preview is exact; id=0 → provisional.
	hydrateDerived(&intent)
	findings := ipsec.Validate(&intent, caps)
	previews, rerr := renderBothEnds(&intent)
	if rerr != nil {
		c.JSON(http.StatusBadRequest, response.Error(rerr.Error()))
		return
	}
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

// --- IPSec wizard "endpoint hints" (read-only) --------------------------------
//
// GetIPSecEndpointHints feeds the wizard the picked device's REAL interfaces +
// addresses (from the latest poll) so the operator selects egress/LAN interfaces
// from live values and gets WAN IP + LAN subnets auto-filled instead of typing
// them. Read-only; returns interface names/addresses only (no secrets). Admin-only.

type ipsecHintAddr struct {
	IP   string `json:"ip"`
	CIDR string `json:"cidr,omitempty"` // network CIDR, absent for /30-/32 or unparseable
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
	// The interface bearing the device's polled (WAN/mgmt) IP is the egress; its
	// own network is transit, never a "protected" LAN — exclude it from lan_subnets
	// (otherwise a WAN /29 would be suggested as a protected subnet).
	wanIdx := -1
	for _, a := range addrs {
		if a.IPAddress == device.IPAddress {
			wanIdx = a.IfIndex
			break
		}
	}

	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	seenSubnet := map[string]bool{}
	for _, iface := range ifaces {
		isLAN := netclass.IsLANType(iface.TypeName)
		hi := ipsecHintIface{
			Name:      iface.Name,
			TypeName:  iface.TypeName,
			Status:    iface.Status,
			IsLAN:     isLAN,
			Addresses: []ipsecHintAddr{},
		}
		for _, a := range addrsByIdx[iface.Index] {
			ha := ipsecHintAddr{IP: a.IPAddress}
			if cidr, ok := netclass.SubnetCIDR(a.IPAddress, a.NetMask); ok {
				ha.CIDR = cidr
				// A candidate "protected subnet": a LAN-segment network that is not
				// the WAN/egress transit network and not a FortiLink/link-local link.
				if isLAN && iface.Index != wanIdx && !netclass.IsFabricInterface(iface.Name, a.IPAddress) && !seenSubnet[cidr] {
					seenSubnet[cidr] = true
					resp.LANSubnets = append(resp.LANSubnets, cidr)
				}
			}
			hi.Addresses = append(hi.Addresses, ha)
		}
		resp.Interfaces = append(resp.Interfaces, hi)
	}

	// Egress = the interface bearing the device's polled (WAN/mgmt) IP, else the
	// first up non-LAN interface.
	for _, hi := range resp.Interfaces {
		for _, a := range hi.Addresses {
			if a.IP == device.IPAddress {
				resp.SuggestedEgress = hi.Name
				break
			}
		}
		if resp.SuggestedEgress != "" {
			break
		}
	}
	if resp.SuggestedEgress == "" {
		for _, hi := range resp.Interfaces {
			if !hi.IsLAN && strings.EqualFold(hi.Status, "up") {
				resp.SuggestedEgress = hi.Name
				break
			}
		}
	}
	// LAN = first up LAN-type interface carrying an address, excluding the egress
	// (WAN) interface itself (fall back to any such interface if none report "up",
	// since sFlow-only rows have no admin status).
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
