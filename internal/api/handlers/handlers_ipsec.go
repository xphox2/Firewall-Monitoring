package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	TunnelID    uint                  `json:"tunnel_id"`
	TunnelName  string                `json:"tunnel_name"`
	End         int                   `json:"end"` // 0=A, 1=B
	Vendor      string                `json:"vendor"`
	DeviceID    uint                  `json:"device_id"`
	BaseURL     string                `json:"base_url"`
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

	deviceIDs := [2]uint{m.ADeviceID, m.BDeviceID}
	enqueued := make([]ipsecPreflightEnqueued, 0, 2)
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
			Steps:       drv.PreflightProbe(ipsec.ViewFor(intent, i)),
		}
		buf, merr := json.Marshal(payload)
		if merr != nil {
			httputil.InternalError(c, "Failed to build preflight payload", merr)
			return
		}
		cmd := &models.ProbeCommand{
			ProbeID:  *dev.ProbeID,
			DeviceID: dev.ID,
			Type:     database.ProbeCommandTypeIPSecPreflight,
			Payload:  string(buf),
		}
		if eerr := db.EnqueueProbeCommand(cmd); eerr != nil {
			httputil.InternalError(c, "Failed to enqueue preflight", eerr)
			return
		}
		enqueued = append(enqueued, ipsecPreflightEnqueued{
			End: i, DeviceID: dev.ID, Vendor: intent.Ends[i].Vendor, ProbeID: *dev.ProbeID, CommandID: cmd.CommandID,
		})
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
		End       int             `json:"end"`
		DeviceID  uint            `json:"device_id"`
		Status    string          `json:"status"` // pending/dispatched/succeeded/failed/expired, or "none"
		Report    json.RawMessage `json:"report"` // structured collector report (when succeeded)
		RawResult string          `json:"raw_result,omitempty"`
	}
	out := make([]endReport, 0, 2)
	for i, devID := range [2]uint{m.ADeviceID, m.BDeviceID} {
		er := endReport{End: i, DeviceID: devID, Status: "none"}
		cmd, cerr := db.GetLatestCommandByDeviceType(devID, database.ProbeCommandTypeIPSecPreflight)
		if cerr == nil && cmd != nil {
			er.Status = cmd.Status
			if json.Valid([]byte(cmd.Result)) {
				er.Report = json.RawMessage(cmd.Result)
			} else if cmd.Result != "" {
				er.RawResult = cmd.Result
			}
		}
		out = append(out, er)
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"tunnel_id": m.ID, "ends": out}))
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
