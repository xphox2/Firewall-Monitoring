package handlers

import (
	"net/http"
	"strings"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// handlers_event_profiles.go — management API for Event Rule Profiles (v48):
// the Default > Site > Device chain of per-alert-type toggles + rule layers.
// All routes admin-only (a toggle Off silences alerting — same class as event
// rules). Every write ends with refreshAlertConfigCache so the API's own
// resolver sees the change immediately; poller/trap pick it up on their
// refresh cadence.

// eventProfileRow is the list payload: profile + live-joined counts.
type eventProfileRow struct {
	models.EventRuleProfile
	Counts database.EventProfileCounts `json:"counts"`
}

func (h *Handler) ListEventRuleProfiles(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	profiles, err := db.GetAllEventRuleProfiles()
	if err != nil {
		httputil.InternalError(c, "Failed to list event rule profiles", err)
		return
	}
	defaultID := uint(0)
	for _, p := range profiles {
		if p.IsDefault {
			defaultID = p.ID
		}
	}
	counts, err := db.GetEventProfileCounts(defaultID)
	if err != nil {
		httputil.InternalError(c, "Failed to count profile contents", err)
		return
	}
	rows := make([]eventProfileRow, 0, len(profiles))
	for _, p := range profiles {
		row := eventProfileRow{EventRuleProfile: p}
		if pc := counts[p.ID]; pc != nil {
			row.Counts = *pc
		}
		rows = append(rows, row)
	}
	c.JSON(http.StatusOK, response.Success(rows))
}

func validateProfileName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "Profile name is required"
	}
	if len(name) > 200 {
		return "Profile name too long (max 200)"
	}
	return ""
}

func (h *Handler) CreateEventRuleProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if msg := validateProfileName(req.Name); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	p := models.EventRuleProfile{Name: strings.TrimSpace(req.Name), Description: req.Description}
	if err := db.CreateEventRuleProfile(&p); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Failed to create profile (name must be unique)"))
		return
	}
	h.refreshAlertConfigCache(db)
	c.JSON(http.StatusOK, response.Success(p))
}

func (h *Handler) GetEventRuleProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	p, err := db.GetEventRuleProfile(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Profile not found"))
		return
	}
	toggles, err := db.GetProfileToggles(id)
	if err != nil {
		httputil.InternalError(c, "Failed to load toggles", err)
		return
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"profile": p, "toggles": toggles}))
}

func (h *Handler) UpdateEventRuleProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	existing, err := db.GetEventRuleProfile(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Profile not found"))
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if msg := validateProfileName(req.Name); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	name := strings.TrimSpace(req.Name)
	if existing.IsDefault && name != existing.Name {
		// The Default profile is the chain anchor every UI string references.
		c.JSON(http.StatusBadRequest, response.Error("The Default profile cannot be renamed"))
		return
	}
	existing.Name = name
	existing.Description = req.Description
	if err := db.UpdateEventRuleProfile(existing); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Failed to update profile (name must be unique)"))
		return
	}
	h.refreshAlertConfigCache(db)
	c.JSON(http.StatusOK, response.Success(existing))
}

func (h *Handler) DeleteEventRuleProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if err := db.DeleteEventRuleProfile(id); err != nil {
		c.JSON(http.StatusBadRequest, response.Error(err.Error()))
		return
	}
	h.refreshAlertConfigCache(db)
	c.JSON(http.StatusOK, response.Success(gin.H{"deleted": id}))
}

func (h *Handler) CloneEventRuleProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if msg := validateProfileName(req.Name); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	if _, err := db.GetEventRuleProfile(id); err != nil {
		c.JSON(http.StatusNotFound, response.Error("Profile not found"))
		return
	}
	clone, err := db.CloneEventRuleProfile(id, strings.TrimSpace(req.Name))
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Failed to clone profile (name must be unique)"))
		return
	}
	h.refreshAlertConfigCache(db)
	c.JSON(http.StatusOK, response.Success(clone))
}

// PutProfileToggles replaces a profile's full sparse toggle set. The body is
// ONLY the non-Inherit rows — the UI renders every type from /api/alert-types
// and omits Inherit, so full-replace cannot drop unknown types.
func (h *Handler) PutProfileToggles(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	profile, err := db.GetEventRuleProfile(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Profile not found"))
		return
	}
	var req struct {
		Toggles []struct {
			AlertType models.AlertType `json:"alert_type"`
			Enabled   bool             `json:"enabled"`
		} `json:"toggles"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	seen := map[models.AlertType]bool{}
	toggles := make([]models.EventRuleProfileToggle, 0, len(req.Toggles))
	for _, t := range req.Toggles {
		if !models.TogglableAlertType(t.AlertType) {
			c.JSON(http.StatusBadRequest, response.Error("Unknown alert type: "+string(t.AlertType)))
			return
		}
		if seen[t.AlertType] {
			c.JSON(http.StatusBadRequest, response.Error("Duplicate alert type: "+string(t.AlertType)))
			return
		}
		seen[t.AlertType] = true
		toggles = append(toggles, models.EventRuleProfileToggle{AlertType: t.AlertType, Enabled: t.Enabled})
	}
	if err := db.ReplaceProfileToggles(profile.ID, toggles); err != nil {
		httputil.InternalError(c, "Failed to save toggles", err)
		return
	}
	h.refreshAlertConfigCache(db)
	c.JSON(http.StatusOK, response.Success(gin.H{"saved": len(toggles)}))
}

// ListAlertTypes serves the canonical registry the toggle matrix and the rule
// builder render from — the server is the single source of truth (the old
// hardcoded JS list drifted).
func (h *Handler) ListAlertTypes(c *gin.Context) {
	c.JSON(http.StatusOK, response.Success(models.AllAlertTypes()))
}

// assignBody is the {profile_id: n|null} payload for the column-targeted
// assignment endpoints. A pointer-to-pointer distinguishes "clear" (explicit
// null) from garbage.
type assignBody struct {
	ProfileID *uint `json:"profile_id"`
}

// validateAssignProfile loads the target profile when non-nil so a typo'd ID
// can't create a dangling assignment (dangling refs fall through safely at
// fire time, but the UI would show a ghost).
func validateAssignProfile(db database.Store, profileID *uint) string {
	if profileID == nil {
		return ""
	}
	if _, err := db.GetEventRuleProfile(*profileID); err != nil {
		return "Profile not found"
	}
	return ""
}

func (h *Handler) SetDeviceEventProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if _, err := db.GetDevice(id); err != nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}
	var req assignBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if msg := validateAssignProfile(db, req.ProfileID); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	if err := db.SetDeviceEventProfile(id, req.ProfileID); err != nil {
		httputil.InternalError(c, "Failed to assign event profile", err)
		return
	}
	h.refreshAlertConfigCache(db)
	c.JSON(http.StatusOK, response.Success(gin.H{"device_id": id, "profile_id": req.ProfileID}))
}

func (h *Handler) SetSiteEventProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if _, err := db.GetSite(id); err != nil {
		c.JSON(http.StatusNotFound, response.Error("Site not found"))
		return
	}
	var req assignBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	if msg := validateAssignProfile(db, req.ProfileID); msg != "" {
		c.JSON(http.StatusBadRequest, response.Error(msg))
		return
	}
	if err := db.SetSiteEventProfile(id, req.ProfileID); err != nil {
		httputil.InternalError(c, "Failed to assign event profile", err)
		return
	}
	h.refreshAlertConfigCache(db)
	c.JSON(http.StatusOK, response.Success(gin.H{"site_id": id, "profile_id": req.ProfileID}))
}

// GetEventProfileAssignments lists the live sites/devices assigned to a
// profile — the Assignments tab's view over the same config columns the
// entity-side selects write.
func (h *Handler) GetEventProfileAssignments(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if _, err := db.GetEventRuleProfile(id); err != nil {
		c.JSON(http.StatusNotFound, response.Error("Profile not found"))
		return
	}
	sites, devices, err := db.GetEventProfileAssignments(id)
	if err != nil {
		httputil.InternalError(c, "Failed to load assignments", err)
		return
	}
	if sites == nil {
		sites = []database.EventProfileAssignment{}
	}
	if devices == nil {
		devices = []database.EventProfileAssignment{}
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"sites": sites, "devices": devices}))
}

// BatchAssignEventProfile assigns this profile to the listed sites/devices
// (ADDITIVE — it never touches assignments not listed; removal goes through
// the per-entity endpoints with profile_id null, so a stale batch can't
// silently strip someone else's assignment).
func (h *Handler) BatchAssignEventProfile(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	if _, err := db.GetEventRuleProfile(id); err != nil {
		c.JSON(http.StatusNotFound, response.Error("Profile not found"))
		return
	}
	var req struct {
		SiteIDs   []uint `json:"site_ids"`
		DeviceIDs []uint `json:"device_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}
	// Validate the WHOLE list before writing anything (a mid-list 400 after
	// partial writes would leave assignments half-applied), and refresh the
	// resolver even on a write error so any assignments that DID land are
	// live in this process, not stale until the next cadence tick.
	for _, sid := range req.SiteIDs {
		if _, err := db.GetSite(sid); err != nil {
			c.JSON(http.StatusBadRequest, response.Error("Site not found"))
			return
		}
	}
	for _, did := range req.DeviceIDs {
		if _, err := db.GetDevice(did); err != nil {
			c.JSON(http.StatusBadRequest, response.Error("Device not found"))
			return
		}
	}
	defer h.refreshAlertConfigCache(db)
	pid := id
	assigned := 0
	for _, sid := range req.SiteIDs {
		if err := db.SetSiteEventProfile(sid, &pid); err != nil {
			httputil.InternalError(c, "Failed to assign site", err)
			return
		}
		assigned++
	}
	for _, did := range req.DeviceIDs {
		if err := db.SetDeviceEventProfile(did, &pid); err != nil {
			httputil.InternalError(c, "Failed to assign device", err)
			return
		}
		assigned++
	}
	c.JSON(http.StatusOK, response.Success(gin.H{"assigned": assigned}))
}

// GetEffectiveEventConfig returns the resolved profile chain, every alert
// type's toggle state (+ deciding layer), and the applicable rules in
// evaluation order for a device or site — computed by the SAME locked
// resolvers the firing path uses.
func (h *Handler) GetEffectiveEventConfig(c *gin.Context) {
	if h.alertManager == nil {
		c.JSON(http.StatusServiceUnavailable, response.Error("Alert engine not ready"))
		return
	}
	deviceID, dOK := httputil.ParseUintQuery(c, "device_id")
	siteRaw, sOK := httputil.ParseUintQuery(c, "site_id")
	if !dOK && !sOK {
		c.JSON(http.StatusBadRequest, response.Error("device_id or site_id is required"))
		return
	}
	var siteID *uint
	if sOK {
		siteID = &siteRaw
	}
	if !dOK {
		deviceID = 0
	}
	chain, toggles, rules := h.alertManager.EffectiveEventConfig(deviceID, siteID)
	c.JSON(http.StatusOK, response.Success(gin.H{
		"chain":   chain,
		"toggles": toggles,
		"rules":   rules,
	}))
}
