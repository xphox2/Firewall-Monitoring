package handlers

import (
	"errors"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/database"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetSites(c *gin.Context) {
	db := h.reqDB(c)
	if db == nil {
		c.JSON(http.StatusOK, response.Success([]models.Site{}))
		return
	}

	sites, err := db.GetAllSites()
	if err != nil {
		httputil.InternalError(c, "Failed to fetch sites", err)
		return
	}

	c.JSON(http.StatusOK, response.Success(sites))
}

func (h *Handler) GetSite(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	site, err := db.GetSite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Site not found"))
		return
	}

	// GetSite preloads Site.Probes; redact their sensitive fields (registration
	// key hash, TLS cert/key paths + material) before returning. This route is
	// reachable by the viewer role, so the redaction must happen here, not only
	// in an admin-only caller.
	httputil.RedactProbes(site.Probes)

	var children []models.Site
	if err := db.Gorm().Where("parent_site_id = ?", id).Find(&children).Error; err != nil {
		log.Printf("Site %d: failed to get children: %v", id, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"data":     site,
		"children": children,
	})
}

func (h *Handler) CreateSite(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	var site models.Site
	if err := c.ShouldBindJSON(&site); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if strings.TrimSpace(site.Name) == "" {
		c.JSON(http.StatusBadRequest, response.Error("Name is required"))
		return
	}

	if len(site.Name) > 255 || len(site.Region) > 255 || len(site.Country) > 255 ||
		len(site.Address) > 500 || len(site.Timezone) > 100 || len(site.Description) > 1000 {
		c.JSON(http.StatusBadRequest, response.Error("One or more fields exceed maximum length"))
		return
	}

	existing, err := db.GetSiteByName(site.Name)
	if err != nil {
		httputil.InternalError(c, "Failed to check existing site", err)
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, response.Error("Site with this name already exists"))
		return
	}

	// L-14: 0 is the UI's "no parent"; store it as NULL rather than a dangling
	// reference to a site 0 that can never exist.
	if site.ParentSiteID != nil && *site.ParentSiteID == 0 {
		site.ParentSiteID = nil
	}
	if site.ParentSiteID != nil {
		parent, err := db.GetSite(*site.ParentSiteID)
		if err != nil {
			c.JSON(http.StatusBadRequest, response.Error("Parent site not found"))
			return
		}
		if parent == nil {
			c.JSON(http.StatusBadRequest, response.Error("Parent site not found"))
			return
		}
	}

	// L-13: zero server-owned fields so a client cannot mass-assign them (same
	// hygiene as H-11's CreateIRCServer). The associations matter most: GORM's
	// Create upserts a populated parent_site / probes graph, so a nested object
	// in the body would write rows this endpoint never meant to touch.
	site.ID = 0
	site.CreatedAt = time.Time{}
	site.UpdatedAt = time.Time{}
	site.ParentSite = nil
	site.Probes = nil
	if err := db.CreateSite(&site); err != nil {
		httputil.InternalError(c, "Failed to create site", err)
		return
	}

	c.JSON(http.StatusCreated, response.Success(site))
}

func (h *Handler) UpdateSite(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	site, err := db.GetSite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, response.Error("Site not found"))
		return
	}

	allowedFields := map[string]bool{
		"name":           true,
		"region":         true,
		"country":        true,
		"address":        true,
		"timezone":       true,
		"parent_site_id": true,
		"description":    true,
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, response.Error("Invalid request"))
		return
	}

	if parentIDVal, ok := updates["parent_site_id"]; ok {
		// L-14: a JSON map decodes numbers as float64 and keeps strings/bools
		// as-is. Anything but null or a whole number in uint32 range used to
		// fall through to the UPDATE unvalidated — "abc" and 1.5 surfaced as
		// a 500 from PostgreSQL (SQLite stored them), -3 stored a dangling
		// parent. 0 and null both mean "no parent".
		pid, isNum := parentIDVal.(float64)
		switch {
		case parentIDVal == nil || (isNum && pid == 0):
			updates["parent_site_id"] = nil
		case !isNum || pid < 0 || pid != math.Trunc(pid) || pid > math.MaxUint32:
			c.JSON(http.StatusBadRequest, response.Error("Invalid parent_site_id"))
			return
		default:
			parentID := uint(pid)
			updates["parent_site_id"] = parentID
			parent, err := db.GetSite(parentID)
			if err != nil || parent == nil {
				c.JSON(http.StatusBadRequest, response.Error("Parent site not found"))
				return
			}
			if parentID == id {
				c.JSON(http.StatusBadRequest, response.Error("Site cannot be its own parent"))
				return
			}
			// Walk up the parent chain to detect circular references (max depth 50)
			cur := parent
			for depth := 0; depth < 50; depth++ {
				if cur.ParentSiteID == nil || *cur.ParentSiteID == 0 {
					break
				}
				if *cur.ParentSiteID == id {
					c.JSON(http.StatusBadRequest, response.Error("Circular parent reference detected"))
					return
				}
				ancestor, err := db.GetSite(*cur.ParentSiteID)
				if err != nil || ancestor == nil {
					break
				}
				cur = ancestor
			}
		}
	}

	filteredUpdates := httputil.FilterAllowedFields(updates, allowedFields)

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, response.Error("No valid fields to update"))
		return
	}

	// Validate string field lengths
	stringLimits := map[string]int{
		"name": 255, "region": 255, "country": 255,
		"address": 500, "timezone": 100, "description": 1000,
	}
	for field, maxLen := range stringLimits {
		if val, ok := filteredUpdates[field]; ok {
			if str, isStr := val.(string); isStr && len(str) > maxLen {
				c.JSON(http.StatusBadRequest, response.Error("Field "+field+" exceeds maximum length"))
				return
			}
		}
	}

	if nameVal, ok := filteredUpdates["name"]; ok {
		if nameStr, isStr := nameVal.(string); isStr {
			existing, err := db.GetSiteByName(nameStr)
			if err != nil {
				httputil.InternalError(c, "Failed to check existing site", err)
				return
			}
			if existing != nil && existing.ID != id {
				c.JSON(http.StatusConflict, response.Error("Site with this name already exists"))
				return
			}
		}
	}

	// Bare model + WHERE, not Model(site): GetSite preloads ParentSite, and
	// GORM re-derives parent_site_id from a loaded belongs-to association —
	// a parent change or clear returned 200 but persisted the OLD parent
	// (same trap UpdateDevice/UpdateProbe hit in v0.10.394).
	if err := db.Gorm().Model(&models.Site{}).Where("id = ?", id).Updates(filteredUpdates).Error; err != nil {
		httputil.InternalError(c, "Failed to update site", err)
		return
	}

	updated, err := db.GetSite(id)
	if err != nil {
		c.JSON(http.StatusOK, response.Success(site))
		return
	}
	c.JSON(http.StatusOK, response.Success(updated))
}

func (h *Handler) DeleteSite(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var children []models.Site
	if err := db.Gorm().Where("parent_site_id = ?", id).Find(&children).Error; err != nil {
		httputil.InternalError(c, "Failed to check child sites", err)
		return
	}
	if len(children) > 0 {
		c.JSON(http.StatusConflict, response.Error("Cannot delete site with child sites"))
		return
	}

	if err := db.DeleteSite(id); err != nil {
		if errors.Is(err, database.ErrSiteHasMembers) {
			c.JSON(http.StatusConflict, response.Error(
				"move or purge this site's devices and decommission its probes first"))
			return
		}
		httputil.InternalError(c, "Failed to delete site", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Site deleted"))
}
