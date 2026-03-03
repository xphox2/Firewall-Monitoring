package handlers

import (
	"net/http"
	"strings"

	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetSites(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, models.SuccessResponse([]models.Site{}))
		return
	}

	sites, err := h.db.GetAllSites()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to fetch sites"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(sites))
}

func (h *Handler) GetSite(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	site, err := h.db.GetSite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Site not found"))
		return
	}

	var children []models.Site
	h.db.Gorm().Where("parent_site_id = ?", id).Find(&children)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"data":     site,
		"children": children,
	})
}

func (h *Handler) CreateSite(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	var site models.Site
	if err := c.ShouldBindJSON(&site); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if strings.TrimSpace(site.Name) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Name is required"))
		return
	}

	if len(site.Name) > 255 || len(site.Region) > 255 || len(site.Country) > 255 ||
		len(site.Address) > 500 || len(site.Timezone) > 100 || len(site.Description) > 1000 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("One or more fields exceed maximum length"))
		return
	}

	existing, err := h.db.GetSiteByName(site.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to check existing site"))
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, models.ErrorResponse("Site with this name already exists"))
		return
	}

	if site.ParentSiteID != nil && *site.ParentSiteID > 0 {
		parent, err := h.db.GetSite(*site.ParentSiteID)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Parent site not found"))
			return
		}
		if parent == nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("Parent site not found"))
			return
		}
	}

	site.ID = 0
	if err := h.db.CreateSite(&site); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to create site"))
		return
	}

	c.JSON(http.StatusCreated, models.SuccessResponse(site))
}

func (h *Handler) UpdateSite(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	site, err := h.db.GetSite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Site not found"))
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}

	if parentIDVal, ok := updates["parent_site_id"]; ok {
		if parentIDVal == nil {
			updates["parent_site_id"] = nil
		} else if pid, isNum := parentIDVal.(float64); isNum && pid > 0 {
			parentID := uint(pid)
			parent, err := h.db.GetSite(parentID)
			if err != nil || parent == nil {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Parent site not found"))
				return
			}
			if parentID == id {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Site cannot be its own parent"))
				return
			}
			// Walk up the parent chain to detect circular references (max depth 50)
			cur := parent
			for depth := 0; depth < 50; depth++ {
				if cur.ParentSiteID == nil || *cur.ParentSiteID == 0 {
					break
				}
				if *cur.ParentSiteID == id {
					c.JSON(http.StatusBadRequest, models.ErrorResponse("Circular parent reference detected"))
					return
				}
				ancestor, err := h.db.GetSite(*cur.ParentSiteID)
				if err != nil || ancestor == nil {
					break
				}
				cur = ancestor
			}
		}
	}

	filteredUpdates := httputil.FilterAllowedFields(updates, allowedFields)

	if len(filteredUpdates) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("No valid fields to update"))
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
				c.JSON(http.StatusBadRequest, models.ErrorResponse("Field "+field+" exceeds maximum length"))
				return
			}
		}
	}

	if nameVal, ok := filteredUpdates["name"]; ok {
		if nameStr, isStr := nameVal.(string); isStr {
			existing, err := h.db.GetSiteByName(nameStr)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to check existing site"))
				return
			}
			if existing != nil && existing.ID != id {
				c.JSON(http.StatusConflict, models.ErrorResponse("Site with this name already exists"))
				return
			}
		}
	}

	if err := h.db.Gorm().Model(site).Updates(filteredUpdates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to update site"))
		return
	}

	updated, err := h.db.GetSite(id)
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(site))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(updated))
}

func (h *Handler) DeleteSite(c *gin.Context) {
	if !httputil.RequireDB(c, h.db) {
		return
	}

	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}

	var children []models.Site
	if err := h.db.Gorm().Where("parent_site_id = ?", id).Find(&children).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to check child sites"))
		return
	}
	if len(children) > 0 {
		c.JSON(http.StatusConflict, models.ErrorResponse("Cannot delete site with child sites"))
		return
	}

	if err := h.db.DeleteSite(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Failed to delete site"))
		return
	}

	c.JSON(http.StatusOK, models.MessageResponse("Site deleted"))
}
