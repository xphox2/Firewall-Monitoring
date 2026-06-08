package handlers

import (
	"log"
	"net/http"
	"strings"

	"firewall-mon/internal/api/response"
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

	if site.ParentSiteID != nil && *site.ParentSiteID > 0 {
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

	site.ID = 0
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
		if parentIDVal == nil {
			updates["parent_site_id"] = nil
		} else if pid, isNum := parentIDVal.(float64); isNum && pid > 0 {
			parentID := uint(pid)
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

	if err := db.Gorm().Model(site).Updates(filteredUpdates).Error; err != nil {
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
		httputil.InternalError(c, "Failed to delete site", err)
		return
	}

	c.JSON(http.StatusOK, response.Message("Site deleted"))
}
