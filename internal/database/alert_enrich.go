package database

import (
	"firewall-mon/internal/models"

	"gorm.io/gorm"
)

// deviceSiteRow is one device's name and site, for display enrichment.
type deviceSiteRow struct {
	ID     uint
	Name   string
	SiteID *uint
}

// deviceSiteNames resolves device names (with their site) and site names in
// two batched queries: the devices, then every site referenced either by those
// devices or directly by siteIDs. Unknown ids are simply absent from the maps.
func deviceSiteNames(g *gorm.DB, deviceIDs, siteIDs []uint) (map[uint]deviceSiteRow, map[uint]string) {
	devByID := make(map[uint]deviceSiteRow)
	siteSet := make(map[uint]struct{}, len(siteIDs))
	for _, id := range siteIDs {
		siteSet[id] = struct{}{}
	}
	if len(deviceIDs) > 0 {
		var devs []deviceSiteRow
		g.Model(&models.Device{}).Where("id IN ?", deviceIDs).Select("id, name, site_id").Scan(&devs)
		for _, d := range devs {
			devByID[d.ID] = d
			if d.SiteID != nil {
				siteSet[*d.SiteID] = struct{}{}
			}
		}
	}
	siteName := make(map[uint]string)
	if len(siteSet) > 0 {
		sids := make([]uint, 0, len(siteSet))
		for id := range siteSet {
			sids = append(sids, id)
		}
		var sites []struct {
			ID   uint
			Name string
		}
		g.Model(&models.Site{}).Where("id IN ?", sids).Select("id, name").Scan(&sites)
		for _, s := range sites {
			siteName[s.ID] = s.Name
		}
	}
	return devByID, siteName
}

// EnrichAlertDeviceSite fills each alert's transient DeviceName/SiteName from its
// DeviceID in two batched queries (devices, then their sites), so the alerts
// list, the alert detail and the NOC feed identify the device by NAME and show
// its site without an N+1.
func EnrichAlertDeviceSite(g *gorm.DB, alerts []models.Alert) {
	if len(alerts) == 0 {
		return
	}
	idset := map[uint]struct{}{}
	var siteIDs []uint
	for _, a := range alerts {
		if a.DeviceID != 0 {
			idset[a.DeviceID] = struct{}{}
		}
		// Site-scoped alerts (e.g. the SFLOW_SECURITY_DIGEST storm rollup) carry no
		// device but persist their own SiteID — resolve those site names too.
		if a.SiteID != nil {
			siteIDs = append(siteIDs, *a.SiteID)
		}
	}
	ids := make([]uint, 0, len(idset))
	for id := range idset {
		ids = append(ids, id)
	}
	devByID, siteName := deviceSiteNames(g, ids, siteIDs)
	for i := range alerts {
		if d, ok := devByID[alerts[i].DeviceID]; ok {
			alerts[i].DeviceName = d.Name
			if d.SiteID != nil {
				alerts[i].SiteName = siteName[*d.SiteID]
			}
		}
		// Fall back to the alert's own persisted SiteID (site-scoped, device-less
		// alerts) when the device→site path didn't set a name.
		if alerts[i].SiteName == "" && alerts[i].SiteID != nil {
			alerts[i].SiteName = siteName[*alerts[i].SiteID]
		}
	}
}
