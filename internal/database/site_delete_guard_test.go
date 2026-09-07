package database

import (
	"errors"
	"testing"

	"firewall-mon/internal/models"
)

// TestDeleteSite_RefusesWithMembers: a site with a device (even a RETIRED one)
// or a probe cannot be deleted — pre-v0.11.239 DeleteSite cascaded a raw
// DELETE over both, silently destroying device rows.
func TestDeleteSite_RefusesWithMembers(t *testing.T) {
	d := NewDatabaseForTesting(t)

	withDevice := &models.Site{Name: "with-device"}
	withProbe := &models.Site{Name: "with-probe"}
	empty := &models.Site{Name: "empty"}
	for _, s := range []*models.Site{withDevice, withProbe, empty} {
		if err := d.CreateSite(s); err != nil {
			t.Fatalf("create site: %v", err)
		}
	}
	dev := &models.Device{Name: "fw", IPAddress: "10.0.0.1", SiteID: &withDevice.ID}
	if err := d.db.Create(dev).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := d.RetireDevice(dev.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := d.CreateProbe(&models.Probe{Name: "p", SiteID: withProbe.ID}); err != nil {
		t.Fatalf("create probe: %v", err)
	}

	if err := d.DeleteSite(withDevice.ID); !errors.Is(err, ErrSiteHasMembers) {
		t.Errorf("delete site with a retired device: err = %v, want ErrSiteHasMembers", err)
	}
	if err := d.DeleteSite(withProbe.ID); !errors.Is(err, ErrSiteHasMembers) {
		t.Errorf("delete site with a probe: err = %v, want ErrSiteHasMembers", err)
	}
	if err := d.DeleteSite(empty.ID); err != nil {
		t.Errorf("delete empty site: %v", err)
	}

	// Nothing was cascaded.
	var sites, devices, probes int64
	d.db.Model(&models.Site{}).Count(&sites)
	d.db.Model(&models.Device{}).Count(&devices)
	d.db.Model(&models.Probe{}).Count(&probes)
	if sites != 2 || devices != 1 || probes != 1 {
		t.Errorf("after guarded deletes: sites=%d devices=%d probes=%d, want 2/1/1", sites, devices, probes)
	}
}
