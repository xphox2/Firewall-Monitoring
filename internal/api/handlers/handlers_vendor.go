package handlers

import (
	"sort"
	"strings"
	"time"
)

// GenericVendor is the vendor every ingest path assumes when a device has no
// usable vendor: id 0 (no device), a missing row, or an empty / unknown value.
// It is the one place that answers "what does no vendor mean" — the DB
// default (models.Device), the create handler and the SNMP resolver all say
// the same, and the vendor_default_guard guardrail keeps a `"fortigate"`
// default from creeping back in.
const GenericVendor = "generic"

// deviceVendorCacheTTL bounds how long a device's vendor is served from the
// per-handler cache on the ingest paths (an operator changing a device's
// vendor in the UI is picked up within this window).
const deviceVendorCacheTTL = 60 * time.Second

type deviceVendorEntry struct {
	vendor string
	expiry time.Time
}

// deviceVendor returns the lower-cased vendor of device id, or GenericVendor
// for id 0, a device that does not exist, or an empty stored value. The result
// is TTL-cached per id (deviceVendorCacheTTL) so a syslog batch from one
// device costs at most one GetDevice per minute, not one per batch. Every
// ingest-side vendor dispatch (deny projection; attribution and normalization
// in later PRs) goes through here so the fallback cannot drift between them.
func (h *Handler) deviceVendor(id uint) string {
	if id == 0 || h.db == nil {
		return GenericVendor
	}
	now := time.Now()
	h.mu.RLock()
	e, ok := h.deviceVendorCache[id]
	h.mu.RUnlock()
	if ok && now.Before(e.expiry) {
		return e.vendor
	}
	vendor := GenericVendor
	if dev, err := h.db.GetDevice(id); err == nil && dev != nil {
		if v := strings.ToLower(strings.TrimSpace(dev.Vendor)); v != "" {
			vendor = v
		}
	}
	h.mu.Lock()
	if h.deviceVendorCache == nil {
		h.deviceVendorCache = make(map[uint]deviceVendorEntry)
	}
	h.deviceVendorCache[id] = deviceVendorEntry{vendor: vendor, expiry: now.Add(deviceVendorCacheTTL)}
	h.mu.Unlock()
	return vendor
}

// validVendorList returns the accepted vendor names, sorted, for error
// messages — built from validVendors so adding a vendor is a one-map change.
func validVendorList() string {
	names := make([]string, 0, len(validVendors))
	for v := range validVendors {
		names = append(names, v)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// invalidVendorMessage is the 400 body for a vendor outside validVendors.
func invalidVendorMessage() string {
	return "Invalid vendor: must be one of " + validVendorList()
}
