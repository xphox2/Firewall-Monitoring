package handlers

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/httputil"
	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"
	"firewall-mon/internal/normalize/capability"

	"github.com/gin-gonic/gin"
)

// Capability API (Phase 1, S-4; roadmap §1.4): the static vendor profile
// (internal/normalize/capability) joined with what each device was actually
// observed sending (device_field_observed, written by the syslog ingest) over
// a 24-hour window. Both endpoints are admin-only (adminOnlyRoutes): the
// matrix says which log options are on and which features the fleet can
// report on. UI consumption is Phase 2.

// capabilityWindow is the observation window: a field seen within it counts
// as observed. A day covers every FortiGate option that logs on a schedule
// and the quiet overnight hours of a branch.
const capabilityWindow = 24 * time.Hour

// capabilityField is one (device, field) cell of the device matrix.
type capabilityField struct {
	State        capability.FieldState   `json:"state"`
	Source       capability.Source       `json:"source"`
	Completeness capability.Completeness `json:"completeness,omitempty"`
	Note         string                  `json:"note,omitempty"`
	Count        int64                   `json:"count"`
	LastSeen     *time.Time              `json:"last_seen,omitempty"`
}

// capabilityFeature is a feature's verdict for one device.
type capabilityFeature struct {
	State  capability.FeatureState `json:"state"`
	Fields []capability.Field      `json:"fields,omitempty"` // the fields that decided the state
}

// deviceCapabilities is the GET /admin/api/devices/:id/capabilities body.
type deviceCapabilities struct {
	DeviceID    uint                         `json:"device_id"`
	Vendor      string                       `json:"vendor"`
	Hardware    string                       `json:"hardware,omitempty"`
	WindowHours int                          `json:"window_hours"`
	Fields      map[string]capabilityField   `json:"fields"`
	Features    map[string]capabilityFeature `json:"features"`
}

// GetDeviceCapabilities returns the full matrix for one device: every
// tracked field with its effective state (native / partial /
// config_dependent / inactive / unsupported), and every feature's verdict.
func (h *Handler) GetDeviceCapabilities(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	id, ok := httputil.ParseID(c)
	if !ok {
		return
	}
	device, err := db.GetDevice(id)
	if err != nil || device == nil {
		c.JSON(http.StatusNotFound, response.Error("Device not found"))
		return
	}
	since := time.Now().Add(-capabilityWindow)
	rows, err := db.GetFieldObserved(id, since)
	if err != nil {
		httputil.InternalError(c, "Failed to load observed fields", err)
		return
	}
	observed := make(map[string]models.DeviceFieldObserved, len(rows))
	for _, r := range rows {
		observed[r.Field] = r
	}
	vendor := deviceVendorName(device)
	profile := capability.Lookup(vendor)
	out := deviceCapabilities{
		DeviceID:    device.ID,
		Vendor:      vendor,
		Hardware:    profile.Hardware,
		WindowHours: int(capabilityWindow / time.Hour),
		Fields:      make(map[string]capabilityField, len(normalize.ObservedFields)),
		Features:    make(map[string]capabilityFeature, len(capability.Features)),
	}
	for _, name := range normalize.ObservedFields {
		spec := profile.Spec(capability.Field(name))
		cell := capabilityField{Source: spec.Source, Completeness: spec.Completeness, Note: spec.Note}
		obs, seen := observed[name]
		if seen {
			cell.Count = obs.Count
			ls := obs.LastSeen
			cell.LastSeen = &ls
		}
		cell.State = capability.EffectiveState(spec, seen)
		out.Fields[name] = cell
	}
	for feature := range capability.Features {
		out.Features[feature] = featureVerdict(feature, profile, func(f capability.Field) bool {
			_, seen := observed[string(f)]
			return seen
		})
	}
	c.JSON(http.StatusOK, response.Success(out))
}

// fleetCapability is one device's row in GET /admin/api/capabilities.
type fleetCapability struct {
	DeviceID uint                    `json:"device_id"`
	Name     string                  `json:"name"`
	Vendor   string                  `json:"vendor"`
	State    capability.FeatureState `json:"state"`
	Fields   []capability.Field      `json:"fields,omitempty"`
}

// GetCapabilities answers "which devices can report on this feature":
// ?feature=<name> returns one row per active device with the feature's
// verdict. Without the parameter it lists the feature names and the fields
// each needs, so a caller can discover the vocabulary.
func (h *Handler) GetCapabilities(c *gin.Context) {
	db := h.reqDB(c)
	if !httputil.RequireDB(c, db) {
		return
	}
	feature := strings.TrimSpace(c.Query("feature"))
	if feature == "" {
		c.JSON(http.StatusOK, response.Success(gin.H{
			"features":     capability.Features,
			"window_hours": int(capabilityWindow / time.Hour),
		}))
		return
	}
	if _, ok := capability.Features[feature]; !ok {
		c.JSON(http.StatusBadRequest, response.Error("Unknown feature: must be one of "+strings.Join(capability.FeatureNames(), ", ")))
		return
	}
	devices, err := db.GetActiveDevices()
	if err != nil {
		httputil.InternalError(c, "Failed to load devices", err)
		return
	}
	rows, err := db.GetFieldObserved(0, time.Now().Add(-capabilityWindow))
	if err != nil {
		httputil.InternalError(c, "Failed to load observed fields", err)
		return
	}
	type devField struct {
		dev   uint
		field string
	}
	observed := make(map[devField]bool, len(rows))
	for _, r := range rows {
		observed[devField{r.DeviceID, r.Field}] = true
	}
	out := make([]fleetCapability, 0, len(devices))
	for i := range devices {
		d := &devices[i]
		vendor := deviceVendorName(d)
		v := featureVerdict(feature, capability.Lookup(vendor), func(f capability.Field) bool {
			return observed[devField{d.ID, string(f)}]
		})
		out = append(out, fleetCapability{DeviceID: d.ID, Name: d.Name, Vendor: vendor, State: v.State, Fields: v.Fields})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	c.JSON(http.StatusOK, response.Success(gin.H{
		"feature":      feature,
		"fields":       capability.Features[feature],
		"window_hours": int(capabilityWindow / time.Hour),
		"devices":      out,
	}))
}

// featureVerdict folds the feature's fields' effective states into one
// verdict, worst first: unsupported (a field the vendor cannot supply) >
// inactive (supplyable, not observed) > degraded (observed, but partial or
// config-dependent) > supported. Fields lists the ones that decided it.
func featureVerdict(feature string, profile capability.Profile, seen func(capability.Field) bool) capabilityFeature {
	rank := func(s capability.FeatureState) int {
		switch s {
		case capability.Unsupported:
			return 3
		case capability.Inactive:
			return 2
		case capability.Degraded:
			return 1
		}
		return 0
	}
	v := capabilityFeature{State: capability.Supported}
	for _, f := range capability.Features[feature] {
		var s capability.FeatureState
		switch capability.EffectiveState(profile.Spec(f), seen(f)) {
		case capability.FieldUnsupported:
			s = capability.Unsupported
		case capability.FieldInactive:
			s = capability.Inactive
		case capability.FieldPartial, capability.FieldConfigDependent:
			s = capability.Degraded
		default:
			continue
		}
		switch {
		case rank(s) > rank(v.State):
			v.State = s
			v.Fields = append(v.Fields[:0], f)
		case s == v.State:
			v.Fields = append(v.Fields, f)
		}
	}
	return v
}

// deviceVendorName is the device's vendor as the profiles and the ingest
// spell it (lower-cased; empty is GenericVendor, the same fallback as
// deviceVendor).
func deviceVendorName(d *models.Device) string {
	if v := strings.ToLower(strings.TrimSpace(d.Vendor)); v != "" {
		return v
	}
	return GenericVendor
}
