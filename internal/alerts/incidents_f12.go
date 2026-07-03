package alerts

import (
	"fmt"
	"log"
	"time"

	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// F12 incident grouping: a device outage becomes ONE story. When
// DEVICE_OFFLINE fires, an incident opens for the device; every state alert
// fired for it while the incident is open attaches (Alert.IncidentID) and its
// individual notification is muted; the device's recovery closes the incident
// and sends a single summary. Kills the "switch reboot = 8 emails" storm.
//
// The open-incident set is cached in-memory (openIncidents, guarded by am.mu)
// and reloaded from the DB each poll cycle in RefreshThresholds, so a poller
// restart keeps attaching to incidents opened before it.

// incidentFor returns the open incident ID for a device (0 = none).
func (am *AlertManager) incidentFor(deviceID uint) uint {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.openIncidents[deviceID]
}

// refreshOpenIncidents reloads the open-incident cache (called from
// RefreshThresholds once per poll cycle, outside am.mu DB-wise).
func (am *AlertManager) refreshOpenIncidents() {
	if am.db == nil {
		return
	}
	incs, err := am.db.GetOpenIncidents()
	if err != nil {
		log.Printf("refreshOpenIncidents: %v", err)
		return
	}
	m := make(map[uint]uint, len(incs))
	for i := range incs {
		m[incs[i].DeviceID] = incs[i].ID
	}
	am.mu.Lock()
	am.openIncidents = m
	am.mu.Unlock()
}

// openIncident opens (or reuses) the device's incident and caches it.
func (am *AlertManager) openIncident(device *models.Device, severity models.Severity) *models.Incident {
	if am.db == nil {
		return nil
	}
	inc := models.Incident{
		DeviceID:  device.ID,
		StartedAt: time.Now(),
		Severity:  severity,
		Title:     fmt.Sprintf("Device %s (%s) offline", device.Name, device.IPAddress),
	}
	if err := am.db.CreateIncident(&inc); err != nil {
		log.Printf("openIncident device %d: %v", device.ID, err)
		return nil
	}
	am.mu.Lock()
	am.openIncidents[device.ID] = inc.ID
	am.mu.Unlock()
	return &inc
}

// closeIncident resolves the device's open incident and sends ONE summary
// notification through the device's policy channels.
func (am *AlertManager) closeIncident(device *models.Device) {
	if am.db == nil {
		return
	}
	am.mu.Lock()
	_, hadOpen := am.openIncidents[device.ID]
	delete(am.openIncidents, device.ID)
	globalNC := notifier.SnapshotConfig(&am.config.Alerts)
	resolved := am.resolveAlertConfig(device.ID, device.SiteID, "DEVICE_OFFLINE")
	am.mu.Unlock()

	inc, err := am.db.ResolveIncident(device.ID)
	if err != nil {
		log.Printf("closeIncident device %d: %v", device.ID, err)
		return
	}
	if inc == nil || !hadOpen {
		// Nothing open, or opened by a previous process and never seen here —
		// resolve silently (mirrors the cold-resolve contract of sendRecovery).
		return
	}

	dur := time.Since(inc.StartedAt).Round(time.Minute)
	now := time.Now()
	summary := models.Alert{
		Timestamp:      now,
		DeviceID:       device.ID,
		AlertType:      "INCIDENT_RESOLVED",
		Severity:       "info",
		Message:        fmt.Sprintf("Incident resolved: %s — %d alert(s) over %s", inc.Title, inc.AlertCount, dur),
		MetricName:     "incident",
		IncidentID:     &inc.ID,
		Acknowledged:   true,
		AcknowledgedAt: &now,
		ResolvedAt:     &now,
	}
	am.saveAlert(&summary)
	nc := BuildNotifyConfigFromResolved(resolved, globalNC)
	if err := am.notifier.SendAlert(&summary, nc); err != nil {
		log.Printf("closeIncident: summary notification failed: %v", err)
	}
}
