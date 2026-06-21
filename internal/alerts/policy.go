package alerts

import (
	"log"
	"strings"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"
)

// ResolvedAlertConfig is the computed configuration for a specific (device, alertType) pair.
// It is not persisted — it is resolved on-the-fly from the inheritance chain.
type ResolvedAlertConfig struct {
	PolicyID          *uint
	AlertEnabled      bool
	Threshold         float64
	Severity          string
	CooldownMinutes   int
	NotifyEmail       bool
	NotifySlack       bool
	NotifyDiscord     bool
	NotifyWebhook     bool
	EmailRecipients   string
	SlackURL          string
	DiscordURL        string
	WebhookURL        string
	InMaintenance     bool
	EscalationEnabled bool
	EscalationMinutes int
	EscalationRepeat  int
}

// PolicyCache holds in-memory copies of all policy-related data.
// Refreshed once per poll cycle alongside threshold refresh.
type PolicyCache struct {
	policies      []models.AlertPolicy
	policyByID    map[uint]*models.AlertPolicy
	deviceConfigs map[uint]*models.DeviceAlertConfig
	siteConfigs   map[uint]*models.SiteAlertConfig
	windows       []models.MaintenanceWindow
	defaultPolicy *models.AlertPolicy
	loaded        bool
}

// RefreshPolicyCache reloads all policy data from the database.
func (am *AlertManager) RefreshPolicyCache(db *database.Database) {
	if db == nil {
		return
	}

	policies, err := db.GetAlertPolicies()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load policies: %v", err)
		return
	}

	deviceConfigs, err := db.GetAllDeviceAlertConfigs()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load device configs: %v", err)
		return
	}

	siteConfigs, err := db.GetAllSiteAlertConfigs()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load site configs: %v", err)
		return
	}

	windows, err := db.GetActiveMaintenanceWindows()
	if err != nil {
		log.Printf("RefreshPolicyCache: failed to load maintenance windows: %v", err)
		return
	}

	cache := PolicyCache{
		policies:      policies,
		policyByID:    make(map[uint]*models.AlertPolicy, len(policies)),
		deviceConfigs: make(map[uint]*models.DeviceAlertConfig, len(deviceConfigs)),
		siteConfigs:   make(map[uint]*models.SiteAlertConfig, len(siteConfigs)),
		windows:       windows,
		loaded:        true,
	}

	for i := range policies {
		cache.policyByID[policies[i].ID] = &policies[i]
		if policies[i].IsDefault {
			cache.defaultPolicy = &policies[i]
		}
	}
	for i := range deviceConfigs {
		cache.deviceConfigs[deviceConfigs[i].DeviceID] = &deviceConfigs[i]
	}
	for i := range siteConfigs {
		cache.siteConfigs[siteConfigs[i].SiteID] = &siteConfigs[i]
	}

	am.mu.Lock()
	am.policyCache = cache
	am.mu.Unlock()
}

// resolveAlertConfig computes the effective alert configuration for a given device and alert type.
// Resolution order: Device Override → Site Override → Policy AlertRule → Policy defaults → Global defaults
func (am *AlertManager) resolveAlertConfig(deviceID uint, siteID *uint, alertType string) ResolvedAlertConfig {
	resolved := ResolvedAlertConfig{
		AlertEnabled:    true,
		CooldownMinutes: 5,
		Severity:        defaultSeverityForType(alertType),
	}

	if !am.policyCache.loaded {
		// Fallback to global config when cache not loaded
		resolved.Threshold = am.globalThresholdForType(alertType)
		return resolved
	}

	devCfg := am.policyCache.deviceConfigs[deviceID]

	// Check device alerts enabled
	if devCfg != nil && !devCfg.AlertsEnabled {
		resolved.AlertEnabled = false
		return resolved
	}

	// Resolve policy: device → site → default
	var policy *models.AlertPolicy
	if devCfg != nil && devCfg.PolicyID != nil {
		policy = am.findPolicy(*devCfg.PolicyID)
	}
	if policy == nil && siteID != nil {
		if siteCfg := am.policyCache.siteConfigs[*siteID]; siteCfg != nil && siteCfg.PolicyID != nil {
			policy = am.findPolicy(*siteCfg.PolicyID)
		}
	}
	if policy == nil {
		policy = am.policyCache.defaultPolicy
	}

	if policy != nil {
		resolved.PolicyID = &policy.ID
		resolved.NotifyEmail = policy.NotifyEmail
		resolved.NotifySlack = policy.NotifySlack
		resolved.NotifyDiscord = policy.NotifyDiscord
		resolved.NotifyWebhook = policy.NotifyWebhook
		resolved.EmailRecipients = policy.EmailRecipients
		resolved.SlackURL = policy.SlackWebhookURL
		resolved.DiscordURL = policy.DiscordWebhookURL
		resolved.WebhookURL = policy.WebhookURL
		resolved.CooldownMinutes = policy.CooldownMinutes
		resolved.EscalationEnabled = policy.EscalationEnabled
		resolved.EscalationMinutes = policy.EscalationMinutes
		resolved.EscalationRepeat = policy.EscalationRepeat
	}

	// Find matching AlertRule
	var rule *models.AlertRule
	if policy != nil {
		for i := range policy.Rules {
			if policy.Rules[i].AlertType == alertType {
				rule = &policy.Rules[i]
				break
			}
		}
	}

	if rule != nil {
		if !rule.Enabled {
			resolved.AlertEnabled = false
			return resolved
		}
		if rule.Severity != "" {
			resolved.Severity = rule.Severity
		}
		if rule.Threshold > 0 {
			resolved.Threshold = rule.Threshold
		}
		if rule.CooldownMinutes != nil {
			resolved.CooldownMinutes = *rule.CooldownMinutes
		}
		// Per-rule channel overrides (non-nil = override)
		if rule.NotifyEmail != nil {
			resolved.NotifyEmail = *rule.NotifyEmail
		}
		if rule.NotifySlack != nil {
			resolved.NotifySlack = *rule.NotifySlack
		}
		if rule.NotifyDiscord != nil {
			resolved.NotifyDiscord = *rule.NotifyDiscord
		}
		if rule.NotifyWebhook != nil {
			resolved.NotifyWebhook = *rule.NotifyWebhook
		}
	}

	// Site-level threshold/cooldown overrides
	if siteID != nil {
		if siteCfg := am.policyCache.siteConfigs[*siteID]; siteCfg != nil {
			resolved.Threshold = overrideThreshold(resolved.Threshold, alertType,
				siteCfg.CPUThreshold, siteCfg.MemoryThreshold, siteCfg.DiskThreshold, siteCfg.SessionThreshold)
			if siteCfg.CooldownMinutes > 0 {
				resolved.CooldownMinutes = siteCfg.CooldownMinutes
			}
		}
	}

	// Device-level threshold/cooldown overrides (most specific wins)
	if devCfg != nil {
		resolved.Threshold = overrideThreshold(resolved.Threshold, alertType,
			devCfg.CPUThreshold, devCfg.MemoryThreshold, devCfg.DiskThreshold, devCfg.SessionThreshold)
		if devCfg.CooldownMinutes > 0 {
			resolved.CooldownMinutes = devCfg.CooldownMinutes
		}
	}

	// If threshold is still 0, fall back to global
	if resolved.Threshold == 0 {
		resolved.Threshold = am.globalThresholdForType(alertType)
	}

	// Check maintenance windows
	now := time.Now()
	for _, w := range am.policyCache.windows {
		if now.Before(w.StartTime) || now.After(w.EndTime) {
			continue
		}
		// Check scope
		if w.DeviceID != nil && *w.DeviceID != deviceID {
			continue
		}
		if w.SiteID != nil && (siteID == nil || *w.SiteID != *siteID) {
			continue
		}
		// Check alert type filter
		if !w.SuppressAll && w.AlertTypes != "" {
			types := strings.Split(w.AlertTypes, ",")
			found := false
			for _, t := range types {
				if strings.TrimSpace(t) == alertType {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		resolved.InMaintenance = true
		break
	}

	return resolved
}

func (am *AlertManager) findPolicy(id uint) *models.AlertPolicy {
	return am.policyCache.policyByID[id]
}

func (am *AlertManager) globalThresholdForType(alertType string) float64 {
	switch alertType {
	case "CPU_HIGH":
		return am.config.Alerts.CPUThreshold
	case "MEMORY_HIGH":
		return am.config.Alerts.MemoryThreshold
	case "DISK_HIGH":
		return am.config.Alerts.DiskThreshold
	case "SESSIONS_HIGH":
		return float64(am.config.Alerts.SessionThreshold)
	default:
		return 0
	}
}

func defaultSeverityForType(alertType string) string {
	switch alertType {
	case "DISK_HIGH", "INTERFACE_DOWN", "VPN_TUNNEL_DOWN", "DEVICE_OFFLINE",
		"SYSLOG_EMERGENCY", "SYSLOG_CRITICAL", "SSH_HOST_KEY_CHANGED":
		return "critical"
	case "SYSLOG_ALERT":
		return "warning"
	default:
		return "warning"
	}
}

// overrideThreshold returns the override threshold for the given alert type if > 0.
// Works for both device and site configs by accepting raw field values.
func overrideThreshold(current float64, alertType string, cpu, mem, disk float64, sess int) float64 {
	switch alertType {
	case "CPU_HIGH":
		if cpu > 0 {
			return cpu
		}
	case "MEMORY_HIGH":
		if mem > 0 {
			return mem
		}
	case "DISK_HIGH":
		if disk > 0 {
			return disk
		}
	case "SESSIONS_HIGH":
		if sess > 0 {
			return float64(sess)
		}
	}
	return current
}

// BuildNotifyConfigFromResolved creates a NotifyConfig for use with the notifier.
// It merges resolved policy config with global notification settings as fallbacks.
func BuildNotifyConfigFromResolved(resolved ResolvedAlertConfig, globalNC notifier.NotifyConfig) notifier.NotifyConfig {
	nc := notifier.NotifyConfig{
		PolicyActive:  resolved.PolicyID != nil,
		EnableEmail:   resolved.NotifyEmail,
		EnableSlack:   resolved.NotifySlack,
		EnableDiscord: resolved.NotifyDiscord,
		EnableWebhook: resolved.NotifyWebhook,
		// SMTP settings always come from global
		EmailEnabled: globalNC.EmailEnabled,
		SMTPHost:     globalNC.SMTPHost,
		SMTPPort:     globalNC.SMTPPort,
		SMTPUsername: globalNC.SMTPUsername,
		SMTPPassword: globalNC.SMTPPassword,
		SMTPFrom:     globalNC.SMTPFrom,
	}

	// Recipients: policy override or global
	if resolved.EmailRecipients != "" {
		nc.SMTPTo = resolved.EmailRecipients
	} else {
		nc.SMTPTo = globalNC.SMTPTo
	}

	// Webhook URLs: policy override or global
	if resolved.SlackURL != "" {
		nc.SlackWebhookURL = resolved.SlackURL
	} else {
		nc.SlackWebhookURL = globalNC.SlackWebhookURL
	}
	if resolved.DiscordURL != "" {
		nc.DiscordWebhookURL = resolved.DiscordURL
	} else {
		nc.DiscordWebhookURL = globalNC.DiscordWebhookURL
	}
	if resolved.WebhookURL != "" {
		nc.WebHookURL = resolved.WebhookURL
	} else {
		nc.WebHookURL = globalNC.WebHookURL
	}

	return nc
}
