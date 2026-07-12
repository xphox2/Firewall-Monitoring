package database

import (
	"context"

	"gorm.io/gorm"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"

	"time"
)

// Store is the repository interface the API handlers depend on instead of the
// concrete *Database god-object. It is satisfied for free by *Database — every
// method below already exists on it — so this is pure interface extraction: no
// query, ORM, or behaviour change. GORM remains the persistence layer; the
// Gorm() escape hatch below hands handlers the raw *gorm.DB exactly as before.
//
// The value is decoupling and testability: a handler can be constructed with a
// fake Store and unit-tested without a live database. Store is composed from
// narrow per-domain interfaces (DeviceStore, AlertStore, …) so a focused test
// or future caller can depend on just the slice it needs.
//
// Methods that mutate the data layer's wiring (migrations, partition setup,
// batchers, key chain) are deliberately NOT here — those stay on the concrete
// *Database used by the daemons (poller/trap-receiver), which never went
// through this interface.
type Store interface {
	DeviceStore
	ProbeStore
	SiteStore
	ConnectionStore
	AlertStore
	AlertPolicyStore
	MaintenanceWindowStore
	TelemetryReadStore
	ChartStore
	EventStatsStore
	IngestStore
	AuthStore
	UserStore
	TokenStore
	TOTPStore
	IncidentStore
	AuditStore
	SecretStore
	MaintenanceOpsStore

	// Gorm exposes the raw *gorm.DB for handlers that build ad-hoc queries
	// (partial updates, one-off lookups). Unchanged escape hatch.
	Gorm() *gorm.DB

	// WithContextStore returns a request-scoped Store bound to ctx (AUDIT-032/079):
	// a client disconnect cancels in-flight queries. Mirrors WithContext, but
	// typed as Store so the handler layer stays on the interface.
	WithContextStore(ctx context.Context) Store
}

// Compile-time proof that the concrete database satisfies the interface.
var _ Store = (*Database)(nil)

// WithContextStore adapts the existing WithContext to the Store interface so the
// request-scoping plumbing in the handler layer never touches the concrete type.
func (d *Database) WithContextStore(ctx context.Context) Store {
	return d.WithContext(ctx)
}

// DeviceStore covers device CRUD and probe-scoped device lookups.
type DeviceStore interface {
	CreateDevice(device *models.Device) error
	DeleteDevice(id uint) error
	GetDevice(id uint) (*models.Device, error)
	GetAllDevices() ([]models.Device, error)
	GetDeviceIDsByProbe(probeID uint) ([]uint, error)
	GetDevicesByProbe(probeID uint) ([]models.Device, error)
	GetDeviceStatuses() ([]map[string]interface{}, error)
	ResolveDevicesByIPs(ips []string) map[string]uint
}

// ProbeStore covers probe registration lifecycle and the relay schema-v4
// server→collector command channel (probe_commands.go).
type ProbeStore interface {
	ApproveProbe(probeID uint, approvedBy uint) error
	CreateProbe(probe *models.Probe) error
	DecommissionProbe(id uint) error
	DeleteProbe(id uint) error
	GetProbe(id uint) (*models.Probe, error)
	GetProbeByName(name string) (*models.Probe, error)
	GetAllProbes() ([]models.Probe, error)
	RecommissionProbe(id uint) error
	RejectProbe(probeID uint, reason string) error
	EnqueueProbeCommand(cmd *models.ProbeCommand) error
	ClaimProbeCommands(probeID uint) ([]models.ProbeCommand, error)
	CompleteProbeCommand(probeID uint, commandID, status, result string) (bool, error)
	GetProbeCommands(probeID uint, limit int) ([]models.ProbeCommand, error)
	ExpireStaleProbeCommands() (int64, error)
	CancelProbeCommand(probeID uint, commandID string) (bool, error)
}

// SiteStore covers site CRUD.
type SiteStore interface {
	CreateSite(site *models.Site) error
	DeleteSite(id uint) error
	GetSite(id uint) (*models.Site, error)
	GetAllSites() ([]models.Site, error)
	GetSiteByName(name string) (*models.Site, error)
}

// ConnectionStore covers the network-analyzer connection map and its details.
type ConnectionStore interface {
	CreateConnection(conn *models.DeviceConnection) error
	GetAllConnections() ([]models.DeviceConnection, error)
	GetConnectionDetail(connID uint) (*ConnectionDetailResult, error)
	GetConnectionEvents(srcDeviceID, dstDeviceID uint, hours int) ([]ConnectionEvent, error)
	GetConnectionFlowStats(connID uint, hours int) (*ConnectionFlowResult, error)
	GetConnectionStatuses() ([]map[string]interface{}, error)
	GetConnectionTraffic(connID uint, rangeStr string) ([]VPNChartBucket, error)
}

// AlertStore covers alert acknowledgement, snooze, and notes.
type AlertStore interface {
	AcknowledgeAlertEnhanced(id uint, notes string) error
	AcknowledgeAlertsBulk(ids []uint, notes string) (int64, error)
	AcknowledgeAlertsByFilter(f AlertFilter, notes string) (int64, error)
	GetAlerts(limit int, acknowledged *bool) ([]models.Alert, error)
	UpdateAlertNotes(id uint, notes string) error
	SnoozeAlert(id uint, until time.Time, by, reason string) error
	SnoozeAlertsBulk(ids []uint, until time.Time, by, reason string) (int64, error)
	SnoozeAlertsByFilter(f AlertFilter, until time.Time, by, reason string) (int64, error)
	UnsnoozeAlert(id uint) error
}

// AlertPolicyStore covers alert policies, rules, and per-device/site overrides.
type AlertPolicyStore interface {
	CreateAlertPolicy(policy *models.AlertPolicy) error
	DeleteAlertPolicy(id uint) error
	GetAlertPolicies() ([]models.AlertPolicy, error)
	GetAlertPolicy(id uint) (*models.AlertPolicy, error)
	UpdateAlertPolicy(policy *models.AlertPolicy) error
	BatchUpsertAlertRules(policyID uint, rules []models.AlertRule) error
	GetDeviceAlertConfig(deviceID uint) (*models.DeviceAlertConfig, error)
	UpsertDeviceAlertConfig(cfg *models.DeviceAlertConfig) error
	DeleteDeviceAlertConfig(deviceID uint) error
	GetSiteAlertConfig(siteID uint) (*models.SiteAlertConfig, error)
	UpsertSiteAlertConfig(cfg *models.SiteAlertConfig) error
	DeleteSiteAlertConfig(siteID uint) error
	// Event rules (v35): unified vendor-aware alert/suppress rule engine.
	ListEventRules() ([]models.EventRule, error)
	GetEventRule(id uint) (*models.EventRule, error)
	CreateEventRule(r *models.EventRule) error
	UpdateEventRule(r *models.EventRule) error
	DeleteEventRule(id uint) error
	RecentSyslogForTest(limit int) ([]models.SyslogMessage, error)
}

// MaintenanceWindowStore covers scheduled maintenance windows.
type MaintenanceWindowStore interface {
	CreateMaintenanceWindow(w *models.MaintenanceWindow) error
	DeleteMaintenanceWindow(id uint) error
	GetActiveMaintenanceWindows() ([]models.MaintenanceWindow, error)
	GetMaintenanceWindows() ([]models.MaintenanceWindow, error)
	UpdateMaintenanceWindow(w *models.MaintenanceWindow) error
}

// TelemetryReadStore covers the latest/history telemetry reads used by the
// dashboard, device detail, and analytics pages.
type TelemetryReadStore interface {
	GetLatestHAStatus(deviceID uint) ([]models.HAStatus, error)
	GetLatestInterfaceAddresses() ([]models.InterfaceAddress, error)
	GetLatestInterfaceStats() ([]models.InterfaceStats, error)
	GetLatestProcessorStats(deviceID uint) ([]models.ProcessorStats, error)
	GetLatestSDWANHealth(deviceID uint) ([]models.SDWANHealth, error)
	GetLatestSecurityStats(deviceID uint) (*models.SecurityStats, error)
	GetLatestSystemStatus() (*models.SystemStatus, error)
	GetLatestVPNStatuses(deviceID uint) ([]models.VPNStatus, error)
	GetAllLatestVPNStatuses() ([]models.VPNStatus, error)
	InterfaceEverUp(deviceID uint, name string, since time.Time) (bool, error)
	VPNEverUp(deviceID uint, tunnelName string, since time.Time) (bool, error)
	GetSystemStatusHistory(deviceID uint, hours int) ([]models.SystemStatus, error)
	GetSystemStatusBuckets(deviceID uint, rangeStr string) ([]SystemStatusBucket, error)
	GetSecurityStatsHistory(deviceID uint, hours int) ([]models.SecurityStats, error)
	GetPingResultHistory(deviceID uint, hours int) ([]models.PingResult, error)
	GetPingStatsByTarget(deviceID uint, targetIP string) (*models.PingStats, error)
	GetLatestInterfaceCountersByDevice(deviceID uint) ([]models.FlowInterfaceCounter, error)
	GetUptimeRecords(limit int) ([]models.UptimeRecord, error)
	RecentHAFailover(deviceID uint, window time.Duration) bool
	GetTelemetryTotals() (*TelemetryTotals, error)
}

// ChartStore covers the adaptive-bucket chart windows and dashboard series.
type ChartStore interface {
	GetInterfaceChartWindow(deviceID uint, ifIndex int, from, to time.Time) ([]InterfaceChartBucket, error)
	GetFlowInterfaceChartWindow(deviceID uint, ifIndex int, from, to time.Time) ([]InterfaceChartBucket, error)
	GetVPNChartWindow(deviceID uint, tunnelName string, from, to time.Time) ([]VPNChartBucket, error)
	GetDashboardTimeSeries(hours int) (*DashboardTimeSeries, error)
}

// EventStatsStore covers the alert/syslog/trap/flow statistics aggregates.
type EventStatsStore interface {
	GetAlertStats(hours int, deviceID uint) (*EventStatsResult, error)
	GetSyslogStats(hours int, deviceID uint) (*EventStatsResult, error)
	GetTrapStats(hours int, deviceID uint) (*EventStatsResult, error)
	GetFlowStats(hours int, filter FlowStatsFilter) (*FlowStatsResult, error)
	// GetMixedFlowSourceDevices lists devices double-reporting flows via more
	// than one protocol in the last hour (dual-export warning banner, v29).
	GetMixedFlowSourceDevices() []string
	GetRecentDetections(since time.Time, limit int, unackedOnly, includeAlerted bool) ([]models.FlowDetection, error)
	GetDetectionsByAlert(alertID uint) ([]models.FlowDetection, error)
	AckFlowDetection(id uint) error
	AckFlowDetections(ids []uint) error
	// Flow-source suppression (silence-a-source, v0.11.46).
	SuppressFlowSource(src string, until time.Time, by, reason string) error
	IsFlowSourceSuppressed(src string, ref time.Time) (bool, error)
	ListActiveFlowSuppressions() ([]models.FlowSourceSuppression, error)
	DeleteFlowSuppression(id uint) error
	// UI-managed settings read-through (v0.11.46 — no new env vars).
	GetBoolSetting(key string, def bool) bool
	GetIntSetting(key string, def int) int
	GetNOCSnapshot(window time.Duration) (*NOCSnapshot, error)
	GetNOCSnapshotFiltered(window time.Duration, filter NOCFilter) (*NOCSnapshot, error)
	GetDeviceAlertSeverities() (map[uint]string, error)
	GetActiveThreatIntel() ([]models.ThreatIntel, error)
	ListThreatIntel(limit int) ([]models.ThreatIntel, error)
	SearchThreatIntel(f ThreatIntelFilter, offset, limit int) ([]models.ThreatIntel, int64, error)
	CountActiveThreatIntel() (int64, error)
	CountThreatIntelBySource() ([]ThreatIntelSourceCount, error)
	UpsertThreatIntel(e *models.ThreatIntel) error
	DeleteThreatIntel(id uint) error
	DeleteThreatIntelBySource(source string) (int64, error)
	ListThreatFeedStatus() ([]models.ThreatFeedStatus, error)
	UpsertThreatFeedStatus(s *models.ThreatFeedStatus) error
	SetThreatFeedEnabled(source string, enabled bool) error
}

// IngestStore covers the probe-ingestion write path and batch idempotency.
type IngestStore interface {
	SaveFlowSamples(samples []models.FlowSample) error
	// SaveAgentDrops persists one per-window sFlow sample-pool drops delta
	// (M2 of the 2026-07-01 audit: previously this had no production caller,
	// so the sampling_backoff detector read a table nothing wrote).
	SaveAgentDrops(agentAddress string, samplingRate uint32, windowStart time.Time, dropsCount uint64) error
	SaveFlowInterfaceCounters(counters []models.FlowInterfaceCounter) error
	SaveHAStatuses(statuses []models.HAStatus) error
	SaveInterfaceAddresses(addrs []models.InterfaceAddress) error
	SaveInterfaceStats(stats []models.InterfaceStats) error
	SaveLicenseInfo(licenses []models.LicenseInfo) error
	SavePingResults(results []models.PingResult) error
	SavePingStats(stats *models.PingStats) error
	FoldPingStats(deviceID, probeID uint, targetIP string, minL, maxL, sum float64, count int, packetLoss float64, now time.Time) error
	SaveProcessorStats(stats []models.ProcessorStats) error
	SaveDiskUsage(rows []models.DiskUsage) error
	SaveLoadAverage(rows []models.LoadAverage) error
	SaveSDWANHealth(health []models.SDWANHealth) error
	SaveSecurityStats(stats []models.SecurityStats) error
	SaveSyslogMessages(msgs []models.SyslogMessage) error
	SaveSystemStatuses(statuses []models.SystemStatus) error
	SaveTrapEvents(traps []models.TrapEvent) error
	SaveVPNStatuses(statuses []models.VPNStatus) error
	MarkBatchProcessed(probeID uint, batchID string) error
	BatchAlreadyProcessed(probeID uint, batchID string) bool
}

// AuthStore covers admin credential reads/writes used by the auth handlers.
type AuthStore interface {
	GetAdminByUsername(username string) (*auth.AdminAuth, error)
	UpdateAdminPassword(id uint, password string) error
	IncrementAdminTokenVersion(id uint) error
	SetAdminMustChangePassword(id uint, must bool) error
	GetAdminMustChangePassword(id uint) (bool, error)
	SaveLoginAttempt(attempt *models.LoginAttempt) error
}

// UserStore covers multi-user management (RBAC, P0-1). The rows live in the
// historical `admins` table; "user" is the API/UI-facing name.
type UserStore interface {
	ListAdmins() ([]models.Admin, error)
	GetAdminByID(id uint) (*models.Admin, error)
	CreateAdmin(admin *models.Admin) error
	UpdateAdminRole(id uint, role string) error
	SetAdminDisabled(id uint, disabled bool) error
	DeleteAdmin(id uint) error
	// CountOtherEnabledAdmins counts enabled role-admin accounts EXCLUDING the
	// given id — the last-admin guard (must stay ≥1 before demote/disable/delete).
	CountOtherEnabledAdmins(excludeID uint) (int64, error)
	// UpdateAdminProfile writes only the self-service email/full_name columns
	// (v28) — never role/password.
	UpdateAdminProfile(id uint, email, fullName string) error
	// SetAdminMFAPromptDismissed records the explicit MFA-wizard decline;
	// idempotent, first timestamp wins.
	SetAdminMFAPromptDismissed(id uint) error
	// GetAdminDashboardPrefs / SetAdminDashboardPrefs persist the self-service
	// system-health dashboard layout JSON for one account.
	GetAdminDashboardPrefs(id uint) (string, error)
	SetAdminDashboardPrefs(id uint, prefs string) error
}

// TOTPStore covers two-factor enrollment state (P0-3). Secrets arrive already
// encrypted (EncryptField); recovery-code params are sha256: hashes.
type TOTPStore interface {
	SetAdminTOTP(id uint, encSecret string, enabled bool) error
	ClearAdminTOTP(id uint) error
	ReplaceRecoveryCodes(adminID uint, hashes []string) error
	ConsumeRecoveryCode(adminID uint, codeHash string) (bool, error)
}

// IncidentStore covers F12 incident grouping (read side for the API; the
// poller's correlator uses the concrete type).
type IncidentStore interface {
	ListIncidents(limit, offset int) ([]models.Incident, int64, error)
	GetIncidentAlerts(incidentID uint) ([]models.Alert, error)
}

// TokenStore covers scoped API-token management (P0-2). Resolution for the
// auth middleware is LookupAPIToken (plaintext in, row out — hashing stays in
// the database package).
type TokenStore interface {
	LookupAPIToken(plaintext string) (*models.ApiToken, error)
	CreateAPIToken(tok *models.ApiToken) error
	ListAPITokens() ([]models.ApiToken, error)
	RevokeAPIToken(id uint) error
	TouchAPITokenLastUsed(id uint, t time.Time) error
}

// AuditStore covers the admin-action audit trail.
type AuditStore interface {
	GetAuditLogs(actor, action string, since time.Time, limit, offset int) ([]models.AuditLog, int64, error)
	SaveAuditLog(entry *models.AuditLog) error
}

// SecretStore covers the field-level encrypt/decrypt helpers handlers use when
// echoing or storing device/IRC credentials.
type SecretStore interface {
	EncryptField(plaintext string) string
	DecryptField(ciphertext string) string
	EncryptIRCChannelSecrets(ch *models.IRCChannel)
	DecryptIRCChannelSecrets(ch *models.IRCChannel)
	EncryptIRCServerSecrets(s *models.IRCServer)
	DecryptIRCServerSecrets(s *models.IRCServer)
}

// MaintenanceOpsStore covers the admin-triggered maintenance operations exposed
// through the settings/health endpoints.
type MaintenanceOpsStore interface {
	CleanupConfigRevisions() error
	CollapseLegacyConfigRevisionDuplicates() (int64, error)
	EnsurePartitions() error
	EncryptionVerified() (bool, string)
}
