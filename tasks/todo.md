# SSH-Based FortiGate Monitoring Feature Plan

## Overview
Enable the Firewall-Collector probe to SSH into FortiGate firewalls using a read-only admin account and:
1. Periodically fetch configuration and detect changes (with alerts)
2. Poll detailed diagnostic data for historical storage and charts

## User Requirements
- Probe connects to FortiGate IP via SSH (port 22 default, configurable)
- Read-only SSH admin only (no write/backup commands)
- Username/password auth (passwords encrypted at rest, decrypted by API server)
- Config polling: 15 min default (user configurable), store last 5 revisions
- Process & interface error polling: 5 min default (user configurable)
- Alerts on config change (customizable like other alerts)
- Historical data stored for charts

---

## Architecture Overview

```
FortiGate (SSH) ── Probe ── RelayClient ── API Server ── Database
                                                    │
                                                    ▼
                                              Web UI (charts/alerts)
```

**Data Flow:**
1. Probe fetches assigned devices via `FetchDevices()` (every 5 min) - includes SSH credentials (encrypted in DB)
2. Probe SSHs to each FortiGate, executes diagnostic commands
3. Probe sends data to API via `RelayClient.Send*()` methods
4. API stores data, generates alerts if configured
5. Web UI displays charts, alerts, config history

---

## 1. Database Schema Changes

### 1a. Device Model - Add SSH Fields
**File:** `internal/models/models.go`

```go
type Device struct {
    // ... existing fields ...

    // SSH credentials (NEW)
    SSHUsername    string `json:"ssh_username"`
    SSHPassword    string `json:"ssh_password"`   // AES-256-GCM encrypted
    SSHPort        int    `json:"ssh_port"`        // default 22
    SSHPollEnabled bool   `json:"ssh_poll_enabled"` // default false
    SSHPollInterval int   `json:"ssh_poll_interval"` // seconds, default 900 (15 min)
}
```

### 1b. ProcessStats Model
**File:** `internal/models/models.go`

Stores output of `diagnose sys top` for historical process-level CPU/memory monitoring.

```go
type ProcessStats struct {
    ID         uint      `json:"id" gorm:"primaryKey"`
    Timestamp  time.Time `json:"timestamp" gorm:"index:idx_procstats_device_ts,priority:2"`
    DeviceID   uint      `json:"device_id" gorm:"index;index:idx_procstats_device_ts,priority:1"`
    Processes  []ProcessInfo `json:"processes" gorm:"serializer:json"`
}

type ProcessInfo struct {
    Name      string  `json:"name"`
    PID       int     `json:"pid"`
    CPU       float64 `json:"cpu"`   // percentage
    Memory    float64 `json:"mem"`  // percentage
    Command   string  `json:"command"`
}
```

### 1c. InterfaceErrors Model
**File:** `internal/models/models.go`

Stores output of `diagnose netlink interface list` for detailed per-interface error tracking.

```go
type InterfaceErrors struct {
    ID          uint      `json:"id" gorm:"primaryKey"`
    Timestamp   time.Time `json:"timestamp" gorm:"index:idx_ifaceerr_device_ts,priority:2"`
    DeviceID    uint      `json:"device_id" gorm:"index;index:idx_ifaceerr_device_ts,priority:1"`
    Interface   string    `json:"interface"` // interface name
    InErrors    uint64    `json:"in_errors"`
    InDiscards  uint64    `json:"in_discards"`
    OutErrors   uint64    `json:"out_errors"`
    OutDiscards uint64    `json:"out_discards"`
}
```

### 1d. DeviceConfigRevision Model
**File:** `internal/models/models.go`

Stores configuration snapshots (last 5 per device).

```go
type DeviceConfigRevision struct {
    ID         uint      `json:"id" gorm:"primaryKey"`
    DeviceID   uint      `json:"device_id" gorm:"not null;index"`
    Timestamp  time.Time `json:"timestamp" gorm:"not null"`
    Checksum   string    `json:"checksum"`    // MD5 hash from FortiGate
    ConfigText string    `json:"config_text"`  // full config (plain text)
    Length     int       `json:"length"`       // config file size
    IsCurrent  bool      `json:"is_current"`  // latest revision
}
```

### 1e. DeviceAlertConfig - Add SSH Alert Types
**File:** `internal/models/models.go`

Existing alert config needs new type for SSH config changes.

```go
// Existing AlertRule has Type field - add:
// CONFIG_CHANGE = "config_change" - triggered when config checksum changes
// PROCESS_ANOMALY = "process_anomaly" - future: CPU spike on specific process
```

---

## 2. API Server Changes

### 2a. SSH Password Encryption
**File:** `internal/crypto/crypto.go` (NEW)

AES-256-GCM encryption/decryption utility:
- Master key from environment variable `ENCRYPTION_KEY` (32 bytes, hex-encoded)
- `EncryptPassword(plaintext string) (ciphertext string, err)`
- `DecryptPassword(ciphertext string) (plaintext string, err)`

### 2b. Update Device CRUD
**File:** `internal/api/handlers/handlers_devices.go`

- `POST /api/devices` / `PUT /api/devices/:id` - accept SSH fields, encrypt password before DB save
- `GET /api/devices/:id` - decrypt password when returning to probe (never return to UI)
- `POST /api/devices/:id/test-ssh` - probe tests SSH connection, returns success/failure

### 2c. Config History Endpoints
**File:** `internal/api/handlers/handlers_devices.go`

- `GET /api/devices/:id/config-history` - list config revisions with timestamps/checksums
- `GET /api/devices/:id/config-history/:revision-id/download` - download full config as file
- `GET /api/devices/:id/config-current` - get current running config

### 2d. ProcessStats Endpoint
**File:** `internal/api/handlers/handlers_devices.go`

- `GET /api/devices/:id/process-history` - time-series data for process charts
  - Query params: `?from=&to=&limit=`
- `GET /api/devices/:id/process-latest` - latest process snapshot

### 2e. InterfaceErrors Endpoint
**File:** `internal/api/handlers/handlers_devices.go`

- `GET /api/devices/:id/interface-errors` - time-series data for error charts
  - Query params: `?interface=port1&from=&to=`
- `GET /api/devices/:id/interface-errors-latest` - latest error snapshot per interface

### 2f. Alert Integration
**File:** `internal/alerts/alerts.go`

- When probe reports config checksum change, API creates `CONFIG_CHANGE` alert
- Alert type configurable in alert policies (like other alert types)
- `GetAlertType()` returns info about which alert types exist
- Alert message includes device name, old/new checksum, timestamp

---

## 3. Relay Layer Changes

### 3a. DeviceInfo - Add SSH Fields
**File:** `internal/relay/relay.go`

```go
type DeviceInfo struct {
    // ... existing fields ...
    SSHUsername     string `json:"ssh_username"`
    SSHPassword     string `json:"ssh_password"`     // already encrypted
    SSHPort         int    `json:"ssh_port"`
    SSHPollEnabled  bool   `json:"ssh_poll_enabled"`
    SSHPollInterval int    `json:"ssh_poll_interval"`
}
```

### 3b. New Relay Message Types
**File:** `internal/relay/relay.go`

```go
type ConfigRevision struct {
    ID         uint      `json:"id"`
    DeviceID   uint      `json:"device_id"`
    Timestamp  time.Time `json:"timestamp"`
    Checksum   string    `json:"checksum"`
    ConfigText string    `json:"config_text"`
    Length     int       `json:"length"`
}

type ProcessSnapshot struct {
    ID        uint         `json:"id"`
    DeviceID  uint         `json:"device_id"`
    Timestamp time.Time    `json:"timestamp"`
    Processes []ProcessInfo `json:"processes"`
}

type InterfaceErrorSnapshot struct {
    ID        uint   `json:"id"`
    DeviceID  uint   `json:"device_id"`
    Timestamp time.Time `json:"timestamp"`
    Errors    []InterfaceErrorInfo `json:"errors"`
}
```

### 3c. New Relay Send Methods
**File:** `internal/relay/relay.go`

```go
func (r *RelayClient) SendConfigRevision(rev *ConfigRevision) error
func (r *RelayClient) SendProcessSnapshot(snap *ProcessSnapshot) error
func (r *RelayClient) SendInterfaceErrorSnapshot(snap *InterfaceErrorSnapshot) error
```

### 3d. API Receive Endpoints
**File:** `internal/api/handlers/handlers_data.go`

- `POST /api/probes/:id/config-revision` - receive config snapshot
- `POST /api/probes/:id/process-snapshot` - receive process data
- `POST /api/probes/:id/interface-errors` - receive interface error data

---

## 4. Probe Changes

### 4a. SSH Client Library
**File:** `internal/ssh/client.go` (NEW)

```go
type SSHClient struct {
    Host     string
    Port     int
    Username string
    Password string
    client   *ssh.Client
    session  *ssh.Session
}

func NewSSHClient(host string, port int, username, password string) (*SSHClient, error)
func (c *SSHClient) Connect() error
func (c *SSHClient) Execute(command string) (string, error)
func (c *SSHClient) ExecuteMultiple(commands []string) ([]string, error)
func (c *SSHClient) Close()
```

**FortiOS SSH Nuances:**
- Shell prompt ends with `#` or `$`
- Need to handle `-----END CSR-----` and similar multi-line outputs
- Use `exec` subsystem or pseudo-terminal for commands
- Timeout: 30 seconds per command

### 4b. FortiGate Command Templates
**File:** `internal/ssh/fortigate.go` (NEW)

```go
var FortiGateCommands = struct {
    ShowConfig      string  // "show"
    ConfigChecksum  string  // "diagnose sys checksum conf"
    ProcessTop     string  // "diagnose sys top"
    SystemStatus   string  // "get system status"
    SystemPerf     string  // "get system performance status"
    InterfaceList  string  // "diagnose netlink interface list"
}{
    ShowConfig:     "show",
    ConfigChecksum: "diagnose sys checksum conf",
    ProcessTop:     "diagnose sys top",
    SystemStatus:   "get system status",
    SystemPerf:     "get system performance status",
    InterfaceList:  "diagnose netlink interface list",
}
```

### 4c. Probe Main Changes
**File:** `cmd/probe/main.go`

Add to `startSNMPPolling()` or new function `startSSHPolling()`:

```go
func (p *Probe) startSSHPolling() {
    // Fetch device list every 5 minutes
    // For each device with SSHPollEnabled=true:
    //   - SSH connect
    //   - Execute commands
    //   - Parse output
    //   - Send via RelayClient
    //   - Handle config change detection
    //   - Store last 5 configs
}
```

**Polling Logic:**
1. `diagnose sys checksum conf` → compare to last stored checksum
2. If changed, run `show` → store config + update checksum
3. `diagnose sys top` → parse and send ProcessSnapshot
4. `diagnose netlink interface list` → parse errors and send InterfaceErrorSnapshot

### 4d. Process Output Parser
**File:** `internal/ssh/parser.go` (NEW)

Parse `diagnose sys top` output into `[]ProcessInfo`:
```
NAME             PID   CPU   COMMAND
pyfcgi           1234  25%   python3
scanunit         5678  12%   ./scanunit
```

### 4e. Interface Error Parser
**File:** `internal/ssh/parser.go` (NEW)

Parse `diagnose netlink interface list` output for error counts per interface.

---

## 5. UI Changes

### 5a. Device Form Modal - SSH Fields
**Files:** `web/admin/admin.html`, `cmd/api/static/js/admin-main.js`

Add to device add/edit form:
- SSH Username (text input)
- SSH Password (password input)
- SSH Port (number, default 22)
- Enable SSH Polling (checkbox)
- SSH Poll Interval (number, default 900 seconds)

### 5b. Device Detail Page - New Tabs
**File:** `web/admin/admin.html`, `cmd/api/static/js/admin-main.js`

New tab sections:
- **Process Monitor** - chart of top processes by CPU%
- **Interface Errors** - chart of errors per interface over time
- **Config History** - list of stored configs with timestamps/checksums, download buttons

### 5c. Config History Component
**File:** `cmd/api/static/js/admin-main.js`

```javascript
function renderConfigHistory(configs) {
    // List configs with timestamp, checksum, length
    // Download button per revision
    // "Current" badge on latest
}
```

### 5d. Process Chart Component
**File:** `cmd/api/static/js/admin-main.js`

Line chart showing top 5 processes by CPU% over time. Clickable to see details.

### 5e. Interface Errors Chart Component
**File:** `cmd/api/static/js/admin-main.js`

Line chart showing InErrors + OutErrors per interface. Click interface to see details.

---

## 6. Implementation Order

### Phase 1: Core Infrastructure
1. Add SSH fields to Device model
2. Create crypto utility for password encryption
3. Update Device CRUD to handle SSH fields
4. Add SSH fields to DeviceInfo relay struct
5. Create `internal/ssh/client.go` basic SSH client

### Phase 2: Probe SSH Polling
6. Implement FortiGate command execution
7. Add `startSSHPolling()` to probe
8. Implement config checksum check + storage (last 5)
9. Parse and send process stats
10. Parse and send interface errors

### Phase 3: Relay & API Storage
11. Add new relay message types and send methods
12. Add API receive endpoints for new data types
13. Add ProcessStats and InterfaceErrors models + DB migration
14. Add DeviceConfigRevision model + DB migration

### Phase 4: API Endpoints & Alerting
15. Add config history endpoints
16. Add process/interface error history endpoints
17. Add alert on config change (CONFIG_CHANGE alert type)
18. Make alert type configurable in alert policies

### Phase 5: UI
19. Add SSH fields to device form modal
20. Build config history UI component
21. Build process chart UI component
22. Build interface errors chart UI component
23. Add tab navigation on device detail page

---

## 7. Key Files to Modify

| File | Changes |
|------|---------|
| `internal/models/models.go` | Add SSH fields to Device, add ProcessStats, InterfaceErrors, DeviceConfigRevision models |
| `internal/crypto/crypto.go` | NEW - AES encryption utilities |
| `internal/api/handlers/handlers_devices.go` | Add SSH CRUD, test-ssh, config-history, process-history, interface-errors endpoints |
| `internal/api/handlers/handlers_data.go` | Add receive endpoints for new relay message types |
| `internal/relay/relay.go` | Add SSH fields to DeviceInfo, new message types, new send methods |
| `cmd/probe/main.go` | Add SSH polling loop, call new SSH methods |
| `internal/ssh/client.go` | NEW - SSH client library |
| `internal/ssh/fortigate.go` | NEW - FortiGate command constants |
| `internal/ssh/parser.go` | NEW - Parse command outputs |
| `web/admin/admin.html` | Add SSH fields to device modal, new tabs on device page |
| `cmd/api/static/js/admin-main.js` | SSH form handling, config history, process chart, interface errors chart |
| `cmd/api/static/css/admin-shared.css` | New chart styles if needed |

---

## 8. Open Questions / Future Considerations

- [ ] Should we support multiple SSH poll intervals for different command groups?
- [ ] Process name normalization - some process names vary by FortiOS version
- [ ] Should we store full config diffs or just snapshots?
- [ ] Support for other vendors (PaloAlto, etc.) - architecture should be vendor-agnostic
- [ ] Configuration rollback UI - future feature to push config back to FortiGate
- [ ] Scheduled config backup to external SFTP server - user-initiated, not probe-driven

---

## 9. Code Review Findings (v1.2.34 / v0.10.167)

### HIGH Priority - Fixed (v1.2.34 / v0.10.167)
1. **SSH host key verification disabled**: Changed from custom callback accepting any host to `ssh.InsecureIgnoreHostKey()` for clearer intent
2. **Phase1Map silently overwrites duplicates**: Added warning log when duplicate Phase1 tunnel names detected; keeps first occurrence
3. **GetLatestVPNStatuses returns nil slice**: Changed to return empty slice `[]models.VPNStatus{}` instead of nil on no records, prevents JSON `null`
4. **IRC migration not transactional**: Wrapped IRC table recreation in transaction to prevent partial schema on failure

### MEDIUM Priority - Fixed
5. **No SSH concurrency limit**: Added semaphore (5 concurrent) to prevent unlimited goroutine spawns during SSH polling
6. **Greedy regex captures trailing whitespace**: Changed `.+` to `\S+` for status fields to avoid trailing whitespace
7. **Stale canvas text behind chart**: Added `clearRect()` before drawing "Not enough history data" text
8. **Triple API fetch for same data**: Refactored all three chart functions to share single fetch promise
9. **VPN Phase1name regex**: Fixed to capture quoted names (e.g., `"phase1name"`) instead of only non-whitespace

### LOW Priority - Fixed
10. **Dead code splitByWhitespace**: Removed unused function
11. **Duplicate connStyleLookup**: Removed local copy from admin-connection-detail.js; uses canonical `connStyle()`
12. **Queue O(n) shift on overflow**: Changed from slice slicing to `append()` pattern

### LOW Priority - Could Not Consolidate
- **Duplicate formatBytes in JS**: Tried to consolidate but found that files use IIFEs with 'use strict' - window.formatBytes is NOT accessible via unqualified formatBytes() calls. Each file (admin-device-detail.js, admin-connection-detail.js, public-dashboard.js) needs its own local copy due to IIFE scope isolation.

### Previously Fixed
- Parser multi-set bug, Database migration missing, Status regex truncation, VPN Status empty fallback, p2.RemoteGateway unused

---

## 10. Testing Checklist

### Completed (v0.10.165 / v1.2.32)
- [x] Probe SSH connects to FortiGate with read-only credentials
- [x] `get system performance status` - CPU breakdown, memory breakdown, network throughput, sessions
- [x] `show vpn ipsec phase1-interface` / `show vpn ipsec phase2-interface` - VPN tunnel configs
- [x] `get system ha status` - HA cluster status
- [x] `get system status` - firmware, serial, licenses
- [x] `execute sensor list` - hardware sensors
- [x] VPN tunnel statuses sent with phase1 interface name and mode
- [x] Network throughput chart on device detail page (in/out kbps)
- [x] CPU breakdown chart on device detail page (stacked area)
- [x] VPN tab enhanced with Interface and Mode columns
- [x] Connection map panel enhanced with Interface and Mode columns
- [x] VPN Status fallback to "unknown" when Phase1 lookup fails
- [x] Database migration helpers for new SystemStatus/VPNStatus columns

### Pending
- [ ] `show` command returns full config
- [ ] `diagnose sys checksum conf` returns valid checksum
- [ ] Config changes detected → alert created
- [ ] Last 5 configs stored, oldest auto-deleted when 6th arrives
- [ ] Process stats stored and chart renders correctly
- [ ] Interface errors stored and chart renders correctly
- [ ] SSH password encrypted in DB
- [ ] Device form saves/loads SSH fields correctly
- [ ] Config download returns valid config file
