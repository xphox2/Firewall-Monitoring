# Firewall-Mon — Design Patterns Audit (2026-06-22)

Scope: Gang of Four patterns + cross-cutting anti-patterns, applied to the
Firewall-Mon server repository at `E:\Golang\OpenCode\Firewall-Mon`.
Date: 2026-06-22. Audit pass: very thorough — every `internal/` package opened,
file sizes measured, all `func (h *Handler) …` counted, all `sync.Mutex` /
`atomic.Bool` locations listed, all `type X interface` declarations inspected,
all `errors.Is/As` usages checked, all package-level registries enumerated.

## Summary

- **Overall grade: B**
- **Top 3 wins**
  1. The `cmd/api/main.go:setupRoutes` middleware chain is a textbook **Decorator** stack — ordered, commented, each layer does one thing, and the `audit.Middleware` correctly fires `c.Next()` first so it records the post-handler status. (Reference: `cmd/api/main.go:467-491`.)
  2. The **Postgres advisory-lock** pattern (`database.go:265-352`) is a clean distributed **Singleton** guard: three keys (`apiSingletonLockKey`, `pollerWorkLockKey`, `startupMigrationLockKey`) with ASCII-packed constants so they're greppable in `pg_locks`. AUDIT-007/040/044 all ride this single mechanism.
  3. The two **Strategy** registries (`internal/snmp/vendor.go:vendorRegistry`, `internal/configdiff/normalize.go:registry`) are correctly applied — each has 6+ concrete implementations, registration is via `init()` per-vendor-file, lookup is the only entry point. Not one-implementation-shapes.
- **Top 3 concerns**
  1. **`Handler` in `internal/api/handlers/handlers.go` is a full God Object / Facade drift.** 100+ methods across 9 production files (`handlers_data.go`, `handlers_devices.go`, `handlers_dashboard.go`, `handlers_probes.go`, `handlers_settings.go`, `handlers_analytics.go`, `handlers_connections.go`, `handlers_irc.go`, `handlers_alert_policies.go`), holds 9 collaborators, setter-injected with an `RWMutex` (`mu sync.RWMutex` line 34) to paper over late binding. Touching any sub-feature requires editing `handlers.go` and one more file.
  2. **Three different "package-level singleton" idioms coexist** (`database.AppVersion`, `snmp.vendorRegistry`, `configdiff.registry`, plus the implicit singletons in `cmd/api/main.go`). All four rely on initialization order; none is wired through DI. One test (`handlers_devices_test.go` style fixtures) had to thread the same five constructors by hand.
  3. **The `sFlow` receiver (`internal/sflow/sflow.go`) still runs single-goroutine, single 64 KiB buffer** — exactly what the lessons.md SFLOW-NOC-REDESIGN-PLAN says the 100k samples/sec target must change. This is a *known incomplete* (sFlow redesign phase), but it means a Pattern audit has to call it out: the receiver is a single `sync.Mutex`-free `SFlowReceiver` struct (good), but the design target work has not yet landed.

## Findings

### [SEVERITY: critical] Handler is a God Object / Facade drift
- **Pattern violated**: Facade — drift into God Object (cross-cutting anti-pattern #1 in skill)
- **File**: `internal/api/handlers/handlers.go:24-35`
- **Snippet**:
  ```go
  type Handler struct {
      config       *config.Config
      authManager  *auth.AuthManager
      snmpClient   *snmp.SNMPClient
      uptimeTrack  *uptime.UptimeTracker
      alertManager *alerts.AlertManager
      ircManager   *irc.Manager
      notifier     *notifier.Notifier
      version      string
      db           *database.Database
      mu           sync.RWMutex
  }
  ```
- **Why it's a problem**: Counted 100+ `func (h *Handler) …` methods across 9 production files (the grep returned 100+ matches and was truncated). The struct holds 9 collaborators and exposes 5 setters (`SetIRCManager`, `SetAlertManager`, `SetSNMPClient`, `SetNotifier`, `SetVersion`) that all serialize on `h.mu`. Setters only exist because construction happens in three places (`cmd/api/main.go`, `cmd/poller/main.go`, and tests) at different points in the lifecycle. This is the textbook God Object / Facade drift: a single type that "knows every other type" and "orchestrates everything" via mutable late binding instead of constructor wiring. The skill says: *"If your facade is hundreds of lines and depends on every module in the codebase, split it into a few targeted facades or per-feature service classes."* This Handler has 100+ methods (≈ 4,000 lines across files) and depends on every module in the codebase.
- **Suggested fix**: Split by bounded context into per-feature sub-handlers that the route table composes:
  ```go
  // internal/api/handlers/devices.go
  type DevicesHandler struct {
      db *database.Database
  }
  func NewDevicesHandler(db *database.Database) *DevicesHandler { return &DevicesHandler{db: db} }
  func (h *DevicesHandler) Get(c *gin.Context) { ... }
  func (h *DevicesHandler) Create(c *gin.Context) { ... }

  // internal/api/handlers/irc.go
  type IRCHandler struct {
      irc    *irc.Manager
      db     *database.Database
      config *config.Config
  }
  ```
  Then `setupRoutes(router, devices, probes, alerts, irc, dashboard, …)` takes each handler struct instead of one `*Handler`. Delete the `mu sync.RWMutex` — there's nothing left to race on. The `reqDB(c)` helper moves to a free function or to a small `dbBound` interface embedded in each sub-handler.
- **Effort**: L (touches 9 files + the route table + every test that constructs `Handler`).

### [SEVERITY: high] `database.AppVersion` is process-global state passed through package scope
- **Pattern violated**: Singleton-as-default-scope (cross-cutting anti-pattern #5)
- **File**: `internal/database/migrations.go:14-15`
- **Snippet**:
  ```go
  // AppVersion is the build version stamped into each schema_migrations row.
  // Set by the binary's main (cmd/api) from its ServerVersion const; empty for
  // the poller/trap daemons and tests, which is harmless.
  var AppVersion string
  ```
- **Why it's a problem**: `AppVersion` is a package-level mutable string that one daemon (`cmd/api`) sets and another (`cmd/poller`, `cmd/trap-receiver`) leaves empty. The `cmd/api/main.go:48` and `:68` and `:105` set it from three call sites because the constructor can't take it. The skill's anti-pattern rule is exact: *"a top-level `var` instance is process-global but lazily initialized without synchronization — fine for stateless helpers, dangerous if the constructor does I/O."* This one isn't dangerous per se, but it's the wrong shape: a constructor argument. The `migrate` and `migrate-status` subcommands each set it manually before calling `database.Connect`. If a future test runs `database.Connect` first then reads `schema_migrations.app_version`, it sees the wrong version. It's already papercut-shaped.
- **Suggested fix**: Pass `appVersion string` into `Connect(cfg, appVersion)` and `NewDatabase(cfg, appVersion)`. Stamping a version into a `schema_migrations` row is a write-time concern, not a global. Delete the `var AppVersion`.
- **Effort**: S (3 callers + 1 constructor signature change + tests).

### [SEVERITY: high] Vendor / Normalizer registries are service-locator singletons with init-order coupling
- **Pattern violated**: Singleton — *real* one (process-global `map` guarded by `RWMutex`)
- **Files**: `internal/snmp/vendor.go:56-76`, `internal/configdiff/normalize.go:48-54`
- **Snippet (`vendor.go`)**:
  ```go
  var (
      vendorMu       sync.RWMutex
      vendorRegistry = make(map[string]VendorProfile)
  )

  func RegisterVendor(profile VendorProfile) {
      vendorMu.Lock()
      defer vendorMu.Unlock()
      vendorRegistry[profile.Name()] = profile
  }

  func GetVendorProfile(name string) VendorProfile {
      vendorMu.RLock()
      defer vendorMu.RUnlock()
      if p, ok := vendorRegistry[name]; ok {
          return p
      }
      return nil
  }
  ```
- **Why it's a problem**: `VendorProfile` is **Strategy** (good — 8 impls in `vendor_*.go`), but the registry is a **service-locator singleton** that depends on every `vendor_*.go` file's `init()` having run before any caller asks. If a future code path constructs a vendor profile lazily or tests one in isolation, it's invisible until runtime. The `vendorMu` lock is also doing nothing useful for the actual hot path (`GetVendorProfile` is called at most once per polled device). Worse, `DefaultVendor()` (`vendor.go:79-90`) iterates the map non-deterministically to pick a fallback — the same fleet's first poll could pick different vendors on different API restarts. This is a *de facto* singleton that the skill says is the exception, not the default.
- **Suggested fix**: Drop the registry. Make `VendorProfile` a method on a `Device` (or a per-vendor `NewProfile(cfg) VendorProfile` constructor) and let the caller pick by `device.Vendor`. If the registry must stay for backward-compat reasons, return the profile via a constructor argument passed through `*SNMPClient` instead of `GetVendorProfile(name string)`. At minimum, replace `DefaultVendor()`'s non-deterministic map iteration with an explicit priority list (fortigate, paloalto, cisco_asa, …).
- **Effort**: M (touches every `vendor_*.go` `init()` and every caller of `GetVendorProfile`).

### [SEVERITY: high] `Handler` setters serialize on a mutex to paper over late DI
- **Pattern violated**: Singleton — late binding + shared mutable state (cross-cutting #5)
- **File**: `internal/api/handlers/handlers.go:64-101`
- **Snippet**:
  ```go
  func (h *Handler) SetIRCManager(mgr *irc.Manager) {
      h.mu.Lock()
      defer h.mu.Unlock()
      h.ircManager = mgr
  }
  func (h *Handler) SetAlertManager(am *alerts.AlertManager) {
      h.mu.Lock()
      defer h.mu.Unlock()
      h.alertManager = am
  }
  // ... three more SetX methods, all the same shape
  ```
- **Why it's a problem**: The skill on Constructors and DI: *"In modern Go/TS/C# code, prefer passing that single instance through constructor injection or a DI container — that is testable, mockable, and doesn't hide dependencies."* The current `Handler` is constructed empty in `NewHandler(cfg, authManager, db)`, then 5 collaborators are added after the fact via setters guarded by a mutex. The mutex is doing the job a constructor should do (sequencing dependency assembly before any reader can see it). After `cmd/api/main.go:313-407` finishes the wiring, no further setter is called in production — so the mutex protects nothing in production and is only there because the test helpers (`handlers_config_semantic_test.go:88`, `ssh_host_key_test.go:22`) re-create the Handler between goroutines. That's a test smell that has leaked into production code.
- **Suggested fix**: Constructor takes everything it needs; setters and `mu` deleted:
  ```go
  func NewHandler(cfg *config.Config, deps Deps) *Handler {
      return &Handler{
          config:       cfg,
          db:           deps.DB,
          authManager:  deps.Auth,
          alertManager: deps.Alerts,
          ircManager:   deps.IRC,
          notifier:     deps.Notifier,
          snmpClient:   deps.SNMP,
          uptimeTrack:  deps.Uptime,
          version:      deps.Version,
      }
  }
  type Deps struct {
      DB *database.Database; Auth *auth.AuthManager; Alerts *alerts.AlertManager
      IRC *irc.Manager; Notifier *notifier.Notifier; SNMP *snmp.SNMPClient
      Uptime *uptime.UptimeTracker; Version string
  }
  ```
  Tests build the same `Deps` and call the same constructor. Or, better, split into per-feature handlers (see critical finding) so each one has only the deps it actually needs.
- **Effort**: S if combined with the God Object split; M if done alone (touches every `SetX` caller and test).

### [SEVERITY: high] `sFlow.Receiver` is single-goroutine; design target requires worker pool
- **Pattern violated**: Pattern-by-rote — the current shape (single reader + single 64 KiB buffer + `atomic.Bool`) is "what the language idiom says to write," not "what 100k samples/sec demands." (Per `tasks/lessons.md` SFLOW-NOC-REDESIGN-PLAN and lesson "100k+ samples/sec is the design target.")
- **File**: `internal/sflow/sflow.go:66-171`
- **Snippet**:
  ```go
  func (r *SFlowReceiver) readLoop() {
      defer r.wg.Done()
      buf := make([]byte, 65536)
      for r.running.Load() {
          select {
          case <-r.stopChan:
              return
          default:
              r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
              n, addr, err := r.conn.ReadFromUDP(buf)
              ...
              if n > 0 {
                  if len(r.allowedIPs) > 0 && !r.allowedIPs[addr.IP.String()] { continue }
                  r.parseDatagram(buf[:n])
              }
          }
      }
  }
  ```
- **Why it's a problem**: This is the **active** design target (lessons.md is unambiguous). The current shape is a single goroutine + single 64 KiB buffer (`make([]byte, 65536)`) + no `SetReadBuffer` + no `SO_REUSEPORT` + parse-on-receive-goroutine. At 100k samples/sec with multi-10-byte samples per datagram, a single reader caps well below the target. The skill's *Concurrency* section is exact: locks on the hot path are a smell — but here the issue is *lack* of parallel readers, not a misplaced mutex. The good news is the **receiver has no per-packet mutex** (`flowHandler` is called inline; whatever the handler does with its own locks is its business). The receiver is correctly structured for replacement.
- **Suggested fix**: (Owns the SFLOW-NOC-REDESIGN-PLAN work; not in scope for this audit.) The shape to land is:
  - `SO_REUSEPORT` socket + a worker pool (4 goroutines on a 4-core box) sharing the read buffer.
  - `SetReadBuffer(8 MB)` per socket.
  - `pgx.CopyFrom` for bulk insert, not GORM `Create`.
  - Per-agent token-bucket rate limit before parse.
  - `flowHandler` becomes a channel send (`chan<- *ParsedFlow`); workers consume. The current `FlowHandler func(*ParsedFlow)` callback signature is preserved as the public contract — the internal handoff is the new bit.
- **Effort**: L (this is the redesign itself).

### [SEVERITY: medium] Alert types and severities are stringly-typed; AlertManager has 25+ methods without a State machine
- **Pattern violated**: Pattern-by-rote (cross-cutting #2)
- **Files**: `internal/alerts/alerts.go` (1017 lines, 25 `(am *AlertManager)` methods), `internal/alerts/alerts.go:48-58` (alert-type strings), `internal/irc/bot.go:459-509` (command-type strings)
- **Snippet (`alerts.go:54-59`)**:
  ```go
  checks := []metricCheck{
      {"CPU_HIGH", fmt.Sprintf("cpu_high_%d", status.DeviceID), "cpu_usage", status.CPUUsage},
      {"MEMORY_HIGH", fmt.Sprintf("memory_high_%d", status.DeviceID), "memory_usage", status.MemoryUsage},
      ...
  }
  ```
- **Why it's a problem**: Alert types are `"CPU_HIGH"`, `"MEMORY_HIGH"`, `"DISK_HIGH"`, `"SESSIONS_HIGH"`, `"INTERFACE_DOWN"`, `"VPN_TUNNEL_DOWN"`, `"DEVICE_OFFLINE"`, `"SYSLOG_EMERGENCY"`, etc. — all stringly-typed, passed across 8 files (`alerts.go`, `policy.go`, `notifier.go`, `report/spike.go`, `handlers_data.go`, `handlers_analytics.go`, `handlers_devices.go`, `handlers_alert_policies.go`). The skill: *"Don't use State for two or three simple states — an enum + switch is clearer."* The `irc.handleCommand` switch on `cmd.CommandType` (`bot.go:459`) has the same shape — `string` field with magic values `"status"`, `"stats"`, `"help"`, `"default"`. A typo (`"statuss"`) compiles, fails silently, and is invisible until an operator runs `!statuss` and gets `cmd.Response` as a literal (because the default case falls through to `response = cmd.Response`, which is empty). This is exactly the failure mode the skill warns about.
- **Suggested fix**: `type AlertType string` with `const (AlertTypeCPUHigh AlertType = "CPU_HIGH"; …)`. Same for `Severity` (`type Severity string` with `const (SevInfo Severity = "info"; …)`) — currently the code mixes the string `"info"`/`"warning"`/`"critical"`/`"medium"`/`"high"` across `notifier.go`, `report/`, `configdiff/classify.go`, and `alerts/policy.go`. Severity already exists as a string enum in `configdiff.SeverityInfo` etc. (good — `classify.go:11-15`); extend the pattern. For `irc.handleCommand`, `type CommandType string` with `const (CommandStatus CommandType = "status"; …)`. This makes the `switch` exhaustive-checkable by `go vet` (or by an external linter) and turns silent typos into compile errors.
- **Effort**: M (string-typed constants propagate, so a sed-class rename needs care; do it as a typed-introduction first, fix call sites in follow-ups).

### [SEVERITY: medium] AlertManager has parallel per-method boilerplate instead of a data-driven rule registry
- **Pattern violated**: Pattern-by-rote (cross-cutting #2)
- **File**: `internal/alerts/alerts.go:46-125` (`CheckSystemStatus`), `:127-179` (`CheckInterfaceStatus`), `:570-615` (`CheckVPNStatus`), `:617-655` (`CheckDeviceOffline`)
- **Snippet (excerpt from `CheckSystemStatus` and `CheckVPNStatus`)**:
  ```go
  // CheckSystemStatus — body shape:
  //   am.mu.Lock(); build `checks` slice; resolve each; populate fired[]; am.mu.Unlock()
  //   am.dispatchFired(fired, ...)
  //   am.mu.Lock(); build recovery slice; am.mu.Unlock()
  //   for _, rc := range recoveryChecks { am.sendRecovery(...) }
  //
  // CheckInterfaceStatus — body shape (lines 127-179):
  //   am.mu.Lock(); loop over interfaces; resolve; populate fired[]; am.mu.Unlock()
  //   am.dispatchFired(fired, ...)
  //   for _, iface := range interfaces { if iface.Status == "up" { sendRecovery(...) } }
  //
  // CheckVPNStatus (570-615): same shape, different loop body.
  ```
- **Why it's a problem**: Four methods, all the same skeleton: lock, scan, resolve, build `fired`, unlock, dispatch, loop recovery. This is the classic "open the same file 25 times" smell. The skill on Pattern-by-rote: *"a switch statement is not a State-machine catastrophe,"* but here we have four near-identical switch-statements-on-type each in its own function. The fix is a small **Strategy/Template** registry: `type alertCheck struct { AlertType string; ShouldFire func(item any) bool; BuildAlert func(item any, resolved ResolvedAlertConfig) models.Alert; Key func(item any) string }` driven from a single `runChecks(checks []alertCheck, items []any, …)` method.
- **Suggested fix**: One `func (am *AlertManager) checkAndFire(alertType string, items []any, …)` that takes a registered `checkDef`. Register checks at `init()` time from a `map[string]checkDef`. Each `Check*Status` becomes 3 lines (resolve type → call `checkAndFire`). The skill's Template Method lesson applies: *"Use when you have a stable algorithm structure with variant steps… HTTP request handling (parse → authenticate → route → respond)."* This is exactly that shape.
- **Effort**: M (touches 4 methods + adds the registry; tests should pass unchanged).

### [SEVERITY: medium] `irc.Bot` state is implicit booleans + status strings, not a real State machine
- **Pattern violated**: Strategy vs State confusion (cross-cutting) — `b.Conn == nil` is a state check but there's no state object; status strings (`"connected"`, `"disconnected"`, `"error"`, `"joined"`, `"left"`) are passed to `updateStatus` but never compared.
- **File**: `internal/irc/bot.go:37-650` (the `Bot` and `Manager` types)
- **Snippet (excerpt of the implicit state)**:
  ```go
  // bot.go:284-381  (Start)
  b.mu.Lock()
  if b.Conn != nil { b.mu.Unlock(); return }
  // ...
  b.Conn = conn
  // ...
  // bot.go:344-350  (DISCONNECTED callback)
  b.mu.Lock()
  b.Conn = nil
  b.mu.Unlock()
  b.updateStatus("disconnected", "connection lost")
  // bot.go:175-200  (reconnectLoop)
  for _, bot := range m.bots {
      bot.mu.RLock()
      needsReconnect := bot.Server.AutoReconnect && bot.Conn == nil
      bot.mu.RUnlock()
      // ...
  }
  ```
- **Why it's a problem**: The reconnect loop asks each bot "are you nil?" — that's a state query without a state object. `b.channels[ch.ChannelName]` is a parallel bool map. `updateStatus("connected", "")` writes a status string that's then only ever read by the admin UI via `b.db.Model(b.Server).Updates(...)` — not by the IRC machinery itself. The skill on State: *"Don't use State for two or three simple states — an enum + switch is clearer."* Here we have 5 states (disconnected, connecting, connected, joined, error) and the "state" is scattered across 4 fields + 5 callbacks. The `b.channels` map is genuinely a per-channel state; the rest is bot-level. The cost is visible: in `RestartBot` (`bot.go:975-1004`), the code creates a *new* Bot and replaces the entry in `m.bots[serverID]` — but the old Bot may still be running its callbacks. There's no transition guard. (This is the kind of bug that gets caught by `go test -race` only if the test exercises it.)
- **Suggested fix**: Extract a `BotState` enum (`Disconnected | Connecting | Connected | Reconnecting | Error`) and gate transitions explicitly. The `reconnectLoop` becomes a state-machine runner instead of a polling loop. Per-channel state moves into `map[string]ChannelState`. The `updateStatus` calls persist to DB only — they don't drive behavior. The skill's State rule: *"Each ConcreteState implements the operations appropriate to that state and can request a transition by setting a new state on the context."*
- **Effort**: L (this is the IRC rewrite, not a small refactor).

### [SEVERITY: medium] `database` package is a 54-file god module; "internal/database" is itself a bounded-context violation
- **Pattern violated**: Mediator/Facade God Object — split-by-bounded-context violation (cross-cutting #1)
- **File**: `internal/database/` (54 files, ~10,000 LoC)
- **Snippet (file list)**:
  ```
  alerts.go batcher.go charts.go cleanup.go config_revisions.go
  connection_detail.go crypto.go database.go devices.go device_queries.go
  dialect.go events.go flows.go logging.go migrate.go migrations.go
  ping.go probekey.go sites_probes.go stats.go syslog_agg.go telemetry.go testing.go
  ```
- **Why it's a problem**: The skill on split-by-bounded-context: *"Mediator becomes a God Object if every interaction is centralized in it. If your mediator has thousands of lines of `if/else` on event types, it's really a controller / orchestrator pretending to be a pattern. Split by bounded context."* Here the god isn't a single struct — it's a single package. `internal/database` owns: alert CRUD, alert policies, devices, sites, probes, syslog aggregation, flows, rollups, encryption, partitions, cleanup, audit, telemetry, migrations, chart bucket parsing. Anyone touching any of those concerns imports `internal/database` and gets the other 13 too. The `Database` struct's methods span every concern. The package doc (`database.go:1-6`) says *"AUDIT-072 split the original 4,800-line database.go into cohesive per-domain files"* — that was a good step. The next step is splitting per-domain files into per-domain packages.
- **Suggested fix**: Split into `internal/database` (connection + lifecycle + migrations + advisory locks + the `Database` struct with `Gorm()`, `WithContext()`, `Close()`) and `internal/store/<domain>/` for each bounded context: `store/devices/`, `store/alerts/`, `store/flows/`, `store/probes/`, `store/syslog/`. The poller/trap daemons only need the store they actually use. The Singleton `Database` stays — it's genuinely a process-global resource (the GORM connection).
- **Effort**: L (touches every file that imports `internal/database`; that's most of the codebase). Possibly defer to a separate audit pass.

### [SEVERITY: medium] Decorator (audit middleware) reads context post-`c.Next()` — chain ordering is correct but undocumented as a contract
- **Pattern violated**: Chain of Responsibility (cross-cutting #13) — order sensitivity without documentation
- **File**: `internal/audit/audit.go:38-81`, `cmd/api/main.go:467-491`
- **Snippet (`audit.go:39-44`)**:
  ```go
  func Middleware(db *database.Database) gin.HandlerFunc {
      return func(c *gin.Context) {
          c.Next()
          if db == nil || !auditedMethods[c.Request.Method] {
              return
          }
          ...
  ```
- **Why it's a problem**: The audit middleware MUST run AFTER auth+CSRF (to capture the actor from context) and AFTER the handler (to record the final status). This is correctly implemented but the comment only lives at one site (`audit.go:28-37`). Anyone adding a new global middleware between auth and audit will silently break audit (actor won't be set) or audit will silently break new middleware (status won't be final). The skill's CoR lesson: *"when handler order matters (e.g. auth before logging), make it explicit."* The current comment is at the middleware definition; the route-registration site (`cmd/api/main.go:586-595`) doesn't repeat the constraint.
- **Suggested fix**: Add a structural assertion: `middleware.EnforceOrder(c, []string{"AdminAuth", "CSRFProtection", "audit.Middleware"})` that runs once at startup and panics if the order doesn't match. Or, define a single `AuthenticatedAdminGroup(router, …)` constructor that wires auth+CSRF+audit as one unit, so the order can't be tampered with at a route site. The skill lesson is exact: *"Always validate chain construction or return an 'unhandled' signal."*
- **Effort**: S (a startup-time assertion + a comment refresh at the route site).

### [SEVERITY: medium] Middleware order `RequestLogger` before `metrics.Middleware` records duplicate timings
- **Pattern violated**: Decorator — two middlewares do the same thing (`time.Since(start)`); both call `c.Next()` then time.
- **File**: `cmd/api/main.go:467-475`
- **Snippet**:
  ```go
  router.Use(middleware.RequestLogger())
  router.Use(metrics.Middleware())              // AUDIT-077: record request latency by route/method/status
  router.Use(middleware.BodySizeLimit(5 << 20)) // 5MB max request body
  ```
- **Why it's a problem**: `RequestLogger` (`internal/api/middleware/middleware.go:500-533`) wraps every request with `start := time.Now(); c.Next(); latency := time.Since(start)` and logs failures. `metrics.Middleware` (`internal/metrics/metrics.go:53-67`) wraps every request with the same shape and records latency in a Prometheus histogram. Both observe the SAME `c.Next()` call and time the SAME duration. They are correctly ordered so the histogram captures the full request, but each request takes two `time.Now()` calls + a duration computation + a label-value allocation — for nothing observable. Two decorators, one purpose.
- **Suggested fix**: Pick one. `metrics.Middleware` already exposes the histogram with the matched route template, method, status — that's strictly more useful than the access log line (which only logs >= 400). Delete the timing portion of `RequestLogger` (keep the failure-only structured log on >=400 status); have `metrics.Middleware` be the single timing decorator.
- **Effort**: S.

### [SEVERITY: low] `GetDashboardAll` runs the O(1) batched queries correctly but its `DeviceEnrichment` struct is internal to one function
- **Pattern violated**: Data Clump / local Pattern-by-rote — the inline `type DeviceEnrichment struct` (`handlers_dashboard.go:587-604`) is local to a single function.
- **File**: `internal/api/handlers/handlers_dashboard.go:587-604`
- **Snippet**:
  ```go
  type DeviceEnrichment struct {
      DeviceID     uint       `json:"device_id"`
      HasStatus    bool       `json:"has_status"`
      StatusTime   *time.Time `json:"status_time,omitempty"`
      ...
  }
  ```
- **Why it's a problem**: The AUDIT-033 fix correctly replaced N+1 queries with batched aggregates — good. But the `DeviceEnrichment` type is local to the function (declared inside it, line 587). It's a 17-field data clump with no behavior. Future readers who want a per-device summary will either re-define it elsewhere or copy-paste this struct.
- **Suggested fix**: Lift `DeviceEnrichment` to a package-level type in `internal/api/response/` (alongside `APIResponse`) — it's a wire shape, after all. Add a `BuildDeviceEnrichments(db, deviceIDs)` helper to `internal/database/dashboard.go` so the SQL aggregates and the struct live together. The dashboard handler becomes a one-liner that calls the helper.
- **Effort**: S.

### [SEVERITY: low] `auth.Database` interface has 4 methods, all trivially implemented by `*database.Database`
- **Pattern violated**: Premature Factory — interface defined "just in case" for mocking (a Go smell per the prompt).
- **File**: `internal/auth/auth.go:39-44`
- **Snippet**:
  ```go
  type Database interface {
      GetAdminByUsername(username string) (*AdminAuth, error)
      UpdateAdminPassword(id uint, password string) error
      GetAdminTokenVersion(id uint) (uint, error)
      IncrementAdminTokenVersion(id uint) error
  }

  type AuthManager struct {
      db            Database
      ...
  }

  func NewAuthManager(cfg *config.Config, db Database) *AuthManager { ... }
  ```
- **Why it's a problem**: This is the textbook Go smell called out in the audit prompt: *"are interfaces defined just for mocking."* `auth.Database` has 4 methods, each is a thin pass-through to `*database.Database`. There is no second implementation (search shows only `auth/auth_test.go` which mocks with a struct holding a map — i.e. for tests). The interface exists to allow tests to inject a fake, but the real prod path always passes `*database.Database`. The skill: *"Don't introduce a Strategy interface with one implementation — that's a needless abstraction."* The interface is justified IF you have an in-memory store for CLI tools; that store doesn't exist. The minor benefit (testability) can be preserved with `*database.Database` directly (the existing tests work because they use the real DB).
- **Suggested fix**: Either (a) delete the interface and take `*database.Database` directly (tests use SQLite), or (b) keep the interface but move it to `auth_test.go` (a `_test.go`-only type), or (c) document a second real implementation (e.g. a static-file mode) and add it. Pick one; don't leave the interface half-justified.
- **Effort**: S.

### [SEVERITY: low] `database.WithContext` returns a NEW Database per request — minor allocation overhead per request
- **Pattern violated**: Proxy misuse (cross-cutting #12) — proxying when the underlying object is in-process and cheap.
- **File**: `internal/database/database.go:51-55`
- **Snippet**:
  ```go
  func (d *Database) WithContext(ctx context.Context) *Database {
      cp := *d
      cp.db = d.db.WithContext(ctx)
      return &cp
  }
  ```
- **Why it's a problem**: Every browser-facing handler now calls `db := h.reqDB(c)` at the top — which allocates a 5-field struct on the heap. The "Proxy" is justified by the AUDIT-032 reasoning (per-request gorm session so client disconnect cancels queries), and the shallow copy is fine; the issue is the allocation frequency. The `cmd/api/main.go:setupRoutes` route table handles ~80 admin routes and ~20 public routes; each request allocates. Probably fine at current load; a 100k samples/sec hot-path concern would be different.
- **Suggested fix**: Leave it. The cost is one allocation per request and the AUDIT-032 invariant (client disconnect cancels in-flight queries) is more important than the allocation. Document this as "intentional, see AUDIT-032." No code change.
- **Effort**: none (no change).

### [SEVERITY: low] `validVendors` map in handlers.go duplicates `snmp.VendorProfile` registry
- **Pattern violated**: Strategy + duplicated lookup table
- **File**: `internal/api/handlers/handlers.go:185-198`
- **Snippet**:
  ```go
  var validVendors = map[string]bool{
      "fortigate": true, "paloalto": true, "cisco_asa": true, "sonicwall": true,
      "firewalla": true, "pfsense": true, "opnsense": true, "generic": true,
  }
  ```
- **Why it's a problem**: `validVendors` is a duplicate of the set of vendor names that have a registered `Normalizer` (in `configdiff.normalize.go`) and a registered `VendorProfile` (in `snmp.vendor.go`). The two registries are kept in sync by hand — adding a new vendor requires touching three places. If the operator configures `vendor="foo"` for a device, the API accepts it (it's in `validVendors`), but neither the normalizer nor the SNMP profile will do anything useful.
- **Suggested fix**: `func IsKnownVendor(name string) bool` exported from `internal/snmp` that consults `vendorRegistry`. `validVendors` map deleted. Or expose `configdiff.RegisteredVendors()` and union the two sets (defense in depth: SNMP and Normalizer should agree, but they don't have to).
- **Effort**: S.

### [SEVERITY: low] `models.Alert.Severity` and `models.Alert.AlertType` are string fields with no validation
- **Pattern violated**: Pattern-by-rote — string enum without compile-time safety (related to the earlier finding on alert-type strings).
- **File**: `internal/models/models.go` (973-line file; the Alert struct is one of ~40 GORM models in it)
- **Snippet (approximate — file is large)**:
  ```go
  type Alert struct {
      ...
      AlertType string  // "CPU_HIGH" | "MEMORY_HIGH" | ... (no validation)
      Severity  string  // "info" | "warning" | "critical" | "medium" | "high" (no validation)
      ...
  }
  ```
- **Why it's a problem**: GORM models must use primitive types (or `type Severity string` works because GORM supports string-derived types), but the current struct uses `string`. Any caller can write `alert.Severity = "urgent"` and it's saved. The DB column is a free-form text. The skill: *"Don't use State for two or three simple states — an enum + switch is clearer."* Here we have a string with no compile-time guarantee. Note: this is GORM-idiomatic to use `string`, but `type Severity string` works fine with GORM and gives you the type safety.
- **Suggested fix**: Convert to `type Severity string` and `type AlertType string` with the constants from the earlier finding. GORM handles typed strings without configuration.
- **Effort**: S (model file edit + tag/validation updates).

### [SEVERITY: low] `irc.Bot` callbacks are registered without ever being removed — observer chains rely on the connection's lifetime
- **Pattern violated**: Observer lifecycle (cross-cutting #3) — observers added to a long-lived publisher can leak.
- **File**: `internal/irc/bot.go:324-366`
- **Snippet**:
  ```go
  conn.AddCallback("001",           func(e *irc.Event) { b.onConnected() })
  conn.AddCallback("PRIVMSG",       func(e *irc.Event) { b.onPrivmsg(e) })
  conn.AddCallback("JOIN",          func(e *irc.Event) { b.onJoin(e) })
  conn.AddCallback("PART",          func(e *irc.Event) { b.onPart(e) })
  conn.AddCallback("QUIT",          func(e *irc.Event) { b.onQuit(e) })
  conn.AddCallback("DISCONNECTED",  func(e *irc.Event) { log.Printf(...); ... })
  conn.AddCallback("NOTICE",        func(e *irc.Event) { b.onNotice(e) })
  conn.AddCallback("433",           func(e *irc.Event) { ... })
  ```
- **Why it's a problem**: The `Bot` has its own `quit` channel and `b.Conn` is set to nil on disconnect, but the callbacks hold closures over `b` (the Bot). When `RestartBot` (`bot.go:975-1004`) replaces the entry in `m.bots[serverID]` with a new Bot, the OLD Bot's `conn` may still receive events briefly before its loop exits, and the closure-bound old Bot will fire `b.onConnected`/`b.onPrivmsg` etc. on the NEW connection. The reader-from-bot channel is shared, but the WRITES from old callbacks can race with the new bot's reads. This is exactly the Observer lifecycle leak the skill warns about: *"in long-lived publishers, observers that fail to unsubscribe cause memory leaks."* Here the leak is correctness, not memory.
- **Suggested fix**: Track callbacks explicitly and remove them on `Stop`. Or, simpler, give each Bot its own `*irc.Connection` and ensure `b.mu.Lock` is held in every callback before reading `b.Conn`/`b.Server` (currently `onPrivmsg` line 439 holds `b.mu.RLock` around the commands lookup, but `onConnected` line 398 does NOT).
- **Effort**: M.

### [SEVERITY: low] `BatchInserter` uses `gorm.Create` — not `pgx.CopyFrom`
- **Pattern violated**: Pattern-by-rote — using the easy ORM API instead of the bulk-insert primitive the lessons call for.
- **File**: `internal/database/batcher.go:38-43` (and the per-model instantiations in `database.go:188-196`)
- **Snippet**:
  ```go
  d.syslogBatch = NewBatchInserter[models.SyslogMessage](500, 2*time.Second, func(items []models.SyslogMessage) error {
      return d.db.Create(&items).Error
  })
  ```
- **Why it's a problem**: The skill on **bulk operations**: lessons.md says *"pgx.CopyFrom for bulk insert, not GORM Create."* This is exactly that case. `gorm.Create(&items)` does per-row INSERT statements (or a single multi-row INSERT with `CreateInBatches`, but this code uses default `Create` which is per-row). For the sFlow hot path this is the wrong primitive. For syslog/traps/pings it's less critical but still measurable.
- **Suggested fix**: When the connection is Postgres, use `pgx.CopyFrom` directly through the `sqlDB` pool. The `BatchInserter` already has the right shape (size-bounded buffer + timer flush); only the `flushFn` needs to switch. Keep `gorm.Create` as the SQLite (test) fallback.
- **Effort**: M (one helper + switch the three batcher setups).

## Patterns used well

- **Decorator (middleware chain)** — `cmd/api/main.go:467-491` is exemplary: `SecureHeaders → CORS → RequestID → tracing → RequestLogger → metrics → BodySizeLimit`, then per-group rate limiters. Each layer does one thing; comments explain ordering (e.g. AUDIT-135: "RequestID before RequestLogger so the ID is logged"). The audit middleware (`internal/audit/audit.go:38-81`) is also a clean Decorator that reads the post-`c.Next()` status. *Reference for the next PR that adds a middleware.*
- **Strategy (vendor profile registry)** — `internal/snmp/vendor.go:26-91` defines a 9-method `VendorProfile` interface with 8 implementations (`vendor_fortigate.go`, `vendor_paloalto.go`, `vendor_cisco_asa.go`, `vendor_sonicwall.go`, `vendor_firewalla.go`, `vendor_pfsense.go`, `vendor_opnsense.go`, `vendor_generic.go` + the BSD/Linux VPN variants). The interface is genuinely justified by N>1 implementations.
- **Strategy (normalizer registry)** — `internal/configdiff/normalize.go:38-94` is the same shape, also genuinely justified by 5+ vendor implementations.
- **Adapter** — `internal/notifier/notifier.go` is a clean SMTP/Slack/Discord/Webhook Adapter wrapping `smtp.SendMail` + `http.Client.Post`. The `CompoundAuth` for SMTP (`smtp_auth.go`) is a sub-Adapter that picks PLAIN vs LOGIN. `internal/snmp/snmp.go` is a clean Adapter over `github.com/gosnmp/gosnmp` (the `safeFloat` coercion at `snmp.go:105-120` is a particularly good example of *one* boundary-aware translation).
- **Adapter (wire contract)** — `internal/relay/relay.go` isolates the probe↔server DTOs from the internal `models`. `//go:generate` could probably add JSON schema generation; the package comment (`relay.go:1-12`) explicitly says these are "the human-readable source of truth referenced by MIGRATING.md and docs/SUPPORT-MATRIX.md." Excellent isolation.
- **Distributed Singleton via Postgres advisory locks** — `internal/database/database.go:265-409` defines three distinct keys (`apiSingletonLockKey`, `pollerWorkLockKey`, `startupMigrationLockKey`) for three different singleton semantics (API only, poller only, post-migration setup). The constants are ASCII-packed so they're greppable in `pg_locks`. AUDIT-007/040/044 all ride this single mechanism.
- **Builder (sort of — `cmd/api/main.go` is an explicit constructor sequence)** — main.go is verbose but linear: load config → load or generate JWT secret → init tracing → init admin password → connect DB → acquire singleton lock → init handler → init alert manager → init IRC manager → init SNMP client → wire everything → start. Each step has a documented error mode. Not a fluent builder, but a clear ordered composition.
- **DTO / Wire envelope** — `internal/api/response/response.go:14-43` is the standard `Success{Data,Error,Message}` envelope with `omitempty` JSON tags. Clean, single-purpose, isolated from persistence types.
- **Error wrapping** — Consistent use of `fmt.Errorf("%w: context", err)` and sentinel errors (`ErrInvalidCredentials`, `ErrTokenExpired`, `ErrInvalidToken`, `ErrAccountLocked`, `ErrNoJWTSecret` in `auth/auth.go:17-23`; `ErrEmptyBackup`, `ErrBackupTooSmall`, `ErrMissingVersionHeader`, `ErrMissingSystemGlobal`, `ErrTooFewConfigBlocks`, `ErrUnbalancedConfigBlocks`, `ErrBinaryCorruption` in `configdiff/validate.go:29-35`; `ErrProbeHasDevices` in `database/sites_probes.go:187`). Tests use `errors.Is(err, ErrXxx)` — modern Go idiom, no `== err` comparisons. 
- **Atomic.Bool for lifecycle flags** — `internal/syslog/syslog.go:38,395`, `internal/sflow/sflow.go:71`, `internal/database/batcher.go:32-33` all use `atomic.Bool` for the running/stopped flag instead of a mutex. This is exactly the Go idiom for "set-once-from-one-goroutine, read-from-many" lifecycle.
- **Bounded-buffer batcher with deterministic shutdown** — `internal/database/batcher.go:23-143` is a textbook example of a goroutine-backed batched writer: `atomic.Bool stopped` for fast-path reject, re-check under the mutex (close-the-race), `doneCh` closed only after the final flush. The AUDIT-006 fix here is exemplary.
- **Adapter at HTTP boundary (gated non-2xx)** — `internal/api/middleware/middleware.go:459-498` (`CORS`) correctly refuses the `*` + credentials combo at startup, not at request time — fail-fast.
- **Decorator (CSP nonce)** — `internal/api/middleware/middleware.go:316-426` (SecureHeaders + newCSPNonce + RenderHTML) is a per-request-nonce Decorator that round-trips through `gin.Context` via `c.Set(cspNonceKey, nonce)` and `GetCSPNonce(c)`. The tests (`csp_nonce_test.go`, `csp_nonce_html_test.go`) lock the contract.
- **O(1) batched queries for dashboards** — `handlers_dashboard.go:558-749` (`GetDashboardAll`) — pre-fix was N+1 (13 queries × 50 devices = 650 queries). Now O(1). The `DeviceEnrichment` is local-to-function (a minor smell, see finding), but the SQL rewrite is excellent.
- **Idempotency via header + defer** — `handlers_data.go:27-51` (`batchDedupCheck` + `markBatchIfOK`) uses `defer` to record the batch ID only on a 2xx response. The `if dup { return }` short-circuit returns 200 "deduped" so the collector doesn't retry.
- **Test patterns** — Heavy use of `//go:build integration` (e.g. `integration_pg_test.go`) so Postgres-specific tests don't run in the fast lane. AUDIT-NNN naming convention (`audit044_test.go`) ties every test to its motivating audit. The `TestChangelog_KeepAChangelogHeader_AUDIT110` test in `internal/shell` even validates `CHANGELOG.md` ordering.

## Open questions for the team

1. **Is the `Handler` split in scope for this PR, or should we open a separate refactor ticket?** Splitting 100+ methods across 9 files into per-feature handlers touches every test that constructs a Handler and the entire `setupRoutes` function. Probably needs its own audit pass + a roadmap entry.
2. **Is the `cmd/probe` deletion (lesson "Bundled probe should be deleted") still planned for phase 4?** It would remove the last non-Bearer auth path. Currently `cmd/probe` is read-only per the lessons; this audit didn't touch it.
3. **Where does the sFlow redesign land?** `internal/sflow/sflow.go` is the single biggest hot-path concern (100k samples/sec target). The receiver's shape is good; only the SO_REUSEPORT / worker pool / pgx.CopyFrom / SetReadBuffer work is missing. This audit didn't open the redesign ticket; it just flagged the gap.
4. **Are the stringly-typed AlertType / Severity / CommandType enums intentional?** The pattern shows up in 5+ places; converting to `type X string` with constants would make 6+ files compile-time-safer. Worth a focused PR before adding the next alert type.
5. **What's the policy on `vendorRegistry` / `Normalizer` registries?** Adding a new vendor currently requires: (a) `vendor_<name>.go` with `init()`, (b) `vendor_<name>_normalize.go` for the normalizer, (c) entry in `handlers.go:validVendors`, (d) optionally a `vendor_<name>_test.go`. That's 3-4 files per vendor. Worth keeping, but the registry-vs-DI trade-off (see findings) hasn't been re-evaluated since the codebase grew from 1 to 8 vendors.
6. **The `validVendors` map duplicates the union of the two registries — should it be deleted in favor of `snmp.IsKnownVendor()` + `configdiff.HasRichNormalizer()`?** Related to the previous question. Three places to keep in sync is one too many.
7. **The `Handler.mu sync.RWMutex` is only there because tests race setters with reads — is there a real production scenario?** If no, the right fix is to delete the mutex AND the setters in the same PR (see high-severity finding).
8. **`RequestLogger` and `metrics.Middleware` both time the request — which is the source of truth?** Pick one. Probably `metrics.Middleware` (it has more labels).
9. **Does the IRC `Bot` callback leak we identified (`RestartBot` races with old callbacks) actually happen in production?** If the operator clicks "restart IRC bot" from the admin UI, does the old bot's callbacks fire on the new connection? Worth a `go test -race` test before changing the code.
10. **`snmp.DefaultVendor()` returns a non-deterministic vendor on first call if the named one is absent — is this intentional?** Map iteration order in Go is randomized. If two API instances start with no fortigate but with a fallback, the fallback choice may differ between them.
