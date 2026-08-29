# Firewall-Mon — Master Feature Inventory & Roadmap

**Last updated:** 2026-07-02 (v0.11 program triage — see Part IV for the full feature-by-feature decisions and build sequence).

Two-repo product. **Server** = `Firewall-Mon` (Go module `firewall-mon`, ~v0.10.476): central store + brain + UI. **Collector** = `Firewall-Collector` (`firewall-collector`, ~v1.2.131): stateless remote edge probe. Some ingestion capabilities exist in **both** (server can ingest directly OR receive relayed from a probe).

Maturity legend: **Stable** = shipping; **Beta** = shipping with a known follow-up; **Planned** = roadmap row only.

---

## Part I — Master Feature Inventory

### 1. Monitoring (Data Ingest & Collection)

| Capability | Owner | Maturity | Notes |
|---|---|---|---|
| SNMP polling v1/v2c/v3 (MD5/SHA/SHA2; DES/AES/AES192/256) | Both | Stable | Server `fwmon-poller` (60s, advisory leader lock); collector polls at the edge on `PROBE_POLL_INTERVAL` and relays. |
| Multi-vendor SNMP `VendorProfile` registry | Both | Stable | Both repos register all 8 API vendors: fortigate/paloalto/cisco_asa/sonicwall/firewalla/pfsense/opnsense/generic. `cisco_asa` = MIB-II + CISCO-PROCESS/MEMORY-POOL/FIREWALL MIBs (CPU, memory, connection count, failover; no VPN table yet). `generic` = standards-only MIB-II/HOST-RESOURCES. Unknown vendor strings fall back to `generic`; empty vendor stays FortiGate (legacy default). Linux/BSD VPN interface-name helpers are shared by firewalla/pfsense/opnsense, not separate vendors. |
| SNMP trap receiver (UDP/162, V1 + V2c) | Both | Stable | Community filter, per-source rate limit, panic recovery. Server `fwmon-trap`; collector trap listener relays. |
| Syslog receiver (RFC 5424 + RFC 3164, TCP+UDP/514) | Both | Stable | Server stores `syslog_messages`/`syslog_summaries` + source allow-list. Collector parses RFC 5424 (6 timestamp formats) + FortiGate hostname/SD extraction. **Server adds RFC 3164.** |
| sFlow v5 parser (UDP/6343) | Both | Stable | Server → `flow_samples`. Collector: Ethernet + 802.1Q VLAN, IPv4/IPv6, TCP/UDP, fuzz target. |
| ICMP ping / reachability | Both | Stable | Raw net/icmp, no external binary. Collector adds latency+loss (10-concurrent semaphore, needs `NET_RAW`). |
| SSH config + telemetry polling (FortiGate) | Collector | Stable | `diagnose sys csum`, `show`, `diagnose sys top`, netlink iface list, sensors, perf status, VPN p1/p2, HA. Password or pubkey. **No server-side equivalent.** |
| TFTP config-backup receive (UDP/69) | Collector | Stable | 2 MB cap, per-source allow-list + rate limit *(see audit H2 — not wired in production)*, masked-password detection (FortiOS 7.2.1+). |
| Syslog-triggered debounced config backup | Collector | Stable | 60s debounce on `logid=0100044546`/`447`. |
| Uptime tracking & rollup | Server | Stable | Per-device calc + reset endpoint. |
| NetFlow v5/v9/IPFIX ingest | Collector | ✅ Shipped | Server v0.11.20 + collector v1.3.0 (Tranche 3). |

### 2. Alerting

| Capability | Owner | Maturity | Notes |
|---|---|---|---|
| Threshold engine (CPU/mem/disk/sessions) | Server | Stable | State-machine, dedup + cooldown, runs inside `fwmon-poller`. |
| Interface-down / offline detection | Server | Stable | Probe-offline set by poller, online by API. |
| Traffic-spike detection (per-interface std-dev) | Server | Stable | |
| Probe-health alerts (`PROBE_DATA_LAG`, `PROBE_DATA_TRUNCATED`) | Server | Stable | Server-authoritative on relayed-data freshness/truncation. |
| Alert policies (per-device/site, bulk, clone) | Server | Stable | |
| Maintenance windows (suppression) | Server | Stable | |
| Bulk ack / snooze / notes; auto-snooze + auto-archive | Server | Stable | |
| Per-device circuit breaker (3 fails → every 5th cycle) | Collector | Stable | Edge-local; **not reported to server as an alert state.** |

### 3. Config Management

| Capability | Owner | Maturity | Notes |
|---|---|---|---|
| Config-backup capture (SSH `show` + TFTP) | Collector | Stable | Single capture mode; masked-password detection. **FortiGate-only.** |
| Vendor-aware normalization + diff | Server | Stable | Rich: fortigate/paloalto/cisco_asa; identity-hash: sonicwall/firewalla/pfsense/opnsense/generic. |
| Object-aware diff + risk SEVERITY (info→critical) | Server | Stable | Category + summary; compliance tags reserved. |
| FortiGate change ATTRIBUTION (who/where/method/cfgpath) | Server | Stable | Parsed from event logs, no TACACS+. |
| Config-revision history + in-UI diff viewer | Server | Stable | |
| `configcheck` CLI | Server | Stable | Collector has `diag-backup` + `tftp-test` operator tools. |

### 4. Reporting

| Capability | Owner | Maturity | Notes |
|---|---|---|---|
| Executive HTML report (image-free, zero attachments) | Server | Stable | Single `html/template`. |
| Scheduled daily/weekly email reports | Server | Stable | `REPORT_TIMEZONE` (IANA TZ). |
| PDF export / download / send-now | Server | Stable | |
| Traffic-spike + uptime rollups; SVG/go-chart rendering | Server | Stable | |

### 5. Network Analysis

| Capability | Owner | Maturity | Notes |
|---|---|---|---|
| Sites / Connections / Probes model | Server | Stable | Inter-site connections across OSI layers. |
| Cytoscape topology analyzer | Server | Stable | physical→VLAN→tunnel→overlay; direct unified, overlays dashed. |
| Per-connection detail (traffic/events/flows) | Server | Stable | |
| Adaptive-bucketing chart windows (drag-zoom/pan) | Server | Stable | |
| Flow analytics from sFlow | Server | Stable | `flow_samples`. |

### 6. Security / Auth

| Capability | Owner | Maturity | Notes |
|---|---|---|---|
| JWT admin auth (HS256) + bcrypt (cost 12) | Server | Stable | **Single-admin by design.** |
| Account lockout (5/15min), per-IP LRU rate limiting | Server | Stable | Separate login/public/probe buckets. |
| CSRF on admin mutations; secure headers (HSTS/CSP-nonce/X-Frame) | Server | Stable | |
| In-process TLS termination + SSRF block-list; security.txt | Server | Stable | |
| Encrypted-at-rest secrets (AES-256-GCM, key rotation chain) | Server | Stable | Redacted-mask write-back guard. |
| Admin-action audit log (append-only, route-labelled) | Server | Stable | |
| mTLS probe→server | Both | Stable | Collector refuses world/group-readable keys; `PROBE_INSECURE_SKIP_VERIFY` loud-warns. |
| Per-probe registration-key approval workflow | Both | Stable | Hashed keys, constant-time compare, regenerate, Pending→Approve/Reject. |
| `schema_version` handshake (HTTP 426) | Both | Stable | Order-independent upgrades. |
| `X-Probe-Batch-ID` idempotency | Both | Stable | Server-side dedup (traps/pings/syslog/flows only). |
| Rootless hardened container; cap_drop ALL (+NET_RAW on probe) | Both | Stable | |

### 7. Notifications (all server-only — the collector never notifies)

| Capability | Owner | Maturity |
|---|---|---|
| Email (SMTP, HTML, STARTTLS/LOGIN/PLAIN) | Server | Stable |
| Slack / Discord / generic webhook (SSRF-gated) | Server | Stable |
| IRC bot (per-server, alerts + status commands) | Server | Stable |
| Test-email / test-webhook endpoints | Server | Stable |

### 8. Operability

| Capability | Owner | Maturity | Notes |
|---|---|---|---|
| Health endpoint(s) | Both | Stable | Server `GET /api/health` (PG ping). Collector `/healthz` + richer `/readyz` (approved + heartbeat-fresh + listeners bound, 503 + `X-Ready-Reason`). |
| Prometheus `/metrics` | Both | Stable | Server: latency histograms, DB-pool gauges. Collector: 13 `firewall_collector_` collectors. **Poller/trap-receiver expose none (audit M11).** |
| Structured logging (slog) + X-Request-ID | Both | Stable | |
| OpenTelemetry tracing (W3C across probe→api) | Server | Beta | OFF by default. **Collector emits no spans (audit M10) — half-instrumented.** |
| PostgreSQL 16 + versioned migrations + partitioning + retention | Server | Stable | SQLite tests-only. |
| Process coordination / single-instance guards | Server | Stable | API advisory lock `FWMNAPIS`; poller leader lock. |
| Disk-spillover queue (in-mem + BoltDB) surviving restart/outage | Collector | Stable | **Primary SNMP metrics NOT queued (audit H9).** |
| Graceful shutdown (SIGINT/SIGTERM drain) | Both | Stable | |
| `safego.Go` panic-recovery on long-lived goroutines | Collector | Stable | |
| Operator CLI tooling | Both | Stable | Collector: `ssh-test`/`diag-backup`/`tftp-test`. Server: `configcheck`/`migrate`/`migrate-status`. |
| Deployment/release tooling | Both | Stable | Server: compose (+proxy), `deploy.sh` systemd, embedded PG, nginx.conf. Collector: rootless image, auto-pushed tags. |

---

## Open audit follow-ups (2026-06)

Server items carried forward from the now-archived audit reports
(`docs/audit-archive/`) and the live `docs/audit-2026-06-23-consolidated.md`, so
nothing is lost when those point-in-time reports are retired. Each line is one
tracked item; resolved ones are struck through with the shipping version.

**Status at a glance — ✅ ALL RESOLVED (updated 2026-06-25):**

| Item | State |
|---|---|
| M8 — fail-fast / health on undecryptable secrets | ✅ DONE v0.10.491 |
| REL-01 — daemon panic recovery (`SafeGo`) | ✅ DONE v0.10.491 |
| REL-04 — `statement_timeout` on maintenance DDL | ✅ DONE v0.10.491 |
| LOW dead-code deletions | ✅ closed — not deletable (see below) |
| Server `alpine` 3.19 → 3.21 base bump | ✅ DONE v0.10.490 |
| `jackc/pgx/v5` CVE bump | ✅ DONE v0.10.489 |
| Handler God-Object + `internal/database` split | ✅ decoupled via `database.Store` v0.10.494 (file split was AUDIT-072) |
| Test-coverage backlog (relay/notifier/sflow/snmp) | ✅ addressed v0.10.492 |

**Every item from the 2026-06-23 audit is resolved.** The two large refactors
are complete; the only things deferred are *optional engineering headroom*, not
audit debt: deeper `internal/snmp` test coverage (needs a mockable SNMP walker)
and further receiver decomposition into per-domain handler/repository structs
(deliberately skipped as risky low-ROI churn now that the `database.Store` seam
exists). Detail per item:

- ~~**M8 — startup fail-fast / health signal on undecryptable `{enc}` secrets**~~
  — **DONE v0.10.491**. A persisted key-check value (`encryption_key_canary`
  SystemSetting) is decrypted at startup (`Database.VerifyEncryptionKey`): a
  rotated/lost `ENCRYPTION_KEY` now makes the poller and trap-receiver
  fail-fast (loud `log.Fatal`) instead of polling with empty creds, and the API
  stays up but reports `encryption:false` on `GET /api/health` (+ new
  `/api/readyz` alias) so it returns 503 instead of serving "healthy". Legacy
  keys in `ENCRYPTION_KEY_HISTORY` satisfy the check, matching real secret
  decryptability. Regression test: `crypto_canary_test.go`.
- ~~Server Dockerfile base bump `alpine:3.19` → `3.21`~~ — **DONE v0.10.490**
  (`postgresql16`/`-contrib` verified at 16.14-r0 in alpine 3.21 main, so PG
  stays at major 16 and PGDATA is unchanged).
- ~~`jackc/pgx/v5` v5.6.0 CVE bump~~ — **DONE v0.10.489** (→ v5.10.0, clears
  CVE-2026-33815/33816; `govulncheck ./...` reports no vulnerabilities).
- 🟡 **Handler God-Object split + `internal/database` package split — decoupled
  v0.10.494.** The file-level split (4887-line `database.go` + the monolithic
  `handlers.go` → per-domain files) shipped in AUDIT-072; both structs are
  already lean (10 fields). v0.10.494 addresses the remaining receiver-type
  coupling by extracting a `database.Store` repository interface (composed of
  narrow per-domain interfaces: `DeviceStore`, `AlertStore`, `IngestStore`, …)
  that the handlers depend on instead of the concrete `*database.Database`.
  **GORM and every query are unchanged** — `*database.Database` satisfies the
  interface for free; only `Handler.db`'s static type changed, and a fake `Store`
  now unit-tests handlers with no database (`store_fake_test.go`). The daemons
  (poller/trap-receiver) keep the concrete type. **Optional headroom:** fully
  decomposing the receiver into separate handler structs / repository structs was
  deliberately not done — it's large, risky churn with limited benefit now that
  the interface seam exists, and conflicts with the project's keep-it-simple bar.
- 🟡 **Test-coverage backlog — substantially addressed v0.10.492.** Table-driven
  coverage added across all four packages: `internal/notifier` 1.8% → 48.2%
  (pure payload builders + SMTP LOGIN/PLAIN auth + `SendAlert` fan-out),
  `internal/sflow` 35.9% → 69.4% (RFC 3176 datagram fixtures drive the
  previously-0% `parseDatagram`/`parseFlowSample`), `internal/snmp` 10.8% →
  20.1% (pure helpers + per-vendor formatters/classifiers + `ParseSystemStatus`/
  `ParseHardwareSensors`), and `internal/relay` 0% → wire-contract locked
  (schema-version + `omitempty` JSON contracts). **Remaining headroom:** the
  `snmp` package stays at ~20% because most of it is live `Walk`/`Get` network
  methods that need a device (or an injectable client interface) to exercise;
  pushing it higher means refactoring those toward a mockable walker, tracked as
  future work rather than a discrete audit item.
- ~~**REL-01 — server-daemon panic recovery**~~ — **DONE v0.10.491**. New
  `logging.SafeGo(name, fn)` / `logging.Recover(name)` helpers wrap the
  long-lived goroutines (poller cycle, report scheduler daily/weekly, syslog
  TCP-accept + UDP read loops, sFlow read loop, IRC manager load/reconnect/
  status loops + per-bot + conn loop, DB batch flusher, API login-attempt
  pruner). A panic is now contained to its goroutine, logged with a stack at
  error level, and no longer aborts the whole process. (The HTTP request path
  is already covered by `gin.Recovery()`.) Regression test: `safego_test.go`.
- ~~**REL-04 — `statement_timeout` on the maintenance DDL paths**~~ — **DONE
  v0.10.491**. New `Database.execMaintenanceDDL` lifts the timeout
  (`SET LOCAL statement_timeout = 0`, Postgres-only, tx-scoped) for
  `EnsurePartitions` (partition + index creates), `ConfigureAutovacuum`, and
  `dropPartitionsOlderThan`; `convertEmptyTableToPartitioned` lifts it inside
  its existing transaction. Maintenance DDL on a large/busy DB no longer aborts
  with 57014 at the 30s default.
- ~~**LOW dead-code deletions**~~ — **closed, no action**. Adversarial
  re-verification (2026-06-24) found neither item is deletable: the relay
  `StartCollector`/`runCollectorHandler` busy-loop was already removed with
  `cmd/probe` in commit `493ef87` (2026-06-21), and `linux_vpn`/`bsd_vpn` are
  **not** unregistered stubs — they are live shared helpers called by the
  registered `firewalla` (linux_vpn) and `pfsense`/`opnsense` (bsd_vpn) vendor
  profiles, so deleting them breaks the build. The original finding was
  inaccurate.

---

## Part II — Capability Gaps (data present in one repo not leveraged by the other)

1. **SSH-sourced extended telemetry under-modeled on the server.** Collector emits a rich `SystemStatus` (CPU user/system/nice/idle/iowait/irq/softirq, net in/out kbps, session rate 1/10/30/60s, low-mem, AV/IPS signature versions, SSLVPN users/tunnels). Server alerting/charting key off the narrower SNMP-shaped fields. *Roadmap:* signature-staleness alert, session-rate spike alert, CPU-iowait threshold.
2. **`cisco_asa` SNMP profile — resolved.** Both repos now register a `cisco_asa` profile (CPU via CISCO-PROCESS-MIB, memory via CISCO-MEMORY-POOL-MIB, connection count + failover state via CISCO-FIREWALL-MIB) and a standards-only `generic` profile; unknown vendor strings resolve to `generic` instead of FortiGate enterprise OIDs. *Remaining roadmap:* ASA VPN-tunnel enumeration (CISCO-IPSEC-FLOW-MONITOR-MIB) and hardware sensors (ENVMON/ENTITY-SENSOR) are deliberately omitted pending platform-conformance research.
3. **Config capture is collector-only & FortiGate-only; config intelligence is server-side for fortigate/paloalto/cisco_asa.** PAN-OS/ASA diff+attribution have no remote capture path. *Roadmap:* collector capture for PAN-OS/ASA.
4. **Circuit-breaker / probe-local backoff state is invisible to the server.** The probe knows *which device* fails and *why* (SNMP timeout vs SSH auth vs unreachable) but never relays it. *Roadmap:* a probe→server "per-device collection health" stream.
5. **Readiness asymmetry.** Collector `/readyz` has detailed `X-Ready-Reason`; the server's probe view shows only `last_seen` and can't show *why* a probe is unhealthy. *Roadmap:* relay readiness reasons into the probe detail page.
6. **OTel trace context is half-instrumented** (collector emits no spans). *Roadmap:* collector span emission for end-to-end traces.
7. **No edge-degraded alerting.** A site outage where the probe is up but the server link is down produces no notification until backlog drains. *Roadmap (lower priority, conflicts with thin-probe design):* optional edge "lost contact with server" webhook.
8. **NetFlow gap is bilateral** — collector lists it Planned; server flow analytics are sFlow-only. Needs lockstep work.

---

## Part III — Industry Gap Analysis & Prioritized Roadmap

Benchmarked vs **LibreNMS, Observium, PRTG, Zabbix, Auvik, RANCID/Oxidized, Panorama**. The product is deliberately *firewall-first*, so gaps are weighted by NOC/SOC buyer expectations, not NMS feature parity.

### Where Firewall-Mon already beats the peer set (defend/market)
- Config-change **attribution** (who/where/how, no TACACS+) — normally Panorama-only.
- Vendor-aware **semantic config-diff + risk severity** — most peers only do text diff.
- **OpenTelemetry distributed tracing** across the probe→server boundary — essentially none of the peers.
- **Encrypted-at-rest secrets with rotation chain** + redacted-mask write-back guard.
- **Append-only, route-template-labelled audit log** — stronger than most NMS audit trails.
- **Schema-version handshake (426) + idempotent batch relay** — production-grade collector protocol discipline.

### Gap matrix

| Capability | Today | Peer baseline | Gap | Priority |
|---|---|---|---|---|
| RBAC / multiple operators | Single admin by design | Zabbix/PRTG/Auvik roles | Missing | **P0** |
| API tokens / service auth | JWT admin login only | LibreNMS/Zabbix/PRTG scoped keys | Missing | **P0** |
| 2FA / MFA | bcrypt + lockout | PRTG/Auvik/Zabbix TOTP, SSO | Missing | **P0** |
| NetFlow / IPFIX | sFlow v5 only | LibreNMS/PRTG/Auvik NetFlow + IPFIX | Weak (sampled only) | **P0** |
| Alert escalation / on-call | dedup+cooldown+snooze | Zabbix escalations; PD/Opsgenie | Missing | P1 |
| PagerDuty/Opsgenie/Teams | Email/Slack/Discord/webhook/IRC | All majors | Missing (Teams + on-call) | P1 |
| SLA / availability objects | Uptime rollup | PRTG/Zabbix SLA objects | Weak (no SLA object) | P1 |
| Topology auto-discovery | Manual + analyzer | Auvik; LibreNMS LLDP/CDP/FDB | Weak (no LLDP/CDP) | P1 |
| Config compliance policies | Risk classification | Panorama policy compliance | Partial (no rule engine) | P1 |
| Syslog correlation / event rules | Store + summarize | Zabbix log triggers | Weak | P1 |
| Config-backup at-rest encryption | Secrets AES-GCM; revisions? | RANCID/Oxidized often plain git | Verify | P1 |
| Multi-tenancy / MSP | Single-tenant by design | Auvik/LibreNMS poller groups | Out of scope (deliberate) | P2 |
| Inbound webhooks / external ack | — | Alertmanager receivers | Missing | P2 |
| Maintenance windows | Present | parity | — | — |
| Audit trail / config attribution / tracing | Present | weaker in peers | Ahead | — |

### P0 — Credibility blockers (ship before any enterprise/SOC eval)

- **P0-1 Multi-user + RBAC foundation** — `users` model + Admin/Operator/Read-only roles; reuse JWT/bcrypt/lockout; extend the audit log with `actor_id`. Unblocks tokens and is the single most-cited enterprise objection.
- **P0-2 Scoped API tokens** — per-token bearer creds (hashed at rest like probe keys) with scopes + expiry; leverage `internal/secrets` + constant-time compare.
- **P0-3 TOTP 2FA** — RFC 6238 enrollment + recovery codes on admin login; no SSO needed for v1.
- **P0-4 NetFlow v5/v9 + IPFIX ingestion** — collectors alongside `internal/sflow` (UDP/2055, 4739), normalize into the same `flow_samples` path; template-based v9/IPFIX state. Highest-leverage data-plane item for a firewall product.

### P1 — Operational maturity (Zabbix/PRTG/Auvik parity for daily NOC use)

- **P1-1 Escalation chains + on-call** — escalate unacked alerts to the next tier; add PagerDuty + Opsgenie (Events API v2) + **Microsoft Teams** (the one missing major channel). Builds on the existing dedup/cooldown/auto-snooze state machine.
- **P1-2 SLA / availability objects** — promote uptime rollups into named SLA targets with breach reporting in the executive report.
- **P1-3 Topology auto-discovery (LLDP/CDP/FDB)** — auto-populate sites/connections via the existing SNMP poller; the biggest UX multiplier on the topology analyzer already built.
- **P1-4 Config compliance policy engine** — declarative pass/fail rules over parsed config objects (the reserved compliance tags); differentiates vs Oxidized/RANCID.
- **P1-5 Syslog correlation / event-trigger rules** — pattern→alert (repeated VPN auth failures, admin login from new IP, HA failover); high SOC value, low infra cost.
- **P1-6 Verify/encrypt config-backup at rest** — confirm revisions are encrypted (`internal/database/crypto.go`); a likely audit requirement and a differentiator vs plaintext-git peers.

### P2 — Differentiators & polish

- **P2-1 SNMPv3 posture enforcement** — flag devices still on v1/v2c.
- **P2-2 Inbound webhooks / external ack** — Alertmanager-style receivers + ack-from-chat.
- **P2-3 Multi-tenancy / MSP poller groups** — **deliberate non-goal today**; revisit only for the MSP market (major architectural change).
- **P2-4 Mobile-responsive ops view / browser push for P0 alerts.**
- **P2-5 Adaptive baselining** — generalize the traffic-spike std-dev to CPU/mem/sessions.
- **P2-6 Publish GitHub releases/tags for shipped versions** *(SHIPPED 2026-08-28, v0.11.213: `.github/workflows/release-tag.yml` tags `v<ServerVersion>` + creates a release with the CHANGELOG section on every master push where the constant changed; v0.11.211 backfilled manually so `releases/latest` resolves immediately)* — every release today is only a `ServerVersion` bump in `cmd/api/main.go` plus a CHANGELOG entry; the GitHub repo has **zero tags and zero releases**. The technicallabs.org System Monitor resolves each project's live version from the GitHub API (`releases/latest`, falling back to `tags`), so it can never resolve this repo and permanently shows its stale hardcoded baseline (v0.11.122 while the server is on 0.11.212) no matter how many versions ship. The stale README version badge (0.10.553) is the same missing-surface symptom. Would-be-nice fix: a small CI step on master that tags `v<ServerVersion>` (and optionally `gh release create`) whenever the version constant changes. The same gap exists in Firewall-Collector (see its `docs/FEATURES.md` roadmap).

### Recommended sequencing

1. **P0-1 → P0-2 → P0-3** (one "access control" epic; tokens + audit-actor depend on the user model). Unblocks every enterprise eval.
2. **P0-4 NetFlow/IPFIX** — parallel track, data-plane-only, no auth dependency.
3. **P1-1 + P1-2** (escalation + SLA): the "daily NOC" bundle.
4. **P1-3 topology auto-discovery** — highest UX leverage.
5. **P1-4 + P1-5** (compliance + syslog correlation): the "SOC value" bundle.
6. **P2** opportunistically; keep multi-tenancy explicitly deferred unless MSP is chosen.

**Single highest-ROI item:** the **P0 access-control epic** — the one gap that disqualifies the product in enterprise/SOC procurement regardless of data-plane quality, and mostly assembly of stacks already present (JWT, bcrypt, hashed-key compare, audit log).

---

## Part IV — v0.11 program decisions (2026-07-02 triage)

Every open item above and every AUDIT-F idea (docs/AUDIT.md F01–F89) was reviewed
feature-by-feature on 2026-07-02. This section is the authoritative record; where
it disagrees with older text above, this wins.

### Corrections — already built since the lists were written (do not rebuild)

| Item | Status | Where |
|---|---|---|
| F23/F24 geo + ASN enrichment | DONE | FlowSample Src/DstCountry + Src/DstASN, analytics filters (v0.10.514) |
| F25 threat category stats | DONE | SecurityStats + GetDeviceSecurityStats |
| F28 topology view | DONE | Connection Map (Cytoscape), admin.html |
| F31 real-time event stream | DONE | NOC SSE hub (handlers/noc.go) |
| F46 audit log | DONE | AUDIT-078 (ActorID already threaded) |
| F74 dark/light theme | DONE | Day/Night theme (v0.10.499) |
| F82 partition migration path | DONE | docs/partition-migration.md |
| F81 hot-query indexes | MOSTLY | idx_flow_src/dst_addr exist; only idx_iface_device_name_ts remains |
| F21 top talkers | PARTIAL | report-only; live API/UI still open |
| F42 decommission | PARTIAL | probes only; devices still open |
| F55 poll staleness | PARTIAL | probes only (MarkStaleProbesOffline); device POLL_STALE open |

### Declined (deliberate skips — do not re-propose without new cause)

/admin/system self-monitoring page F50–F56 (Prometheus/Grafana pack covers it;
only exception: none — even F52/F56 self-alerting was declined), device
notes/tags/wiki F43/F44/F49, attachments F45, GDPR purge F77, status-page email
subscriptions F59, sample-data/demo mode F71, multi-tenancy + white-label
F86–F89 (standing non-goal).

### Selected — build sequence (tranches)

| # | Tranche | Contents |
|---|---|---|
| 1 | **Access-control epic** | ✅ **SHIPPED v0.11.0** — RBAC (v0.10.566), scoped API tokens/F64 (v0.10.567), TOTP 2FA/F68 (v0.10.568); migrations v20–22. |
| 2 | Alerting maturity | ✅ **SHIPPED v0.11.1–v0.11.10** — F14 hysteresis (.2), role-aware UI (.3), F18 webhook signing (.4), F13 flap suppression (.5), F17 z-score baselining/P2-5 (.6), PagerDuty+Opsgenie+Teams (.7), F19 escalation chains (.8), F12 incident grouping (.9), F05/F06 MTTA/MTTR+noise reports (.10); migrations v23–27. |
| 3 | **NetFlow v5/v9 + IPFIX** (P0-4) | ✅ **SHIPPED server v0.11.20 + collector v1.3.0** (migration v29) — collector-side receiver (UDP 2055/4739, content-based version dispatch), shared v9/IPFIX template engine (persisted caches, quarantine, withdrawal handling), nfdump-style sampler resolution chain, biflow reverse-record emission (RFC 5103 / OUT_BYTES / NSEL initiator-responder), sequence-gap metrics, per-exporter dual-export dedup with failover (`PROBE_FLOW_DEDUP`); server-side `flow_source` labeling + filter/UI, denied-flow events (IE 233), flow_start/flow_end, post-NAT tuple, mixed-source warning. Vendor conformance fixtures: FortiGate (sampled-scale ×rate), PAN (App-ID), ASA NSEL (byte-only), SonicWall (EntID 8741), MikroTik (IE34-in-data), pfSense/OPNsense/generic. Design record: `docs/flow-protocol-research-2026-07-03.md`. Fast-follows (from research §3): template debug admin page, unknown-exporter approval UX, PAN App-ID/FortiGate app-options → app_category precedence, config-driven vendor-IE map, UDP datagram tee, NSEL update-reconciliation, duration-aware chart bucketing. |
| 4 | Flow detection engine | sFlow roadmap R3/R4, after NetFlow so both sources covered. Research inputs ready (`flow-protocol-research` §4): completeness-gated detectors (sampling_rate==1 + source flag), DDoS bps/pps/fps OR-thresholds + per-prefix, denied-flow storms via firewall_event, flow stitching via flow_end_reason==2, RITA-model beaconing, DNS tunneling, interface-%-from-flows. |
| 5 | SLA & reporting | P1-2 SLA objects + F03 + F33; F01 ad-hoc range; F04+F26 capacity; F07 security posture |
| 6 | Analytics & syslog intel | F20 heatmap; F21+F27 top-talkers UI + conversation matrix; P1-5 correlation rules + F22 top destinations (shared syslog aggregator) |
| 7 | Topology auto-discovery | P1-3 LLDP/CDP/FDB → Connection Map |
| 8 | Config intelligence | P1-6 revision-encryption verify (first, small); P1-4 compliance policy engine |
| 9 | Vendor + collection health | F34 FortiGate deep; probe collection-health/readiness relay (gaps #4/#5); F36 Palo Alto (+ PAN capture); F35 Cisco ASA (+ collector port) |
| 10 | API & integration | F62 /api/v1 + F63 OpenAPI; F65 outbound webhook bus; F66 inbound ingest (P2-2); F67 OIDC/SSO |
| 11 | Public status page | F57+F58+F60+F61 core only |
| 12 | Data lifecycle | F79 rollups; F80 dashboard mat-view; F83 Parquet/CSV archive; F81 remaining index |
| 13 | Onboarding & polish | F69 wizard; F70 SNMP discovery; F72 tooltips; F73 Cmd-K; F47 bulk actions; P2-1 SNMPv3 posture; P2-4 mobile/push |
| — | Compliance riders | F76 tamper-evident audit log + F75 signed backups (after T8); F78 SOC2 evidence (after F76) |

Sequencing rationale: access control first (strategic unblock for tokens, OIDC,
OpenAPI), alerting second (daily-use pain), data-plane epic third/fourth in the
user-chosen order (NetFlow before detection), then operational bundles;
cross-repo tranches (3, 9) coordinate both changelogs and CIs.
