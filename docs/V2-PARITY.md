# Admin UI V2 — feature parity with the classic console

**Status: preview.** The V2 console at `/admin/v2` is route-complete but not
feature-complete. This page is the single source of truth for what is missing,
so an operator (or a reviewer) never has to guess whether a thin screen is a bug
or an unbuilt feature.

**Audit baseline:** v0.11.333 (296 audited units). **Current state:** v0.11.355.
The baseline table is kept for history; the current-state table and the remaining
gaps list below are the actionable view.

## Current state (v0.11.355)

| Area | State | Remaining |
|---|---|---|
| Dashboard / NOC | At parity: KPIs, server runtime telemetry, host CPU/memory/root-disk/DB-volume trend, NOC wallboard with feed pause and site drill-down | — |
| Events | At parity: analytics + rollup charts, distributions, structured event/security inspectors, security class/severity filters and paging | — |
| Flows | At parity: filters, throughput chart, byte-ranked distributions, degraded-window disclosure, conversation drill-down, sample inspector, CSV export | — |
| Syslog / Traps | At parity: stats charts, range pills, severity filtering, structured inspectors | — |
| Threat Intel | At parity: lookup verdict, feed switch/status, indicator search/add/delete, storm tuning | — |
| Topology / Connections / IPSec | Interactive Cytoscape map + five-tab connection detail + structured IPSec preview | Expanding tunnel bundles / VLAN sublanes in the graph itself; graph alert overlays |
| Devices | At parity: charts, traffic, config diff/split/revision view+delete, HA, SD-WAN, ping SLA, security/licences, per-core resources, operational panels | Cosmetic word-diff pairing in split diff |
| Collectors / Sites | Not re-audited since the baseline | Collector/site editor fields and bulk actions may still lag the classic console |
| Alerts | At parity: filters, stats + per-type volume trend, by-type distribution, bulk ack/snooze, paging, linked flow detections, parsed syslog fields, incidents | — |
| Alerting | At parity: rules, profiles, tri-state matrix, assignments, overview, simulator | Profile-scoped "effective" view (the Configuration Overview covers the need) |
| Storage / Archive | Not re-audited since the baseline | Some storage/archive controls may still be classic-only |
| Integrations | At parity: SMTP/webhooks/IRC servers, channels, commands, advanced credentials | — |
| System | At parity: users (disable/reset/passkeys), token expiry/status, audit paging/filters, TOTP wizard + decline, passkey registration/rename, member-since | — |
| Maintenance | At parity: scoping to all/device/site and per-alert-type suppression | Recurrence (unexposed in both consoles) |

## Historical audit baseline (v0.11.333)

### How to read this

Every V1 feature unit (chart, table, form, action, panel) was compared against
V2:

- **Implemented** — equivalent behaviour and depth.
- **Partial** — works, but a subset (fewer columns, no paging, no analytics).
- **Stub** — renders raw JSON or a placeholder.
- **Missing** — no V2 surface.

### Scoreboard (v0.11.333)

| Area | Implemented | Partial | Stub | Missing | Units |
|---|---:|---:|---:|---:|---:|
| Dashboard / NOC | 1 | 6 | 1 | 10 | 18 |
| Events | 1 | 8 | 1 | 17 | 27 |
| Flows | 0 | 7 | 1 | 20 | 28 |
| Syslog | 2 | 2 | 1 | 9 | 14 |
| Traps | 0 | 1 | 0 | 7 | 8 |
| Threat Intel | 1 | 5 | 1 | 2 | 9 |
| Topology / Connections / IPSec | 0 | 4 | 2 | 21 | 27 |
| Devices | 2 | 14 | 1 | 20 | 37 |
| Collectors / Sites | 5 | 5 | 0 | 7 | 17 |
| Alerts | 0 | 7 | 0 | 9 | 16 |
| Alerting | 5 | 7 | 1 | 13 | 26 |
| Storage / Archive | 7 | 4 | 0 | 8 | 19 |
| Integrations | 8 | 1 | 0 | 4 | 13 |
| System | 11 | 7 | 0 | 12 | 30 |
| Maintenance | 1 | 3 | 0 | 3 | 7 |
| **Total** | **44** | **81** | **9** | **162** | **296** |

## Since the v0.11.333 audit

- **v0.11.335** — Event rule create/edit/delete with a condition builder, source-specific
  dampening and preview. Event rule **profile** management (create/clone, On/Off/Inherit
  matrix, site/device assignments) is still classic-only.
- **v0.11.336** — Device telemetry charts (system/network/CPU over 8 ranges), per-interface
  traffic (SNMP + sFlow) and per-tunnel traffic (VPN group). Device config diff, HA,
  SD-WAN, ping SLA, security/licence panels and per-core CPU/disk/load remain classic-only.
- **v0.11.337** — Device config diff viewer (revision compare, verdict, object + line diff,
  search/severity filters, revision download). Remaining device gaps: HA, SD-WAN, ping SLA,
  AV/IPS/web-filter, licences, per-core CPU/disk/load, config revision in-place viewer.
- **v0.11.338** — Device operational panels (per-core CPU, filesystems, load average, security
  counters, licences, HA, SD-WAN, ping SLA, recent alerts). Device page remaining gaps: in-place
  revision viewer and split/tree diff views.
- **v0.11.339** — Alerts triage (filters, stats + volume chart, bulk ack/snooze, pagination,
  detail drawer, incidents open/resolved). Remaining alert gaps: parsed syslog fields, linked
  flow detections, per-type trend breakdowns.
- **v0.11.340** — User administration (disable/enable, reset password, remove passkeys, status),
  API token expiry/status and audit paging/filters.
- **v0.11.341** — 2FA enrollment/disable wizard and passkey registration/removal (with the
  real WebAuthn ceremony and required re-auth). Remaining: decline-with-risk, passkey rename,
  and the profile "member since" line.
- **v0.11.342** — Maintenance scoping (all/device/site) and per-alert-type suppression from the
  server registry. Recurrence remains unexposed in both consoles.
- **v0.11.343** — IRC channels/commands CRUD and advanced server credentials (NickServ/SASL,
  auto-reconnect). The Integrations area is now at parity.
- **v0.11.344** — Event-rule profile CRUD + tri-state toggle matrix. Remaining: profile
  assignments to sites/devices and the effective profile view.
- **v0.11.345** — Live NOC wallboard (vitals, site/device health, named-event feed, threats
  last 60s). Remaining: feed pause/hover hold, per-site drill-down snapshots, and NOC focus
  links from the topology map.
- **v0.11.346** — Structured Threat Intel (lookup verdict card, feed master switch and status,
  indicator search/paging/add/delete, storm tuning on the real field).
- **v0.11.347** — Config revision viewer, split diff and confirmed revision delete. The Device
  area is now at parity except cosmetic word-diff pairing in split view.
- **v0.11.348** — Flow analytics (filters, throughput chart, byte-ranked distributions, degraded
  window disclosure, conversation drill-down, samples inspector, CSV export).
- **v0.11.349** — Event-rule profile assignments (sites/devices) with unassign; Alerting is now
  at parity apart from linked detections and parsed syslog fields in triage.
- **v0.11.350** — Event analytics charts + distributions, structured event and security-event
  inspectors, security class/severity filters and paging. Remaining: syslog/trap detail stubs,
  dashboard host trends, topology/connection detail, storage/system leftovers.
- **v0.11.351** — Syslog and trap stats charts, range pills, severity filtering and structured
  inspectors; traps list gained a server-side `hours` window.
- **v0.11.352** — Interactive Cytoscape topology map (site compounds, connection/tunnel edges,
  filters, zoom/fit, device drill-through).
- **v0.11.353** — Five-tab connection detail (KPIs, tunnel tables, L2 evidence, phase-2
  correlation, traffic chart). Remaining: graph bundle/VLAN expansion and alert overlays.
- **v0.11.354** — Alert linked flow detections, source-address chip and by-type distribution;
  the last classic-only banner was removed. Remaining alert sub-gaps are named inline.
- **v0.11.355** — Structured IPSec preview (findings + per-end CLI) and event-rule tester result.
- **v0.11.356** — Parity document refreshed (current-state table + historical baseline).
- **v0.11.357** — In-app DB-IP credit removed; attribution kept in NOTICE / THIRD-PARTY-NOTICES.
- **v0.11.358** — Per-alert-type volume trends (`alert_type` on /alerts/stats, type selector on the
  volume card). The only remaining alert sub-gap is structured syslog-field parsing.
- **v0.11.359** — Server resource trend (CPU/memory/root disk/DB volume) on the dashboard, with
  unprobed volume buckets kept as gaps.
- **v0.11.360** — Account leftovers: 2FA decline-with-risk, passkey rename, member-since.
- **v0.11.361** — Parsed syslog fields for syslog-sourced alerts (fixed the dead `metric_name`
  gate in both consoles). The alert area is now at parity.
- **v0.11.362** — NOC site drill-down snapshots and live-feed pause/hover-hold. The NOC is at
  parity.

## Remaining gaps

1. **Topology graph depth.** The interactive map covers sites, connections,
   IPSec tunnels, filters, zoom/fit and device drill-through, and the detail
   drawer has the five tabs. Still classic-only: expanding tunnel bundles /
   VLAN sublanes inside the graph and alert overlays on nodes.
2. **Storage / archive.** Not re-audited; some controls may still be classic-only.
3. **Collectors / sites.** Not re-audited; editor fields and bulk actions may lag.
4. **Profile effective view.** Assignments work; the classic per-profile
   "effective" preview is represented by the Configuration Overview.
5. **Device diff cosmetic.** Split view aligns rows but does not pair a modified
   line's delete+insert into one word-diff row.

Raw-JSON stubs still present: device capabilities (inside a disclosure) and the
effective-policy simulator. Event, security-event, syslog, trap, flow-sample,
connection detail, IPSec preview and the event-rule tester are structured (raw
JSON remains available behind a disclosure).

## Where V2 points at V1

No `ClassicFallback` notices and no inline classic-only sub-gap notes remain.
The shell still carries a `PREVIEW` pill and a dismissible notice, and the
classic sidebar links to `/admin/v2` with a `Preview` badge. The remaining
backlog is listed above.
