# Admin UI V2 — feature parity with the classic console

**Status: preview.** The V2 console at `/admin/v2` is route-complete but not
feature-complete. This page is the single source of truth for what is missing,
so an operator (or a reviewer) never has to guess whether a thin screen is a bug
or an unbuilt feature.

Last audited: **v0.11.333** (audit re-run when this file changes).

## How to read this

Every V1 feature unit (chart, table, form, action, panel) was compared against
V2:

- **Implemented** — equivalent behaviour and depth.
- **Partial** — works, but a subset (fewer columns, no paging, no analytics).
- **Stub** — renders raw JSON or a placeholder.
- **Missing** — no V2 surface.

## Scoreboard (v0.11.333)

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
  inspectors; traps list gained a server-side `hours` window. Remaining: dashboard host trends,
  topology/connection detail, storage/system leftovers.

## Top gaps

The scoreboard above is the **v0.11.333 audit baseline**; the per-version log
records what has closed since. Re-auditing all 296 units is pending, so this
list — not the table — is the current backlog.

1. **Topology map and connection detail.** V1 is a Cytoscape graph (pan/zoom,
   compound sites, expandable tunnel bundles, VLAN sublanes, LLDP evidence,
   alert overlays) plus a standalone connection page (bridge/gauges/tunnel
   tables/traffic analysis). V2 lists connections and IPSec data; the map and
   the five connection detail tabs are still classic-only. IPSec CLI preview is
   a raw-JSON stub.
2. **Events depth.** Analytics and rollups exist, but event/security-event
   detail is still a raw-JSON drawer, and several security columns/filters and
   per-type breakdowns remain classic-only.
3. **Syslog and traps depth.** Detail views are raw JSON; trap/syslog trend
   charts and some filters are still missing.
4. **Dashboard resource trend.** The classic dashboard draws host CPU/memory/
   disk trends over time; V2 shows current values only.
5. **Alert triage leftovers.** Parsed syslog fields, linked flow detections and
   per-alert-type trend breakdowns.
6. **Storage / archive leftovers.** The storage page and archive/export flows
   still miss several controls from the classic console.
7. **Account security leftovers.** 2FA "decline with risk acknowledgement",
   passkey rename, and the profile "member since" line.
8. **Collectors / sites leftovers.** Several collector and site editor fields
   and bulk actions remain classic-only.
9. **Profile effective view.** Assignments now work; the classic per-profile
   "effective" preview is represented by the Configuration Overview rather than
   a profile-scoped view.

Raw-JSON stubs still present: event detail, security event detail, syslog
detail, trap detail, connection detail, IPSec CLI preview, device capabilities
and the effective-policy simulator.

## Where V2 points at V1

Thin surfaces still render a `ClassicFallback` notice with a link to the
equivalent classic page: the **topology map / connection detail** and the
**alert triage analytics** that are still classic-only. The shell also carries
a `PREVIEW` pill and a dismissible notice, and the classic sidebar links to
`/admin/v2` with a `Preview` badge.
