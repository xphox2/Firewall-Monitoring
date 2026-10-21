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

## Top gaps

1. **No charts in V2.** No charting dependency. V1 draws ~30 series (dashboard
   resource trend, events rollups/short-window/security analytics, flows
   bandwidth, syslog/trap trends, device and per-interface/per-tunnel traffic,
   connection bandwidth/gauge charts).
2. **Interactive topology map.** V1 is a Cytoscape graph (pan/zoom, compound
   sites, expandable tunnel bundles, VLAN sublanes, LLDP evidence, alert
   overlays). V2 lists VPN-carrying devices.
3. **Connection detail.** Five tabs are raw JSON; the standalone detail page
   (bridge, gauges, tunnel tables, traffic analysis) has no V2 equivalent.
4. **Event rule/profile authoring.** V2 lists/toggles rules only — no
   create/edit/delete, condition builder, dampening, priority, expiry, profile
   matrix or assignments.
5. **Device detail.** No telemetry charts, per-interface/tunnel traffic, config
   **diff viewer**, HA, SD-WAN, ping SLA, AV/IPS/web-filter, licences, per-core
   CPU/disk/load.
6. **Alerts triage.** No range pills, stat tiles, charts, device/site/type/
   severity filters, snoozed toggle, paging, selection or linked detections.
7. **NOC wallboard.** Raw JSON snapshot; no vitals, cards, live feed or threat
   lists.
8. **Account security.** No 2FA enrollment/disable, no passkey registration, no
   admin reset-password/disable-user, no token expiry, no audit paging.
9. **IRC channels/commands.** No CRUD (counts only); server editor omits
   NickServ/SASL/server password/auto-reconnect.
10. **Maintenance scoping** to a device or site is not exposed.

Raw-JSON stubs: event detail, security event detail, syslog detail, flow sample,
trap detail, connection detail, IPSec CLI preview, device capabilities,
effective-policy simulator.

## Where V2 points at V1

Each thin surface renders a `ClassicFallback` notice with a link to the
equivalent classic page: NOC, topology map, connection detail, device detail,
event-rule authoring, alerts analytics, profile security, IRC management,
maintenance scoping and threat-intel lookup. The shell also carries a
`PREVIEW` pill and a dismissible notice, and the classic sidebar links to
`/admin/v2` with a `Preview` badge.
