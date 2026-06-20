# Config Backup Comparison — Feature Roadmap (NOC/SOC-grade)

> Research-backed plan to evolve our config change-detection from a normalized line diff
> into a semantic, attributed, risk-classified change-review experience.
> Research conducted 2026-06-20 (deep-research harness, 26 sources, 24/25 claims adversarially verified).

## Where we are today (baseline)

Our feature is a **hash-based, line-level, indentation-insensitive** diff optimized to *suppress
false positives* from vendor volatile content (ENC blobs, IV drift, timestamps, GUI-dashboard noise).

- `internal/configdiff/` — rich normalizers for FortiGate / Palo Alto / Cisco ASA; identity fallback
  for SonicWall / Firewalla / pfSense / OPNsense.
- Change detection = MD5 of normalized text; `CONFIG_CHANGE` alert (always severity `warning`).
- UI (`admin-device-detail.js`) = client-side line diff with volatile-line masking; A-vs-B only.
- Storage = `DeviceConfigRevision` merge-into-latest (one row per logical state).

**What an operator cannot do today:** see *what kind* of change (rule vs interface vs admin), *who*
made it, whether it's *security-relevant*, or get a *severity*. Everything is a flat line delta.

## What best-in-class tools do (validated research)

| Capability | Reference implementation | Source confidence |
|---|---|---|
| **Semantic/object-aware diff** — parse config into vendor-neutral object model (rules, ACLs, NAT, routes, interfaces, BGP), diff per-object | **Batfish** | high (primary docs + repo) |
| **Behavioral impact** — "what does this change *do*?" (new traffic permitted? BGP edge down?) | Batfish `compareFilters`, `differentialReachability` | high |
| **Rule-anomaly classification** — shadowing / correlation / generalization / redundancy / irrelevance | Al-Shaer & Hamed taxonomy (IEEE JSAC 2005); productized in Tufin/FireMon/PAN Policy Optimizer | high (academic) / medium (vendor) |
| **Overly-permissive / risk scoring + compliance drift** (PCI/NIST/ISO/HIPAA) | Tufin, FireMon Policy Analyzer | medium (vendor marketing) |
| **Change attribution (WHO/WHEN/HOW)** — correlate TACACS+ accounting + syslog change events; "Changed By" + source IP column; flag out-of-band changes | FortiOS 7.0.2+ TACACS+ accounting (login/config-change/cli-cmd audit), ManageEngine NCM | high (primary) |
| **Event-driven detect→pull→diff** — syslog/trap on change triggers immediate backup + baseline diff | SolarWinds NCM RTCD, ManageEngine NCM | high (primary) |
| **Structural (syntax-aware) diff UX** — suppress whitespace/reformatting noise, collapsible stanzas | difftastic (AST diff) | high (primary) |

**Refuted (do not claim):** Batfish `compareFilters` empty result is NOT a mathematical proof of
behavioral equivalence (1-2 vote). Don't market any diff as "proven equivalent."

## Prioritized roadmap

### P0 — Semantic / object-aware diff (highest leverage)
Parse FortiGate/PAN/ASA configs into an object model and render **per-object added/removed/modified**
instead of a line delta. We already have deep FortiGate config knowledge in `internal/configdiff`.
- New: `internal/configdiff/parse_fortigate.go` → `[]ConfigObject{Kind, Name, Path, Attrs}`
  (kinds: `firewall.policy`, `firewall.address`, `system.interface`, `router.static`, `vpn.ipsec`, `system.admin`, …).
- `DiffObjects(a, b)` → `[]ObjectChange{Kind, Name, Op: added|removed|modified, AttrDeltas}`.
- UI: group the diff by object, collapsible stanzas, show only changed attrs.
- Build in-house first (FortiGate dominates the fleet); Batfish integration is a later option,
  not a prerequisite (Java service + pybatfish is heavy for a Go stack).

### P0 — Risk / severity classification per change
Replace the always-`warning` alert with a classified one.
- `internal/configdiff/classify.go`: rules over `ObjectChange`s →
  `Severity{critical|high|medium|info}` + `Category`.
- Concrete auto-flags: policy action→accept with src/dst/service = ANY; policy disabled/deleted;
  admin added/password-related; weakened IPsec/SSL crypto (DH group, cipher); logging disabled;
  management-access (ping/https/ssh) opened on a WAN interface.
- Carry severity into the `CONFIG_CHANGE` alert + show a "security impact" summary line per change.

### P1 — Change attribution (WHO/WHEN/HOW)  [no TACACS+ — use native FortiGate config-change event log]
DECISION (2026-06-20): fleet has **no TACACS+**. Attribution comes from FortiGate's own
config-change event log, NOT accounting. Each event natively carries `user=`, `ui=GUI(<ip>)`/`ssh`/
`jsconsole`, `cfgpath=`, `cfgobj=`, and `cfgattr=` (old→new value). We already receive+store these
syslog messages but DO NOT parse the kv fields yet (`internal/syslog/syslog.go` only does RFC5424 +
device-id; zero `cfgpath`/`cfgattr` handling in repo).
- Add a FortiGate kv-field parser for config-change log events (extract user/ui/src-ip/cfgpath/cfgattr).
- Match events to a revision by `(device, timestamp window)`.
- Populate `DeviceConfigRevision.ChangedBy`, `ChangedFrom` (source IP), `ChangeMethod` (GUI/CLI/API).
- BONUS: `cfgattr` old→new gives a cheap per-attribute semantic diff for UI/CLI-originated changes,
  feeding P0 for free on those events.
- Out-of-band detection — see decision below.

### P1 — Event-driven detect→pull→diff
Trigger an immediate backup+diff from a FortiGate config-change syslog event instead of waiting for
the scheduled poll. Reuses the existing syslog pipeline + collector.

### P2 — Rule-anomaly analysis
On a policy change, run shadowing / redundancy / generalization checks across the rule set
(Al-Shaer & Hamed). Flag "new rule R is shadowed by rule N (never matches)".

### P2 — Compliance-drift mapping  [DEFERRED — design classifier to allow it later]
DECISION (2026-06-20): no official compliance framework needed yet. Do NOT build CIS/PCI/NIST
mapping now. BUT design the P0 risk classifier (`classify.go`) so a `ComplianceTags []string` field
and a pluggable rule pack can be added later without rework — keep rules data-driven, not hardcoded
into the alert path.

### P3 — Quality-of-life
Server-side diff caching/delta storage (stop re-diffing 10k-line configs in JS each open);
config rollback/restore-to-revision; change-velocity/anomaly trend; multi-device config compare.

## Decisions (2026-06-20)
1. Parser: **in-house** per-vendor object parser (FortiGate first). Batfish optional later, not a dep.
2. Attribution: **no TACACS+** — use FortiGate native config-change event log (`user`/`ui`/`cfgpath`/`cfgattr`).
3. Compliance: **deferred** — no framework needed yet; classifier must stay extensible for later add.
4. Out-of-band: **PENDING** — no confirmed ticketing/maintenance-window source. Default design =
   "flag every change for human confirmation"; escalate severity only when the FortiGate event log
   shows the change had NO associated authenticated admin session (i.e. changed outside the device's
   own UI/CLI/API — a possible direct/unexpected change). Revisit if a tickets/calendar source appears.

## Key sources
- Batfish drift/refactor notebooks + repo: https://github.com/batfish/batfish
- Al-Shaer & Hamed, firewall policy anomalies (IEEE JSAC 2005): https://rboutaba.cs.uwaterloo.ca/Papers/Journals/2005/Ehab05.pdf
- FortiGate TACACS+ accounting: https://community.fortinet.com/t5/FortiGate/Technical-Tip-FortiGate-TACACS-Accounting-messages/ta-p/193067
- SolarWinds NCM RTCD: https://documentation.solarwinds.com/en/success_center/ncm/content/ncm-enabling-real-time-configuration-change-detection.htm
- ManageEngine NCM change detection: https://www.manageengine.com/network-configuration-manager/help/change-detection-v12.html
- Tufin risk assessment / FireMon Policy Analyzer (vendor): https://www.tufin.com/solutions/compliance-risk/risk-assessment , https://www.firemon.com/solutions/policy-analyzer/
- difftastic (structural diff): https://github.com/Wilfred/difftastic
