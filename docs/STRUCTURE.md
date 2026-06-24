# Documentation Structure

> Mirror of this file in the collector: [xphox2/Firewall-Collector/docs/STRUCTURE.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/STRUCTURE.md).
> **This file is the canonical index.** The collector's STRUCTURE.md is
> a mirror so anyone reading either repo in isolation can navigate.

The Firewall-Monitoring project is split across two sibling repositories.
This is **not** a parent/child relationship — each repo is a standalone Go
module that builds and runs on its own, and the two are coupled only at
runtime (the collector talks HTTP to the server).

| Repo | Role | GitHub |
|---|---|---|
| **Firewall-Collector** (sibling) | Lightweight probe at a remote site. | [xphox2/Firewall-Collector](https://github.com/xphox2/Firewall-Collector) |
| **Firewall-Monitoring** (this repo) | Central server: stores data, renders dashboards, runs the alert engine, sends notifications, exposes the admin UI. | [xphox2/Firewall-Monitoring](https://github.com/xphox2/Firewall-Monitoring) |

## Which doc lives where

| Topic | Server (this repo) | Collector (mirror) |
|---|---|---|
| Index of where every topic lives | [STRUCTURE.md](STRUCTURE.md) (this file) | [STRUCTURE.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/STRUCTURE.md) |
| Combined architecture (data flow, sequence diagrams) | [**architecture.md**](architecture.md) (full) | [ARCHITECTURE.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/ARCHITECTURE.md) (collector-side view) |
| Feature inventory (website-ready) | [FEATURES.md](FEATURES.md) (server-side) | [FEATURES.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/FEATURES.md) (probe-side) |
| Version compatibility table | [**SUPPORT-MATRIX.md**](SUPPORT-MATRIX.md) (full) | [COMPATIBILITY.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/COMPATIBILITY.md) (1-pager) |
| Probe↔server wire format (`schema_version`) | [**MIGRATING.md**](../MIGRATING.md) | (see server's MIGRATING.md) |
| Environment variables | [config.env.example](../config.env.example) (this repo) | [ENV-VARS.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/ENV-VARS.md) (probe) |
| Operator runbook | [OPERATIONS.md](OPERATIONS.md) | n/a |
| Data retention / PII | [DATA-RETENTION.md](DATA-RETENTION.md) | n/a |
| TLS / probe-credential rotation | [CERT-ROTATION.md](CERT-ROTATION.md) | n/a |
| Custom SNMP vendor profile | [**custom-vendor.md**](custom-vendor.md) (full walkthrough) | [CUSTOM-VENDOR.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/CUSTOM-VENDOR.md) (collector-side) |
| FortiGate device setup (SNMP, syslog, SSH, TFTP) | [FORTIGATE-SNMP-SETUP.md](FORTIGATE-SNMP-SETUP.md) | [FORTIGATE-SETUP.md](https://github.com/xphox2/Firewall-Collector/blob/master/docs/FORTIGATE-SETUP.md) (collector-side) |
| Database migrations | [partition-migration.md](partition-migration.md) | n/a |
| Production-hardened nginx config | [nginx.conf](nginx.conf) | n/a |
| Production upgrade runbook | [OPERATIONS.md §Upgrade](OPERATIONS.md#upgrade) (the standalone `UPGRADE-2026-06.md` is archived under [archive/](archive/UPGRADE-2026-06.md)) | n/a |
| Pre-release security checklist | [OPERATIONS.md §Pre-release / deployment security checklist](OPERATIONS.md#pre-release--deployment-security-checklist) | n/a |
| Config-diff roadmap (NOC/SOC-grade design) | [config-diff-roadmap.md](config-diff-roadmap.md) | n/a |
| Audit log (170/170 findings resolved) | [AUDIT.md](AUDIT.md) | n/a |
| Living feature inventory & roadmap | [FEATURE-ROADMAP.md](FEATURE-ROADMAP.md) | n/a |
| Latest internal audit (2026-06-23, live) | [audit-2026-06-23-consolidated.md](audit-2026-06-23-consolidated.md) | n/a |
| Historical audit reports (point-in-time) | [audit-archive/](audit-archive/README.md) | n/a |

## Filename case convention (known inconsistency)

The collector standardized on **UPPERCASE** filenames in commit 1.2.107
(see `tasks/PLAN.md` for the rationale). The server has not yet had the
same sweep — three legacy files are still lowercase:

- `docs/architecture.md` (should be `ARCHITECTURE.md`)
- `docs/custom-vendor.md` (should be `CUSTOM-VENDOR.md`)
- `docs/partition-migration.md` (should be `PARTITION-MIGRATION.md`)

Renaming them is a separate PR — the shell-guard tests
(`TestArchitectureDiagram_AUDIT108`, `TestCustomVendorDoc_AUDIT170`,
`TestEnsurePartitions_SurfacesWarning_AUDIT146`) pin the lowercase
names and must be updated in the same change. **All new docs in this
repo ship in UPPERCASE** to match the collector's convention. Tracked
in [xphox2/Firewall-Collector/tasks/PLAN.md](https://github.com/xphox2/Firewall-Collector/blob/master/tasks/PLAN.md).
