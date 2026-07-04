<!-- Research input for the v0.11 Tranche 3 NetFlow v5/v9 + IPFIX implementation.
     Produced 2026-07-03 by a 13-agent research pass (6 dimensions, each with
     adversarial fact-checking against RFCs, the IANA IPFIX registry, and vendor
     docs). Section 1 corrections override anything contradicting them. -->

# Tranche 3 (NetFlow v5/v9 + IPFIX) — Final Research Report

Synthesis of 6 research dimensions + adversarial verification. Corrections in §1 **override** anything contradicting them in the raw findings.

---

## 1. Corrections (refuted claims — these override the raw findings)

### 1.1 FortiGate 7.6 sampled NetFlow: collector MUST multiply (highest-stakes correction)
Two dimensions drew **opposite** conclusions from the same Fortinet sentence ("The Netflow report includes rounded-up numbers of packets and bytes divided by the sampling rate"). Verification settled it: the doc's own worked example (rate=100, actual 8,820 bytes / 105 packets) shows the exported flowset carrying `Octets: 88, Packets: 1`, and Fortinet instructs "88 * 100 = 8800 Bytes … basically equal to the actual value." FortiGate tallies full session counters and **divides at export**; the exported numbers are sampled-scale, numerically equivalent to Cisco sampled NetFlow. **The collector must multiply by the sampling rate — same renormalization path as everything else.** Treating FortiGate counts as pre-normalized (as one dimension's IE notes recommended) would undercount by the rate (100x in the example). ([Fortinet 7.6 NetFlow sampling](https://docs.fortinet.com/document/fortigate/7.6.0/new-features/667577/netflow-sampling))

### 1.2 FortiGate does export IPFIX — from NP7 hyperscale CGN only
"FortiGate = v9 only, no IPFIX ever" is too strong. The kernel exporter (`config system netflow`) is v9-only (no version/format knob in the [7.6 CLI reference](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/105185180/config-system-netflow)), and the v1/v5/v9/IPFIX "format" knob belongs to managed-FortiSwitch flow-tracking. **But** NP7 hyperscale boxes (`config log npu-server`) export v9 **and** v10/IPFIX, hardware-generated, with distinct observation domain IDs per NP7 vs CPU, template 280, default port 2055. ([CGN field reference](https://docs.fortinet.com/document/fortigate/7.6.0/fortinet-carrier-grade-nat-field-reference-architecture-guide/811477/netflow-ipfix)) Docs entry: "FortiGate: NetFlow v9 (kernel); IPFIX possible from NP7 hyperscale CGN, on port 2055."

### 1.3 RFC 7011 UDP template rules: normative strengths corrected
- Template-ID reuse: "**MAY** be reused … after waiting at least 3 times the retransmission delay" — a MAY, not a MUST-form prohibition.
- Collector-side template expiry over UDP is **OPTIONAL** ("MAY associate a lifetime"; SHOULD default ≥ 3× observed retransmission rate).
- Confirmed verbatim: withdrawals **MUST NOT** be sent over UDP and MUST be ignored.
- Omitted MUSTs that matter to us: exporters MUST periodically retransmit templates, and on receiving a **different** template for an allocated ID the collector **MUST replace it in place, regardless of any timeout** — "the normal operation of Template ID reuse over UDP."
([RFC 7011 §8.4](https://www.rfc-editor.org/rfc/rfc7011#section-8.4))

### 1.4 goflow2 details corrected
- **Template/sampling store keying**: current main keys both stores as `{RouterKey, Version, ObsDomainID, TemplateID}` / `{RouterKey, Version, ObsDomainID}` — exporter identity is threaded *through* the decoder via `FlowContext` (RouterKey = source IP), not handled outside it. Stores have TTL, sweep, and JSON persistence. Confirmed: no FLOW_SAMPLER_ID(48)/selectorId(302) matching — single rate per exporter domain from IEs 305→50→34. ([goflow2 utils/store](https://github.com/netsampler/goflow2))
- **Drop samples**: goflow2 *decodes* sFlow `DropSample` (format 5) but its producer silently skips them — **not** an end-to-end drop-notification reference implementation.

### 1.5 FortiGate sampling/options/collectors corrected
- No documented option-template sampling export from FortiGate; the 7.6 doc shows a SamplerID inside data records only. Akvorado discussion [#1391](https://github.com/akvorado/akvorado/discussions/1391) shows the option data that does appear is inconsistent (options say SamplerID 255/interval 1; data records say SamplerID 0). **Plan for per-exporter configured rate, verify against lab pcaps; do not assume 48/49/50 or 302/304/305/306 arrive.**
- Multiple collectors: introduced in FortiOS **7.2.8 / 7.4.2** (not "7.x" generally), max 6, CLI-only `config collectors`. ([Fortinet new-feature doc](https://docs.fortinet.com/document/fortigate/7.4.0/new-features/840728/allow-multiple-netflow-collectors-7-4-2))
- template-tx-timeout default 1800 s / template-tx-counter default 20 confirmed.

### 1.6 MikroTik little-endian sampling bug: fixed in ROS 7.10
The RouterOS 6.49.x little-endian v9 samplingInterval bug is real ([fastnetmon #985](https://github.com/pavel-odintsov/fastnetmon/issues/985)), but its 7.x status is **not** unknown — a ROS 7.10 pcap in the same thread decodes correctly, and Akvorado closed [#417](https://github.com/akvorado/akvorado/issues/417) as fixed. Guidance from both projects: **do not auto-byte-swap** (65536 vs 256 is ambiguous) — use a per-exporter override/default rate instead. Also: MikroTik delivers IE 34 **in data records**, not options templates ([goflow2 #113](https://github.com/netsampler/goflow2/issues/113)), so the sampler cache must also learn from data-record IE 34.

### 1.7 UniFi export corrected
UniFi Network 8.5.6+ NetFlow export is **version-selectable (v5/v9/IPFIX)** with configurable sampling **including Off** — not "IPFIX-only, always sampled." Exclusion on UniFi Express and UXG-Lite confirmed; the newer Traffic Flows feature excludes more models (UDR, UDM, UCG-Ultra…). ([release notes](https://community.ui.com/releases/UniFi-Network-Application-8-5-6/bfa15dd8-8b58-4d40-9d83-73ebe8c9a955))

### 1.8 Smaller corrections
- **FortiGate CGN template 280 field IDs**: Fortinet documents names only. natType = IANA IE 297 (unsigned8 — **not** a varlen string); "FLOW_EXPORTER" is Cisco's v9 name for field 144 (IANA 144 = exportingProcessId); OUT_BYTES/OUT_PKTS = IANA 23/24 postOctet/postPacketDeltaCount. Actual IDs/lengths must be learned from the wire template. ([IANA registry](https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv))
- **Akvorado alerting evidence**: correct supporting issues are [#53 (DDoS detection)](https://github.com/akvorado/akvorado) and #118 (forecast); #1895 is a Grafana-plugin issue, unrelated. Substance stands: Akvorado ships no alerting/forecasting/detection.
- **IPFIX sequence semantics of real firewalls**: unverifiable — no vendor documents it. Implement `expectedNext = prevSeq + prevMsgDataRecordCount`, but treat mismatch as **resync + metric**, never authoritative loss (nfdump's approach).
- **Plain-Postgres framing**: Timescale's own benchmark shows vanilla PG ingest collapsing around ~50M rows, not "billions"; all rows/s figures are vendor-blog directional numbers.
- **fps-per-Gbps "1,000–5,000"**: unsupported; real data spans ~200–5,000+ fps/Gbps depending on flow-size mix ([Kentik KB](https://kb.kentik.com/v0/Fc06.htm)). Size from *measured* per-exporter fps. Storage: use ~2 GB/1,000 fps/day (Cisco SNA documents 1.85 GB — [Data Store guide](https://www.cisco.com/c/dam/en/us/products/collateral/security/stealthwatch/stealthwatch-data-store-guide.pdf)).
- **ASA packet counters**: Cisco's NSEL field table has **no packet-counter fields** — byte deltas (231/232) only; packet accounting from ASA is impossible (nfdump's 298/299 handling covers other NSEL-like exporters, not ASA's documented templates). Also flow-**create and flow-denied** templates carry no byte counters at all; 231/232 appear only in teardown/update ([Cisco ASA NetFlow guide](https://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/asa_netflow.html)).

---

## 2. Tranche 3 plan deltas (must-fix)

### 2.1 Schema: one migration, decided now (flow_samples is partitioned — we get one cheap shot)
Add in the **same** tranche-3 migration:

| Column | Source | Why now |
|---|---|---|
| `flow_start`, `flow_end` (or `flow_start` + `duration_ms`) | IEs 152/153, 150/151, 154–157, 21/22+header math, 158/159, 323+161 | NetFlow records are interval aggregates (up to 30-min active timeout). One-instant attribution corrupts every bandwidth chart/z-score. Single biggest semantic difference from sFlow. |
| `firewall_event` (smallint) | IE 233 (0 ignore/1 created/2 deleted/3 denied/4 alert/5 update) | Denied-flow visibility = the #1 NetFlow-over-sFlow win. PAN-OS + ASA both send it. |
| `flow_end_reason` (smallint) | IE 136 (2 = active timeout → flow continues) | Required for stitching + dedup; FortiGate 258/259 send it free. |
| `post_nat_src_addr`, `post_nat_dst_addr`, `post_nat_src_port`, `post_nat_dst_port` | IEs 225–228, 281/282 (v6), ASA legacy 40001–40004 aliases | All real firewall NAT traffic; needed for pre/post-NAT correlation and future sFlow↔NetFlow matching. |
| `icmp_type_code` (or convention: decode into type/code, zero ports) | IE 32 (=type×256+code), 139 v6, 176–179 | See 2.4. |
| `tos` (1 byte) + `src_vlan`/`dst_vlan` | IE 5; IEs 58/59 (+ sFlow extended_switch later) | Cheap; avoids a second partitioned-table migration. |
| exporter app string (e.g. `app_name`) | PAN 56701; FortiGate applicationId 95 + options template 257 | Precedence rule: exporter app > port heuristic. |

Records with `firewallEvent`/`natEvent` present and **no byte counters** (ASA create/denied, RFC 8158 NAT event logs, FortiGate CGN natEvent=4 create) are **events, not flows** — either skip with a counter, or insert flagged with bytes=0 explicitly allowed. **Ingest validation must not reject zero-byte flows** — denied flows are the point. ([RFC 8158 §4.2](https://www.rfc-editor.org/rfc/rfc8158))

### 2.2 Counter mapping: three families, per-record fallback chain
1. IN_BYTES(1)/IN_PKTS(2) — accept lengths 1/2/4/8 generically (v9 fields "can be 8 on core routers", [RFC 3954 §8](https://www.ietf.org/rfc/rfc3954.txt); IPFIX reduced-size encoding, [RFC 7011 §6.2](https://www.rfc-editor.org/rfc/rfc7011.html)).
2. OUT_BYTES(23)/OUT_PKTS(24) — FortiGate per-session reverse counters → feeds biflow reverse-record emission.
3. initiatorOctets(231)/responderOctets(232) — **ASA sends ONLY these** (no IE 1/23 anywhere in its templates). A field-1-only mapper shows zero bytes for every ASA (pmacct hit exactly this: [#502](https://github.com/pmacct/pmacct/issues/502)).
4. 85/86 (octetTotalCount/packetTotalCount) are running totals since metering-process init — if ever encountered, difference per flow key or treat as final-record-only; never sum like deltas ([RFC 5153 §4.3](https://www.rfc-editor.org/rfc/rfc5153)).

**Biflow reverse-record emission** must normalize three encodings to the same output pair: PEN-29305 reverse IEs (IPFIX, [RFC 5103 §6.1](https://www.rfc-editor.org/rfc/rfc5103.html)), OUT_BYTES/OUT_PKTS (v9 FortiGate), initiator/responder (ASA). Emit the reverse row (swap addrs/ports/ifindexes, invert direction) only when the reverse counter > 0; drop records containing only reverse IEs.

### 2.3 Sampler cache: full nfdump-style resolution chain
Per (exporter IP, ODID/sourceID), resolve in order:
1. Operator **override** (Akvorado `override-sampling-rate` pattern);
2. Per-sampler-ID match — record's FLOW_SAMPLER_ID(48)/selectorId(302) against cached sampler options (Cisco runs per-interface samplers);
3. Generic options rate — 305(+306: multiplier = (interval+space)/interval), then 50, then 34 (including **IE 34 arriving in data records** — MikroTik);
4. Configured per-exporter/subnet **default** (Akvorado `default-sampling-rate`);
5. Global default **1** — firewalls (PAN-OS, ASA, pre-7.6 FortiGate) are unsampled and often never send sampler options; Akvorado rejects PAN flows for exactly this ([discussion #1453](https://github.com/akvorado/akvorado/discussions/1453)). **Never drop flows waiting for an options template that will never come.**

v5: mask `interval = raw & 0x3FFF` (top 2 bits are mode) before multiplying. FortiGate 7.6 sampled exports: **multiply** (correction 1.1). MikroTik ROS6: don't auto-swap; document override. Log/metric on mid-stream rate changes (bytes are pre-multiplied at ingest, so a stale rate mis-scales permanently).

### 2.4 ICMP
For protocol 1/58: decode IE 32/139 (type×256+code; Cisco also mirrors it into L4_DST_PORT — nfdump normalizes by moving/zeroing ports) into type/code, **zero the port columns**, and apply the *same* convention to the sFlow parser (which currently ignores ICMP entirely) so filters/app-classification behave identically across protocols. FortiGate has dedicated ICMP templates 260/261/266–269.

### 2.5 Timestamps
One `resolveFlowTimes()` with priority: 152/153 > 150/151 > 154–157 (**64-bit NTP format**: seconds since 1900 + 2⁻³² fraction; subtract 2208988800; era-disambiguate vs export time; micro: ignore bottom 11 fraction bits — [RFC 7011 §6.1.7–6.1.10](https://www.rfc-editor.org/rfc/rfc7011.html)) > 21/22 via wrap-safe unsigned math `offset = (uint32)sysUptime - (uint32)val; msec = exportTimeMs - offset` (nfdump) > 158/159 delta-µs from export time > 323 observationTimeMilliseconds + 161 duration (FortiGate CGN 280, ASA event time). v5: nfdump's exact wrap corrections (First>Last → start −2³²ms; Last>SysUptime by >100,000ms → both −2³²ms; guards Cisco bug CSCei12353 — [netflow_v5_v7.c](https://github.com/phaag/nfdump/blob/master/src/netflow/netflow_v5_v7.c)).

Hardening (real-world exporters are broken): plausibility-clamp derived times against receive time (softflowd puts uptime in the v9 header export-time field, [#37](https://github.com/irino/softflowd/issues/37); Catalyst 3850 emits 1970 epochs; Nexus fills 21/22 with sysUptime/1000). Track per-exporter clock skew (receive time − header export time) as a gauge. PAN-OS and FortiGate v9 both use 21/22, so uptime math is the **hot path**.

### 2.6 Template engine
- **Key**: (listener, exporter IP [+source port for IPFIX session semantics], v9 sourceID / IPFIX ODID, protocol version, template ID). Multi-VDOM FortiGates, ASA contexts, NP7 CPU-vs-NP domains all multiplex one source IP.
- **Two framing loops**: IPFIX trusts header Length + Set lengths (16-B header); v9 walks FlowSet lengths only — the header Count field is ambiguous in the wild, sanity-hint only ([RFC 5153 §10.1](https://www.rfc-editor.org/rfc/rfc5153)).
- **Set IDs**: v9 0/1 vs IPFIX 2/3 for template/options-template; ≥256 data. Version-keyed.
- **Options templates cannot share a parse path**: v9 scope/option lengths are **bytes**; IPFIX carries field **counts** ([RFC 3954 §6.1](https://www.ietf.org/rfc/rfc3954.txt) vs RFC 7011 §3.4.2.2). Getting this wrong silently corrupts sampler tables.
- **Varlen (IPFIX)**: template length 0xFFFF → 1-byte actual length; first byte 255 → 2-byte BE length; prefix excluded from IE length. Required for PAN App-ID/User-ID strings and to transparently skip RFC 6313 structured data (291/292/293 — recognized-but-opaque is sufficient for tranche 3).
- **Enterprise bit (IPFIX)**: bit 15 + 4-byte PEN; key entries as (PEN, elementID, length). PEN 29305 = reverse IEs; 25461 = PAN; 12356 = Fortinet. v9 has no PEN — carry vendor-squatted raw IDs (56701/56702, 33000–40004) in the mapping table.
- **Withdrawal records** (fieldCount==0, ID 2/3 = withdraw-all): log-and-ignore over UDP, but **parse them** — otherwise they corrupt set iteration or register zero-length templates (infinite record loop).
- **Redefinition**: atomic in-place replace, always (RFC 7011 mandate — correction 1.3). **Expiry**: TTL ≥ 30 min (PAN refresh default 30 min/20 records; FortiGate 1800 s).
- **Sanity-validate field lengths at registration**: FortiGate FGT1000D shipped length-9 integers that inflated nfdump counters exactly 69× ([nfdump #77](https://github.com/phaag/nfdump/issues/77)). Quarantine weird templates with a metric; unknown IEs = opaque skip-by-length, never template rejection ([RFC 5153 §5.1](https://www.rfc-editor.org/rfc/rfc5153)).
- **Padding**: stop the data-record loop when remaining < template min record length (both protocols), else trailing zeros become 0.0.0.0→0.0.0.0 phantom flows.
- **Persistence**: persist template+sampler caches to disk across collector restarts (goflow2 pattern); otherwise a restart blinds us up to 30 min per exporter. Docs: recommend lowering FortiGate `template-tx-timeout`.
- **Data-before-template**: count a metric and keep processing the rest of the packet (goflow2 pattern); normal after restart, never per-packet error logs.

### 2.7 Sequence-loss accounting
Per (exporter IP, ODID/sourceID — or v5 engine_type/engine_id, version) tracker in the collector, with version-specific expected deltas: **v5 = +record count; v9 = +1 per export packet; IPFIX = +data-record count (templates excluded)** ([RFC 3954 §5.1](https://www.ietf.org/rfc/rfc3954.txt), [RFC 7011 §3.1](https://www.rfc-editor.org/rfc/rfc7011.html)). Reboot-aware (large backward jump + sysUptime reset → resync, not loss — libfixbuf pattern, [fixbuf v9 docs](https://tools.netsa.cert.org/fixbuf/libfixbuf/v9.html)). Mismatch = resync + metric, never authoritative. The per-record `sequence_number` column cannot express this; surface as "X% export loss from device Y."

### 2.8 Dedup policy scoping
- **Per-device source preference, not record matching.** Sampled stateless sFlow vs stateful session aggregates are not comparable record-for-record; Plixer documents cross-exporter v9 dedup as generally infeasible ([Plixer blog](https://www.plixer.com/blog/netflow-deduplication-flow-deduplication/)). Only FortiGate and VyOS among our target vendors can dual-export at all.
- Default for vendor=fortigate: **prefer NetFlow, sFlow as failover** — Fortinet's own guidance, since sFlow disables all NP7/NP6 offload on the interface while NetFlow doesn't ([hardware-acceleration doc](https://docs.fortinet.com/document/fortigate/7.6.2/hardware-acceleration/631057/sflow-and-netflow-and-hardware-acceleration)).
- **Same-exporter double-metering**: one exporter metering ingress AND egress doubles every byte. Use direction (IE 61) / in-out ifIndex to count once, or document a per-device direction policy.
- **NSEL update/teardown reconciliation**: flow-updates carry interval deltas; teardown byte fields cover the flow — summing both double-counts ([Plixer on ASA refresh-interval](https://www.plixer.com/blog/cisco-asa-netflow-flow-export-active-refresh-interval-problems/)). Explicit, tested decision: teardown-only ingestion (simplest, accurate totals, bursty timing) for tranche 3; update-accumulate-subtract as a tranche-4 refinement.

### 2.9 Enrichment parity + observability
- NetFlow/IPFIX rows go through the **same** server enrichment (app_category, GeoIP/ASN, threat_flag, direction) as sFlow; exporter-provided direction (IE 61) and app strings override heuristics when present. IPv6 end-to-end (PAN 258–263, FortiGate 259) verified through decode → enrichment → UI.
- Staged per-exporter counters (Akvorado pattern): UDP received → decoded → normalized → relayed, decode errors by class, records-dropped-awaiting-template, template churn, templates-cached gauge, sampling-rate-missing state, clock-skew gauge ([Akvorado troubleshooting](https://raw.githubusercontent.com/akvorado/akvorado/main/console/data/docs/05-troubleshooting.md), [goflow2 metrics](https://github.com/netsampler/goflow2)).

### 2.10 SUPPORT-MATRIX doc (write during tranche 3 — the research is done)
Per-vendor operator guidance: FortiGate "use NetFlow; sFlow disables NPU offload; lower template-tx-timeout; expect up to 30-min template wait"; pfSense CE "use softflowd IPFIX mode, not v9 (timestamp bugs)"; Sophos "v5 = no IPv6"; MikroTik "fasttrack/HW-offloaded traffic invisible to traffic-flow"; UniFi "not on Express/UXG-Lite."

---

## 3. Tranche 3 nice-to-haves (cheap while we're in the code)

1. **Template debug endpoint/admin page** — per exporter: template IDs, field lists, age, refresh count; plus a short live decoded-flow tail. Template problems are THE v9/IPFIX support burden (Akvorado/Scrutinizer both expose this).
2. **Kernel UDP drop metrics per listening socket** (Akvorado `in_dropped_packets_total` pattern) + receive-buffer sizing docs — silent kernel drops are the #1 "numbers don't match interface counters" cause.
3. **Unknown-exporter approval UX** — pending-exporters table (src IP, ODID, version, record rate, first/last seen) with bind-to-device/ignore; include "agent ID ≠ source IP" and "options-only exporter" diagnostics. Nobody in open source does this well (SolarWinds-style auto-add is the commercial bar).
4. **PAN App-ID/User-ID + FortiGate APP_ID_OPTIONS (template 257) decoding** — vendor L7 truth into `app_category`; needs only the varlen/options plumbing built anyway.
5. **goflow2-style config-driven vendor-IE mapping table** (PEN+ID → column) instead of hardcoded per-vendor parsing — future-proofs against the next vendor without decoder changes.
6. **sFlow fixes while touching shared emission code**: fix the emission gate (`seqNum > 0` currently emits address-less garbage rows for agents sending sampled_ipv4-only — sflow.go:510); fix the wrong "per-sample delta" `drops` comments (spec: cumulative since agent reset — [sflow_version_5.txt](https://sflow.org/sflow_version_5.txt); server delta logic is correct, comments would mislead a refactorer); capture sub_agent_id instead of discarding it (it's the sFlow analogue of ODID).
7. **Datagram tee/replication** to a downstream collector (pmacct pattern) — removes the "I can't repoint my only NetFlow export" trial blocker; tiny UDP re-emit.

---

## 4. Tranche 4 + later backlog (prioritized)

Each item: [competitive bar] + (Tranche-3 data it needs — verify we don't strand it).

**Tranche 4 (detection + reconciliation):**
1. **Detection gating by completeness** [FastNetMon docs the rule: flows/s thresholds invalid under sampling] — needs per-source sampled-vs-complete flag (sampling_rate==1 session export vs sampled). Every detector declares its validity class. ([FastNetMon thresholds](https://fastnetmon.com/docs-fnm-advanced/fastnetmon-threshold-types/))
2. **Volumetric DDoS / entropy / carpet-bombing** [FastNetMon, Kentik] — per-host bps/pps/fps OR-thresholds + per-prefix (site/subnet) rollups (carpet bombing is invisible per-host); entropy survives sampling ([Brauckhoff IMC 2006](https://dl.acm.org/doi/10.1145/1177080.1177101)). Needs: flow_start/end for rate math, prefix groups from sites, reuse F17 z-score.
3. **Denied-flow / firewallEvent detection** [nfdump NSEL; no OSS competitor integrates with alerting] — deny storms, denied-then-allowed. Needs: `firewall_event` column (T3), existing alert stack.
4. **Flow stitching across active-timeout splits** [Stealthwatch] — 5-tuple continuation merge keyed on flowEndReason==2. Needs: `flow_end_reason` + flow_start/end (T3). Prerequisite for beaconing/exfil/cryptomining.
5. **Beaconing detector (RITA model)** [RITA/AC-Hunter] — Bowley skew + MADM of inter-arrival intervals + byte-size dispersion per src-dst pair; complete-NetFlow-only. Needs: flow timestamps, stitching, completeness flag. (Note: current RITA v5 adds 24h-histogram and duration subscores.)
6. **DNS-tunneling detector** [Stealthwatch/academia] — per-host port-53 bytes/packets/flow baselines + F17 z-score; complete-only.
7. **NSEL update-accumulate reconciliation** (upgrade from teardown-only) + NAT-event routing to a dedicated table [nfdump NEL].
8. **Interface-utilization-% from flows** [Akvorado's `%` Y-axis unit] — join flows to SNMP-polled ifSpeed we already have; "link is 83% full and here's who."
9. **Per-exporter sampling-rate-change staleness policy** (TTL + alert on change) — protects the pre-multiplied bytes contract.

**Later:**
10. **Exfil/data-hoarding staged detector + lateral-movement first-seen edge store** [Stealthwatch] — new persistent host-pair schema; scope early, ship later. Needs direction + bytes (have) + completeness flag (T3).
11. **Rollup ladder + retention defaults** [Akvorado: raw 15d / 1m 1w / 5m 3mo / 1h 1y; Noction 1/5/10-min tiers] — see §6; fold into Tranche 12 F79 (30d raw default, ~15-min rollups kept ~1 year).
12. **Visualization parity** [Akvorado] — top-K with "Other" bucket, bidirectional negative-axis charts, previous-period overlay, limitType=max burst hunting, Sankey.
13. **sFlow expansion (R2–R6 alignment)** — sampled_ipv4/6/ethernet fallback, extended_switch/router, fragment-offset check, discarded_packet samples (format 5, 304 reason codes; goflow2 does NOT do this end-to-end — open field), processor counters (SNMP-free FortiGate CPU/mem — our documented host-restriction pain), port_name, tunnel/VNI structures.
14. **BGP/BMP enrichment, tunnel decapsulation, TCP/TLS IPFIX transport** [Akvorado/pmacct/YAF] — ISP-grade; keep the receiver structured so a TCP listener is addable; SCTP skip is safe (every firewall vendor surveyed exports UDP).

---

## 5. Vendor support matrix (for docs)

| Vendor | Protocols | Sampling | Key quirks | Dual-export (dedup applies?) |
|---|---|---|---|---|
| **FortiGate** (kernel) | NetFlow v9 (port 2055) + sFlow v5 (6343) | Unsampled session-based <7.6; 7.6+ `netflow-sample-rate` — exported counters are sampled-scale, **multiply by rate**; sFlow default 1:2000 | Templates 256–269 (options 256/257, NAT/AF/ICMP variants); OUT_BYTES/OUT_PKTS per session (biflow); applicationId 95, flowEndReason 136; template-tx-timeout default 1800 s; sampler options inconsistent (SamplerID mismatch); historical length-9 field bug (69×); sFlow kills NPU offload; timeouts changed minutes→seconds across FortiOS versions | **YES — primary dedup vendor.** Prefer NetFlow, sFlow failover |
| **FortiGate NP7 CGN** | NetFlow v9 **or IPFIX** (2055/9555/9025/9026) | Unsampled | Template 280 (natEvent 4/5, post-NAT 225–228, obsTime 323 + duration 161, bidirectional counters); distinct ODIDs per NP7 vs CPU; natEvent=4 create records ≈ no counters | Counts as same device as kernel exporter — multi-ODID handling required |
| **Palo Alto PAN-OS** | NetFlow v9 only (no IPFIX, no sFlow) | **Never sampled**; no sampler options → default rate 1 | Fixed templates 256–263; unidirectional; App-ID 56701 (≤32B str) / User-ID 56702 (≤64B str) gated by field 346=PEN 25461 (raw v9 IDs, no enterprise bit); direction IE 61; flowId 148; timestamps via 21/22 (uptime math); refresh 30 min/20 records; MGT-interface restriction on large chassis | No |
| **Cisco ASA/FTD (NSEL)** | NetFlow v9 transport, event-driven | Never sampled | Bytes ONLY in 231/232 (no IE 1/23); **no packet counters at all**; create/denied records have no counters; update+teardown double-count trap; bidirectional single records; no ToS/TCP-flags; xlate 225–228 (40001–40004 pre-9.x); events via 233/33002; absolute msec times | No |
| **pfSense** | Plus 24.03+: native pflow **v5 + IPFIX only (no v9)**; CE: softflowd v5/v9/IPFIX | Unsampled | Plus IPFIX includes RFC 8158 NAT44 fields; up to 16 exporters; softflowd v9 has documented timestamp bugs → recommend IPFIX mode | No |
| **OPNsense** | NetFlow v5/v9 (no IPFIX) | Unsampled | v5 = no IPv6; egress-only default; flowd-based local Insight | No |
| **MikroTik** | v1/v5/v9/IPFIX | Sampling ROS 7+ only | ROS 6.49.x little-endian rate bug (fixed 7.10; use override, don't auto-swap); IE 34 in **data records**; v5 AS fields unpopulated; fasttrack/HW-offload traffic invisible | No |
| **Juniper SRX** | J-Flow v9 or IPFIX (IPFIX 19.4R1+/20.1R1 branch); no sFlow on SRX | Sampled (rate via options) | One template per inet family per service instance; legacy v5 via forwarding-options | No |
| **Sophos XG/XGS** | NetFlow **v5 only** | Unsampled | IPv4 only — no IPv6 visibility (vendor limit, not our bug); CLI-only config | No |
| **WatchGuard Firebox** | v5 + v9 (12.3+) | Optional 1-in-n random | v9 needed for IPv6 + post-NAT "X-Src/X-Dst" (12.7.1+, IE 225/226 family); ingress-only default; BOVPN-virtual excluded; throughput warning | No |
| **Ubiquiti EdgeOS** | v1/v5(default)/v9/IPFIX | Optional | Per-interface, optional egress | No |
| **UniFi gateways** | v5/v9/IPFIX (Network 8.5.6+), selectable | Configurable incl. Off | Not on Express/UXG-Lite; Traffic Flows excludes more models | No |
| **VyOS** | NetFlow v5/v9(default)/IPFIX + sFlow (hsflowd, 1.4+) | Both configurable | pmacct/uacctd-based NetFlow is CPU-heavy; VyOS recommends sFlow for high-pps | **YES — second dedup vendor** |

Dedup scenario is effectively a **FortiGate + VyOS feature**; everything else is single-protocol.

---

## 6. Postgres ceiling note

**Where we are safe.** All figures are vendor-blog directional (verified as such): TimescaleDB peaks ~1.2M rows/s in TSBS-style batch ingest; vanilla PG ingest degrades from ~tens of millions of rows in-table (~50M in Timescale's own benchmark, **not** billions) without partitioning ([Timescale comparison](https://github.com/timescale/docs.timescale.com-content/blob/master/introduction/timescaledb-vs-postgres.md), [QuestDB TSBS](https://questdb.com/blog/timescaledb-vs-questdb-comparison/)). With our monthly-partitioned flow_samples + batched COPY, a realistic single-node comfort zone is **~5–50k flow rows/s sustained** — comfortably above any firewall fleet we target: fps-per-Gbps varies ~200–5,000 with traffic mix (do **not** hardcode; measure per exporter — [Kentik KB](https://kb.kentik.com/v0/Fc06.htm)), so even a handful of busy 1-Gbps FortiGates with unsampled session export lands in the low thousands of fps.

**Storage is the earlier ceiling than ingest.** Plan with ~2 GB/1,000 fps/day (Cisco SNA documents 1.85 GB/1,000 FPS/day — [Data Store guide](https://www.cisco.com/c/dam/en/us/products/collateral/security/stealthwatch/stealthwatch-data-store-guide.pdf)); a 2,500-fps site ≈ 5 GB/day ≈ 150 GB/month per partition. Query pain (top-K over weeks of raw rows) will arrive before insert pain.

**Triggers for the rollup conversation (do this before any ClickHouse talk):**
- sustained aggregate ingest approaching ~10–20k fps, or
- raw retention needs beyond ~30 days at >2,500 fps, or
- top-K dashboard queries over >7-day windows exceeding interactive latency.

**Mitigations, in order:**
1. **Rollup ladder** (the pattern every scalable product converges on — Akvorado raw 15d / 1m 1w / 5m 3mo / 1h 1y; Noction 1/5/10-min tiers; Plixer SAF summaries): 5m/1h aggregate tables keyed by device/interface/app/country/ASN with **no IPs**, filled by the existing batcher, query planner picks coarsest sufficient table. Fits our partition + batcher architecture; fold into Tranche 12 F79.
2. Defaults: 30d raw retention env var (industry norm — [Broadcom NFA](https://techdocs.broadcom.com/us/en/ca-enterprise-software/it-operations-management/network-flow-analysis/23-3/managing/maintenance-and-data-collection/data-retention.html)), partition-drop pruning, per-exporter fps dashboard with projected DB growth (prevents a flow_samples rerun of the syslog_messages bloat incident).
3. Explicitly **avoid** SolarWinds-style silent top-talker truncation (documented user pain — [NTA doc](https://documentation.solarwinds.com/en/success_center/nta/content/nta-configuring-the-nta-top-talker-optimization-sw343.htm)); our pitch is honest full-fidelity raw window + declared rollups.
4. ClickHouse (or Timescale) becomes a real conversation only at sustained **>50k fps or multi-month raw-retention requirements** — an escape hatch, not a Tranche 3 concern. Benchmark on our actual schema before deciding; all published numbers are hardware/batch/cardinality-dependent.

---

### Top 5 things that would have shipped broken without this research
1. FortiGate 7.6 sampled counters not re-multiplied (N× undercount) — after one dimension confidently concluded the opposite.
2. ASA showing zero bytes forever (field-1-only mapper) and denied flows rejected by bytes>0 validation.
3. Single `timestamp` column stranding every duration-aggregate record (unfixable later without a second partitioned-table migration).
4. v9 options templates parsed with IPFIX count semantics (bytes vs counts) silently corrupting sampler tables.
5. Sequence-loss metrics keyed on exporter IP alone, false-alarming on every multi-VDOM/multi-ODID device and every reboot.
