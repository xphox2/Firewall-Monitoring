# Audit 2026-08-27 Remediation Program (AUDIT-171..318)

Plan: ~/.claude/plans/please-start-planning-a-curried-sprout.md
Per-PR loop: verify (refute-by-default) → fix → fable review of diff → QA gates → changelog+version → PR → auto-merge → next.

## Stage A — HIGH
- [x] Batch 1 (Server 0.11.211): startup/deploy — 171, 173, 183, 190, 310 — ALL CONFIRMED+FIXED; fable review SOUND (after: force-add gitignored test, doc/NOTICE polish, single env read); PR #219 open, background CI watch → merge
- [ ] Batch 2 (Collector 1.3.35): CI pinning — 178, 224, 226 CONFIRMED+FIXED, 309 ALREADY-RESOLVED; fable SOUND (after queue.go doc + permissions-guard hardening); PR #99 open, watch-merge running. Bonus real fixes: 3× 0o750 dirs, 2× ineffective //nolint:gosec → #nosec G402, #nosec G404 jitter. internal/shell convention established in collector.
- [x] Batch 3 (Collector 1.3.37): relay durability — MERGED PR #101 (2 review rounds; round 1 caught an introduced Drain loss path + vacuous replay test; final SOUND). Superseded teammate PR #100 en route.
- [x] RELEASE AUTOMATION (user-directed): server PR #221 (v0.11.213) + collector PR #102 (v1.3.38) MERGED; both workflows fired live (auto-released v0.11.213, v1.3.38); backfills v0.11.211/v1.3.35/v1.3.37. technicallabs.org resolves.
- [x] Batch 4 (Server 0.11.214): MERGED PR #222 + auto-released (3 review rounds; HIGH empty-window-crawl caught pre-merge; fleet dup-index drop w/ attach-safe probe; ancient-timestamp clamp; changelog-stacking conflict vs #220/#221 resolved via merge 9bc5dbe). Master CI watch running.
- [~] Batch 5 (Collector 1.3.39): implementation agent running (FortiGate SD-WAN OIDs + full-suffix row keys, dialup vdom fix, rangeToCIDR spaced ranges, voltage V, SSH uptime+TX parsing incl. real netlink format, fixture suite T1-T8).
- [ ] Batch 4 (Server **0.11.214** — renumbered twice; .212=teammate docs, .213=release-automation PR #221): data pipeline — 174, 188, 203, 204 IMPLEMENTED (cd020ed, pushed; all three GROUP-BYs window-walked; threat-feed heartbeat masking fixed alongside; SQLite zone trap caught by own tests). Fable review in flight.
- [ ] INTERJECTED (user): release versions — DONE: v0.11.211 + v1.3.35 releases live (backfill); PR #221 release-tag workflow (v0.11.213, supersedes #220) watch-merging; collector workflow = v1.3.38 after Batch 3 merges.
- [ ] Batch 5 (Collector 1.3.37): FortiGate SNMP/SSH + tests — 177, 217, 218, 219, 222, 299, 300, 303
- [ ] Batch 6 (Server 0.11.213): serverhealth tests — 176
- [ ] CHECKPOINT: deploy + live-verify rust-01

## Stage B — Security
- [ ] Batch 7 (Server): auth + public-API gating — 192, 194, 195, 199, 249, 252, 260, 262
- [ ] Batch 8 (Server): XSS + masking + ingest caps — 184, 200, 272, 311, 312
- [ ] Batch 9 (Collector): ingest attribution (STRICT) + hardening — 186, 187, 216, 237, 263, 282, 283, 284, 305, 306, 307, 317

## Stage C — Correctness
- [ ] Batch 10 (Server): alerts + notifier — 172, 189, 191(*int), 208, 209, 243, 244, 245, 246, 247, 248, 250, 285
- [ ] Batch 11 (Server): probe-ingest contract — 196, 253(all 11 sites), 254, 255
- [ ] Batch 12 (Server): read-path robustness — 193, 197, 251, 256, 257, 258, 259, 261, 270
- [ ] Batch 13 (Server): SNMP twin parity + trap receiver — 296, 239, 297, 301, 302-server
- [ ] Batch 14 (Server): query performance — 198, 201, 202, 266, 269
- [ ] Batch 15 (Collector→Server pair): uptime units — 220, 231
- [ ] Batch 16 (Collector): SNMP misc + observability — 210, 221, 223, 238, 293, 294, 295, 298, 302-collector
- [ ] Batch 17 (Server): IRC — 205, 206, 278, 314, 315
- [ ] Batch 18 (Server): frontend — 185, 229, 230, 232, 233, 234, 235
- [ ] Batch 19 (Server): IPSec validation — 274, 275, 276, 277, 313
- [ ] Batch 20 (Server): reports + data-integrity misc — 207, 215, 264, 265, 273, 279, 280, 281, 290, 291
- [ ] Batch 21 (Server): dead code + uptime wiring — 182, 267, 268, 286, 292, 304, 316, 318(wire)

## Stage D — Contract + docs
- [ ] Batch 22 (Server): relay DTO sync — 211
- [ ] Batch 23 (Collector): docs close-out — 180, 225, 236, 241, 242, 181-coll + resolution appendix
- [ ] Batch 24 (Server): docs + tracker close-out — 179, 181, 227, 228, 240, 271, 308 + resolution appendix
- [ ] FINAL: deploy both, live-verify, update memory

## Decisions
- AUDIT-318: WIRE the uptime tracker (user-approved)
- AUDIT-186/187: STRICT source binding now (user-approved)

## Per-finding outcomes
(recorded per batch as verification completes: CONFIRMED / ALREADY-RESOLVED / REFUTED)

### Batch 5 (verification done — NOT yet implemented; queue after Batch 4)
- ALL 8 CONFIRMED. AUDIT-177: OIDs → `...4.9.2.1.{2,4,5,7,8,14}` + NEW `.9` PktLoss const (high conf on columns; the `.2.1` insertion is certain). MUST key healthMap by FULL index suffix (getIndexFromOID is last-arc-only → composite-indexed rows would merge — reviewer wouldn't ship without settling arity). State enum `0→alive` polarity UNVERIFIED. Best evidence: one real `snmpwalk .1.3.6.1.4.1.12356.101.4.9` from a prod FortiGate w/ SD-WAN — attempt at impl time; else ship full-suffix keying + fixtures + tolerant state mapping.
- AUDIT-219: use device PktLoss column `.9` primary + guarded subtraction fallback (Recv<=Send). MUST land WITH 177 (177 alone arms the underflow).
- AUDIT-217: drop DstEnd(.8=Vdom); .7=DstAddr → rangeToCIDR(dst,"") (output byte-identical /32 — provenance fix). ⚠ DECISION REQUIRED pre-merge: collector maps src→Local/dst→Remote; SERVER maps the OPPOSITE (Mon vendor_fortigate.go:329-343). Consult FORTINET-FORTIGATE-MIB DESCRIPTION text (WebFetch) — RemoteSubnet feeds connection_detail.go:1116 flow-attribution LIKE patterns; a swap inverts them.
- AUDIT-299: hostBitsZero guard; fallback MUST be SPACED `begin - end` (server cidrToLikePattern splits on " - "; unspaced falls to ""→pair skipped). Also fix existing unspaced join at :496.
- AUDIT-300: Unit="V" (collector); server twin :633 = AUDIT-301, Batch 13 — fix both sides, same batch numbering as planned.
- AUDIT-303: regex + optional hours/min groups (len>=2 → defensive). SSH uptime = SECONDS vs SNMP hundredths vs UI /100 → belongs to AUDIT-220/Batch 15 scope; do NOT close "uptime display" under 303.
- AUDIT-222: tier-1 control-flow fix (direction from MATCH not line) + tier-2 regexes must also cover REAL netlink tokens (if=NAME, rx_errors=/tx_errors=/rx_dropped=/tx_dropped= and rxe=/txe= compact) — no real capture exists in either repo; attempt capture at impl time, else dual-format regex + both fixture shapes.
- AUDIT-218: fixture plan T1-T8 specified (ASA-style; literal OIDs in 177/217 tests to avoid tautology; NoSuchInstance case per parser; T8 must NOT assert SSLVPN scalars populate — Appendix A/B respected).
- NEW FINDINGS for tracker (assign AUDIT-319+ at close-out): (319?) server dialup profile columns .2/.3/.4/.11/.12 appear copied from the TUNNEL table (12.2.2.1) into the DIALUP table (12.2.1.1) — Mon vendor_fortigate.go:45-54; unverified, needs derivation. Also: cross-repo dialup Local/Remote mapping divergence (may resolve under 217's decision).

### Batch 4 (verification done — prod inspected read-only; NOT yet implemented)
- REPO NOTE: another session/user has server repo on branch docs/website-live-version-note @ c8f9470 (v0.11.212 claimed). Audit Batch 4 = v0.11.213+. Re-sync master before branching; don't disturb their branch.
- AUDIT-174 REFUTED-FOR-PROD / CONFIRMED-LATENT — prod syslog_messages/trap_events are PLAIN heaps (121M rows/124GB; only denied_events is partitioned; ZERO duplicate indexes exist). Fix = CODE-ONLY: partitionIndexPlan excludes columnsets covered by parent partitioned indexes via CATALOG query (not hardcoded list — LC19 drift). NO migration. MUST land before any future partition conversion of syslog_messages (v54 idx becomes partitioned then → live bug). New test: no two non-unique indexes on a child share indkey (integration_pg). Exactly 2 dup pairs: syslog (severity,timestamp), trap (timestamp).
- AUDIT-188 CONFIRMED — but M9-async ALONE IS A NO-OP: runUnderLeaderLock uses ONE pollerWorkLockKey on a fresh pinned conn → async cleanup holds it → server-health tick REJECTED for the whole cleanup. Fix: (1) startRetentionCleanupAsync + atomic single-flight; (2) server-health gets OWN lock key or runs UNLOCKED (it's ~free; double-insert cheaper than silent outage); (3) do NOT markLoopAlive from the goroutine (masks hung loop — M30); (4) re-arm cleanupTimer at fire time. AST test cleanup_schedule_test.go:46 WILL break — update; mirror feed_sync_async_m9_test.go. Consider own lock key for rollup too (else cleanup suppresses aggregation for hours = widens 204).
- AUDIT-203 CONFIRMED-LATENT (honest LOW) — only 2 discarded time.Parse in pkg (flows.go:717, syslog_agg.go:218); all format pairs currently match; prod has 0 year-0001 rows. Fix: return the error (~6 lines, callers already propagate → tx rollback preserves raw rows). Tests: inject mismatched layout, assert error + raw rows survive.
- AUDIT-204 PARTIALLY CONFIRMED — watermark fix ALREADY adopted in syslog_agg (finding's premise stale); real residual = paged GROUP BY with OFFSET (O(pages × full backlog), to_char bucket unindexable). Fix: TIME-SLICE chunking (1h windows walking MIN(ts)→cutoff, keep id<=watermark); REJECT SET LOCAL timeout=0 (temp-file spill on 42.9GB-free volume + xmin pinning = the 07-26 disk class). syslog_agg first; flows later (390k rows only). Keep shrinkable window knob for tests. Prod: 0×57014 in 7 days; fleet emits ~zero sev 6-7 (aggregation band near-empty). Add test: cleanup can't delete rows whose aggregation pass hasn't committed.
- Prod facts: /data 42.9G free of 196G (77% used); container healthy; schema v57; syslog spans exactly 30d (retention working).

### Batch 3 (both verifiers done; implementation agent running)
- AUDIT-175 CONFIRMED (worse than filed: drain loop REPEATS — one syncData collapses any backlog to ~1000 items in ~80s/100k). Fix: PushFront front tier + requeue items[i*batch:] + stopped bool + break. KEEP permanent-branch continue (M3). Trap: requeue typed items not raw (unmarshalQueued skips malformed → index misalignment). Rewrite TestRequeueTraps_AppendsToQueue (pins old tail semantics); fix lying comments incl. AUDIT-054 note.
- AUDIT-213+214 CONFIRMED = SAME defect; head-requeue closes both (byte-identical replay → same contentBatchID). Restart loses the guarantee for one held batch (duplicates > loss — correct trade, documented).
- AUDIT-287 CONFIRMED + escalation: a 413 metric envelope at queue head wedges drainMetricQueue permanently. Fix: 413/414 non-retryable + remedy-naming log. Land FIRST (reduces 175 blast radius). Server deliberately avoids emitting 413 (07-01 audit) — this fix is the prereq for ever changing that.
- Zero existing tests reference sendBatchesSequential/drainAndSend — headline coverage gap, new tests specified.
- AUDIT-212 CONFIRMED — 3-part fix, ALL required together: (1) relay.go:1297 safego.Go("relay:commandHandler",...); (2) commands.go deferred inFlight delete after :226 (safego alone CREATES the wedge — panic contained → inFlight stuck → silent skip at :211 forever); (3) per-command recover via callHandler helper at :242 so a panicking handler reports `failed` (ends redelivery at attempt 1) and doesn't abort the rest of the batch (HandleCommands loop). No stack/payload in the reported error (server-stored). Redelivery facts: 3min redeliver, 5 attempts, 15min TTL (bounded crash-loop, not unbounded). 4 new tests specified.
- AUDIT-288 CONFIRMED — fix = Option C: do NOT touch negotiatedSchema on /flow-counters 404. New `flowCountersOffUntil atomic.Int64` + `flowCountersOffWindow = 30*time.Minute` (var for tests); gate 1402/1868 via flowCountersEnabled() (schema>=2 && past deadline); finishRegister clears it. MUST UPDATE flow_counters_404_l13_test.go:42-44 (pins the buggy Store(1)); keep its other 3 assertions + the 404-scoped-to-flow-counters test green. 3 new tests specified.
- AUDIT-289 CONFIRMED — exactly 6 bare c.probeID reads: relay.go 2276/2458/2478/2501/2524/2547 (two interface-error sites are singular+plural METHODS). Mechanical GetProbeID() swap; do NOT hold c.mu across HTTP. New race test probeid_race_audit289_test.go (model on relay_test.go:182); keep under CI 120s budget.

### Batch 1
- AUDIT-171 CONFIRMED — gin v1.12.0 LoadHTMLGlob → template.Must panics on zero matches (before IsDebugging branch); deploy.sh:216-218 local + :159/:164 remote both flatten web/. Fix deploy.sh (prefix-preserving copy + rm -rf guard), NOT go:embed (blocked: embed resolves source-relative, cmd/api can't reach ../../web — static.go:14-17). Add internal/shell/deploy_webprefix_audit171_test.go guardrail (style: deploy_configguard_audit099_test.go). Docs: OPERATIONS.md:10, README native install.
  - ADJACENT BUG (fix same PR): deploy.sh:225-227 `cp scripts/*.sh` — scripts/ has only .py files; under set -e install aborts before create_systemd_service; deploy.sh:185 points at nonexistent install.sh.
- AUDIT-190 CONFIRMED — config.env.example:28 SECRETS_DIR=/data vs unit ProtectSystem=strict + ReadWritePaths=/var/lib/firewall-mon (deploy.sh:320-321); fatals in all 3 daemons when JWT_SECRET_KEY empty. Fix: example seeds /var/lib/firewall-mon + truthful comment (Docker unaffected — no env_file, in-code /data default); optional deploy.sh force-seed ONLY inside first-install branch (AUDIT-099 forbids rewriting live config). Guardrail test in internal/shell style.
- AUDIT-173 CONFIRMED+FIXED — empty-as-unset at config.go resolution (single adminPasswordEnv read); Validate() hard-fails empty; audit136 test case 2 inverted; config_audit173_test.go FORCE-ADDED (.gitignore `config/` swallows internal/config new files — AUDIT-001 gotcha, remember for future config tests).
- AUDIT-183 CONFIRMED+FIXED — database.go returns func(){} on all error paths; shell guard pins no `return nil,`.
- AUDIT-310 CONFIRMED+FIXED — NOTICE rewritten (ENCRYPTION_KEY corner scoped), false encryption warning deleted.
- LESSON: local govulncheck must run GOTOOLCHAIN=$(go.mod version) — bare run uses machine toolchain (1.26.4) and false-alarms.
