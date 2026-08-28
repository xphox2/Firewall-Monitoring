# Audit 2026-08-27 Remediation Program (AUDIT-171..318)

Plan: ~/.claude/plans/please-start-planning-a-curried-sprout.md
Per-PR loop: verify (refute-by-default) → fix → fable review of diff → QA gates → changelog+version → PR → auto-merge → next.

## Stage A — HIGH
- [ ] Batch 1 (Server 0.11.211): startup/deploy — 171, 173, 183, 190, 310
- [ ] Batch 2 (Collector 1.3.35): CI pinning — 178, 224, 226, 309-residual
- [ ] Batch 3 (Collector 1.3.36): relay durability — 175, 212, 213, 214, 287, 288, 289
- [ ] Batch 4 (Server 0.11.212): data pipeline/partitioning — 174, 188, 203, 204 (prod DB inspect first)
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

### Batch 1
- AUDIT-171 CONFIRMED — gin v1.12.0 LoadHTMLGlob → template.Must panics on zero matches (before IsDebugging branch); deploy.sh:216-218 local + :159/:164 remote both flatten web/. Fix deploy.sh (prefix-preserving copy + rm -rf guard), NOT go:embed (blocked: embed resolves source-relative, cmd/api can't reach ../../web — static.go:14-17). Add internal/shell/deploy_webprefix_audit171_test.go guardrail (style: deploy_configguard_audit099_test.go). Docs: OPERATIONS.md:10, README native install.
  - ADJACENT BUG (fix same PR): deploy.sh:225-227 `cp scripts/*.sh` — scripts/ has only .py files; under set -e install aborts before create_systemd_service; deploy.sh:185 points at nonexistent install.sh.
- AUDIT-190 CONFIRMED — config.env.example:28 SECRETS_DIR=/data vs unit ProtectSystem=strict + ReadWritePaths=/var/lib/firewall-mon (deploy.sh:320-321); fatals in all 3 daemons when JWT_SECRET_KEY empty. Fix: example seeds /var/lib/firewall-mon + truthful comment (Docker unaffected — no env_file, in-code /data default); optional deploy.sh force-seed ONLY inside first-install branch (AUDIT-099 forbids rewriting live config). Guardrail test in internal/shell style.
