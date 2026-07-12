# Program design: unify all alerting under Event Rules

**Status:** proposed (design review). No code yet.
**Owner direction:** make Event Rules the single alerting‑configuration surface for the product — every alert type editable, scopable, and suppressible as a rule, shipped as built‑in templates. The interface/VPN‑down noise fix is the first rule type and sets the pattern.
**Reviewed by:** adversarial Fable plan review (findings folded in below).

---

## 1. The core reframe (read this first)

The naïve pitch — *"one match engine evaluates every alert"* — **does not work** and must not be built. The Event Rule match expression is a **stateless predicate over `map[string]string`** with `gt`/`lt` values compiled to a **static float at rule‑load time**. That cannot express the stateful behavior real alerts already have:

- **Threshold alerts** (CPU/mem/disk/session) fire at `baseline(device,metric) + K·σ` under z‑score mode (F17) — a *function*, not a constant — and recover with **hysteresis** (`ClearThreshold`, or z‑score's `fireAt − 0.5σ` band): an asymmetric second evaluation on the recovery path.
- **Traffic spikes** use a **seasonal (weekday, hour) baseline** built from 30 days of chart data plus a per‑key **sustain window**, and today bypass the AlertManager/policy path entirely (`cmd/poller`).
- **Interface/VPN/device down** are **state/staleness derivations**, not field matches.

**Corrected architecture:**

> **Event Rule = a unified config + scope + suppression record.** It carries: `source`, a match expression used **only for scoping and suppression** (this interface, this vendor, this event_type — never the threshold comparison), an `action` (alert|suppress), severity, and a per‑source **dampening params blob**. Each alert **source keeps its own stateful evaluator**; the evaluator consults the matching rule for *whether to fire, how to dampen, how severe, and where to route*. Event Rules + the notification policies they reference become the single **UI/config surface**; evaluation stays per‑source.

This is the PagerDuty/Grafana split: **condition object** (the rule) vs. **contact point** (the policy). It fully delivers "manage all alerts as suppressible rules in one place" without pretending the matcher does math it can't.

Roles:

| Object | Responsibility |
|---|---|
| **EventRule** | *What to alert on + how to dampen + how to scope/suppress.* source, match (scope/suppress), action, severity, `dampen_json`, `PolicyID` (routing). Seeded as editable/suppressible templates. |
| **AlertPolicy** | *How to notify + escalate.* Channels + escalation chains + cooldown default. Referenced by rules. **Repurposed, not deprecated.** |
| **Per‑source evaluator** | The stateful engine per source (`state`, `metric`, `spike`, `syslog`, `flow`, `trap`) that produces candidate events and applies the rule's decision. |

---

## 2. Data model changes

### 2.1 `EventRule` (additive)
- `Source` gains values: `state`, `metric`, `spike`, `trap` (today: `syslog|flow|any`).
- **`DampenJSON string` (text)** — per‑source dampening params, validated per source (mirrors how `MatchJSON` is a validated blob). **Not fixed columns** — this is the key decision that lets Phase 2/3 add z‑score/sustain params with **zero further migrations**.
- Scope: reuse existing `VendorScope`, `DeviceID`, `SiteID`; **add `PolicyScope *uint`** (Phase 4) = "applies to devices whose *resolved* policy is P" — preserves the old policy‑membership indirection (see §7).
- **`AlertType` is derived/pinned for non‑syslog sources** (not operator‑settable) — recovery matching and dedup key on exact `(device, alert_type, metric_name)`; letting an operator change it silently breaks both.

Migration: **v41** = the additive `DampenJSON` (+ `PolicyScope` when Phase 4 lands) columns. One migration for the whole program.

### 2.2 `dampen_json` schemas (per source)
```jsonc
// source=state (interface/VPN/device down)
{ "refire_mode": "episode", "min_up_seconds": 14400, "daily_cap": 1 }
// source=metric (CPU/mem/disk/session)
{ "mode": "static|zscore", "threshold": 90, "clear_threshold": 80, "zscore_k": 3.0 }
// source=spike
{ "stddev_k": 3.0, "min_duration_minutes": 15 }
```
Each source registers a validator + defaults. The UI renders fields by source.

### 2.3 Ownership flag (prevents the #1 regression)
Per alert‑type marker `state_engine_owns_<TYPE>` (SystemSetting), flipped **on** when that type's templates are first seeded. Semantics:
- **Flag on** → the rule engine owns the type. **A disabled/deleted template = alerts off, on purpose.** No legacy fallback (no silent double‑fire, no un‑suppressible resurrection).
- **Flag off** (type not yet migrated) → the legacy `resolveAlertConfig` fire path runs unchanged.

This makes "disable the template to suppress the whole type" a real, safe feature, and gives a clean, per‑type migration handoff with **no alerting gap and no double‑fire**.

---

## 3. Per‑source evaluator interface (Phase 0 — paper design, no code until approved)

```go
// StateEvent / MetricSample etc. are the per-source candidate events the poller
// already computes. The evaluator maps them through the matching rule.
type AlertSourceEvaluator interface {
    Source() string                       // "state" | "metric" | "spike" | ...
    // Fields returns the matchable field set for scoping/suppression.
    Fields(ev any) map[string]string
    // Decide applies the matched rule's action + dampen params to produce a
    // fire/suppress/recover decision. Stateful logic (zscore, hysteresis,
    // episode, sustain) lives HERE, not in the match tree.
    Decide(ev any, rule *compiledRule, now time.Time) Decision
}
type Decision struct { Fire, Suppress, Recover bool; Severity models.Severity; Reason string }
```
The existing `matchExpr.eval` is reused verbatim for `appliesTo` + suppression scoping. The **Phase 0 deliverable** is this interface + the three `dampen_json` schemas, **dry‑run‑mapped on paper against the two hardest cases** (z‑score CPU, seasonal spike) and against `resolveAlertConfig`'s full device→site→policy→default override chain, proving the record shape survives Phases 2–3 without another migration or a rule explosion. If the mapping fails, we learn it before v41 exists.

---

## 4. The `state` dampening semantics (Phase 1 content)

A down alert fires only on a genuinely **new outage episode**. On each down observation for a link/tunnel `key`:

1. **An open (unresolved) alert already exists for `key`** → **suppress** (same continuous‑down episode → no re‑fire after ack, no periodic "still down" reminders).
2. **New episode** (recovered since the last alert) → fire iff: **first‑ever** down, **or** it was **up ≥ `min_up_seconds`** (default 4h) before this down, **or** **≥ 24h** since the last down alert (the `daily_cap`). Else **suppress**.

Identical for interfaces and VPNs. Composes with the shipped **everUp counter gate** (v0.11.79 — never alert a never‑cabled port), maintenance windows, and incident grouping.

**Load‑bearing dependencies (must ship together in Phase 1):**
- **Recovery resolves acked alerts.** `sendRecovery` today only resolves `acknowledged=false` rows — so an acked outage never closes, and rule 1 would suppress that interface **forever**. Fix: resolve open rows regardless of ack (notification stays gated on in‑process `wasActive`). Verified safe for **all** consumers (device‑offline, thresholds, traps); release‑note the CPU/mem behavior change (an acked hot box that recovers then re‑breaches now produces a new alert).
- **Persisted up‑timing.** "up ≥4h then down" needs the current up‑run start. In‑memory alone is wiped on every deploy → the exact outage the user needs would be silenced for 24h post‑deploy. Seed the up‑run start from the newest `interface_stats`/`vpn_status` up‑row at startup (data already in the DB).
- **Subsume F13 flap‑suppression** for rule‑dampened state keys (the episode/daily‑cap logic *is* the flap policy) — do not run both. A daily‑capped fire is **saved `Suppressed=true`** (keeps flap evidence + outage visibility in the UI), not skipped.
- **Concurrency:** the `openExists`/history read is a DB query — run it **outside `am.mu`** (like `dbCooldownActive`), never inside `CheckInterfaceStatus`'s locked section, and never take `mu.RLock` reentrantly (Go RWMutex is non‑reentrant → deadlock).
- **Escalation vs. "no reminders":** episode suppression stops **re‑fires**; the policy's escalation chain still re‑notifies an *unacked* episode alert (that's the policy's job) — clarified, not a bug.

---

## 5. Cross‑cutting fixes required before/with Phase 1

1. **Fix rule→policy channel routing (BLOCKER for the two‑object model).** Today `fireEventAlert`'s first notification pulls channels from the *device's* resolved policy and only sets `alert.PolicyID`; the rule's own `PolicyID` doesn't affect the first send (only later escalation). Since rules will drive *all* routing, re‑resolve channels from the rule's policy before the first notify.
2. **Ownership flag** (§2.3) — per‑type, disabled≠absent.
3. **`dampen_json`** (§2.2) — not fixed columns.
4. **Persisted up‑timing** + **acked‑recovery fix** (§4).
5. **Pin/derive AlertType** for non‑syslog rules (§2.1).

---

## 6. Phased roadmap (each phase = its own Fable‑reviewed PR; legacy path stays until a type's flag flips)

- **Phase 0 — design proof (this doc + the §3 interface/schema).** No code. Gate: the record shape survives z‑score + spike + override‑chain on paper.
- **Phase 1 — `state` source + interface/VPN down + the urgent dampening.** EventRule `source=state` + `dampen_json`; `statefields.go`; route `CheckInterfaceStatus`/`CheckVPNStatus` down‑decision through matched state rules; the §4 dampening + all its load‑bearing fixes; the §5 routing fix; seed "Interface down" / "VPN tunnel down" templates (idempotent, ownership flag on); **minimal state‑source UI** (or explicitly API‑editable‑only until Phase 5 — decision needed, see §8). Delivers the noise fix **and** proves the pattern.
- **Phase 2 — `metric` source.** CPU/mem/disk/session thresholds as rules; z‑score/hysteresis as `dampen_json`, evaluator keeps the stateful math; seed defaults; flag flip per type.
- **Phase 3 — remaining types.** device‑offline (staleness), interface‑errors, traffic spike (needs the spike detector wired into the rule/notify path — it bypasses it today), SNMP traps (the trap‑receiver embeds its **own** AlertManager — it must run the seed + `RefreshEventRules` cadence).
- **Phase 4 — config migration + reconcile (own design doc, see §7).** Migrate existing operator AlertPolicy/AlertRule + device/site override thresholds into rules losslessly + idempotently; AlertPolicy keeps channels/escalation; remove legacy fallbacks once every type's flag is on.
- **Phase 5 — unified Event Rules UI.** One surface: source selector, per‑source match‑field hints + dampening fields, per‑source live tester (the current tester replays syslog only — nonsense for state/metric), built‑in badges, per‑interface/tunnel scoping. Old Alert‑Policy threshold editor folds into notification/escalation profiles.

---

## 7. Phase 4 migration — the trap, and how to avoid it (own design doc later)

Naïvely migrating "Policy P's CPU rule, threshold 90" into EventRules is **lossy/stale** because of a **scope‑model mismatch**:
- `AlertRule` scope = **policy membership** — a policy binds to devices *indirectly* via `DeviceAlertConfig.PolicyID` / `SiteAlertConfig.PolicyID`, resolved at fire time. A device's policy assignment can change later.
- `EventRule` scope = **direct** (DeviceID/SiteID/vendor).

Non‑lossy path: add **`PolicyScope *uint`** to EventRule ("applies to devices whose resolved policy is P") so the indirection survives. Also must be mapped, none of which the one‑bullet version covered:
- `DeviceAlertConfig`/`SiteAlertConfig` **per‑metric threshold columns** + `AlertsEnabled` (the device/site override *layer* of `resolveAlertConfig` — half the system).
- **Per‑rule channel overrides** (`AlertRule.NotifyEmail/Slack/... *bool`) — EventRule has no channel‑override fields; either add them, or synthesize per‑type policies (object explosion), or accept loss. Decision required.
- `StormSources` nil‑vs‑0 semantics (v0.11.46).
- Idempotency when re‑run after operator edits on *either* side.

**This phase does not start until it has its own reviewed design.** Do not promise "lossless + idempotent" in one line.

---

## 8. Open decisions for the owner
1. **Phase 1 UI:** ship a minimal `source=state` editor in Phase 1, or declare the seeded templates **API‑editable‑only** until the unified Phase 5 UI? (Recommendation: minimal Phase 1 UI — an operator opening a seeded rule in today's syslog‑shaped builder is confusing.)
2. **`min_up_seconds` default** — 4h as proposed, or 2–3h?
3. **Deprecation posture:** does the old Alert‑Policy threshold UI get removed in Phase 5, or kept read‑only for a release?

## 9. Non‑goals / guarantees
- **No alerting gap or double‑fire** during migration — the per‑type ownership flag guarantees exactly one path owns each type at any time.
- Notifier, escalation, maintenance windows, incident grouping, and the everUp counter gate are **reused**, not rebuilt.
- Every phase live‑validated (lab pair for state/metric) + Fable‑reviewed diff before merge.
