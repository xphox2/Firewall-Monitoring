# IPSec Rollback for Retired Peers — Plan

Status: **reviewed by DeepSeek V4 Pro (`ollama-cloud/deepseek-v4-pro:0813`, read-only) —
APPROVE WITH CHANGES; all accepted findings folded in below (marked `[R#n]`).**
Revised 2026-10-24. **Implemented in v0.11.442** (branch `fix/ipsec-retired-peer-rollback`).
The implementation landed as reviewed, with the two documented refinements: the per-end rollback
record carries a `FailReason` (so a live end that could not be built keeps its reason instead of a
generic one), and the V2 map LISTS the tunnels whose peer is decommissioned below the map instead of
drawing them (the plan assumed a device VPN panel that ui-v2 does not have).

> **Handoff / Resume Note:** this is the single source of truth for the IPSec retired-peer rollback
> fix. The problem is that retiring a firewall breaks the tunnel rollback, which leaves stale
> IPSec objects on the surviving peer and phantom "down" peers on the V2 connections map. Sections
> 1–3 are the verified root cause; sections 4–12 are the implementation parts; section 13 is the
> operator runbook. The review outcome and what it changed are in section 14.

---

## 1. Symptom

The V2 console's connections map (`/admin/v2`, Topology) shows a cluster of phantom remote peers —
status `down`, all branched off the OPNsense firewall, edges leading nowhere. They are leftovers
from the abandoned IPSec tunnel automation.

The FortiGate `TECHLABS-FW-01` was retired. The rollback that should clean the **OPNsense side** of
those tunnels cannot be run: it is rejected, or it lands in `rollback_failed`, and the tunnel never
leaves the "provisioned" set — so the phantom peers are **re-created every 5 minutes** instead of
aging out.

The operator cannot even start the cleanup from V2: the ui-v2 IPSec tab wires only
`preflight` / `deploy` / `recheck`. Only the legacy console
(`cmd/api/static/js/admin-ipsec.js:108`) has a Rollback button.

## 2. Decisions taken (operator-confirmed)

1. A retired end is **skipped and reported**, not attempted. The live end is cleaned; the skip
   reason is surfaced in the rollback's terminal reason.
2. A **bulk endpoint** is added for the orphaned set.
3. After a successful rollback the tunnel row is **left in place**; the operator deletes it
   explicitly (the rollback makes it deletable — the deploy record is cleared).

## 3. Root cause (verified against source — every cited behaviour checks out)

### 3.1 The rollback is all-or-nothing across ends

`internal/api/handlers/handlers_ipsec.go:1734-1742` builds a `remove_ipsec` command for **every**
end and aborts the *whole* rollback if **any single end** fails to build:

```go
for i := range st.Ends {
    cmd, berr := ipsecBuildRemoveCmd(db, m.ID, m.Name, st.Ends[i])
    if berr != nil {
        c.JSON(http.StatusBadRequest, response.Error(berr.Error()))
        return          // ← one dead end kills the live end's cleanup
    }
```

`ipsecBuildRemoveCmd` (`:1859`) fails when the end's device row is gone (purged) or has no
collector. **The IPSec subsystem has no notion of "retired"** — `rg "retired" handlers_ipsec.go
database/ipsec.go ipsec/*.go` returns zero matches.

A *retired* device **is** returned by `db.GetDevice` (`internal/database/devices.go:49-57`,
deliberately unscoped — the comment at `:32-34` says so), and `RetireDevice` (`:255-274`) only
stamps `retired_at` + disables the device; it keeps the row. So a retired end **builds** a command
that then dies at the collector, rather than failing at build time. Both shapes must be handled.

### 3.2 A failed end keeps the record, which keeps the tunnel "provisioned"

When the retired end's command fails, the terminal is `rollback_failed` (`:1266-1268`) and
`deploy_json` is **kept** (`:1281`). `GetProvisionedTunnelPairs`
(`internal/database/ipsec.go:194`) treats every tunnel whose status is not `draft`/`rolled_back` as
provisioned — so the tunnel never escapes.

### 3.3 The "down" rows are manufactured, not observed

`expectedFor` (`internal/ipsectelemetry/ingest.go:96`) turns provisioned pairs into "expected child
SAs" for the OPNsense, and `vpnsession.ParseOPNsense` (`internal/vpnsession/opnsense.go:160-172`)
**synthesizes a `down` row** for every expected child the box is not carrying. This repeats on
every 5-minute telemetry cycle for as long as the tunnel stays "provisioned" — which, per 3.2, is
forever.

### 3.4 The map turns those rows into phantom nodes

`GetVPNMapData` (`internal/api/handlers/handlers_connections.go:649-662`) resolves such a row's peer
to the retired FortiGate, finds it is not an active device (`deviceByID` is built from
`GetActiveDevices()`, `:558`), and returns `matched_device_id: 0`.
`ui-v2/src/pages/TopologyWorkspace.tsx:288-305` then falls back to `ext-${remote_ip}` and creates a
**phantom external node** — the dead peer's IP, status `down`, edged from the OPNsense. That is the
reported symptom.

### 3.5 Two more dead ends

- **State dead-end.** `fromStatuses` (`:1750`) omits `deploying`, and `ForceResetIPSecDeploy` only
  allows `error`/`rollback_failed` (`:1920-1922`). A tunnel wedged in `deploying` — its apply
  command expired when the FortiGate was decommissioned — can be **neither rolled back nor reset
  nor edited nor deleted**. Permanently stuck.
- **No terminal driver.** `GetIPSecDeployResult` is referenced by exactly one route
  (`cmd/api/main.go:1164`) and by no worker. The `rolling_back → terminal` transition happens
  **only** when a client polls. A tunnel left `rolling_back` (operator closed the browser) is stuck
  forever, cannot be re-rolled-back (`fromStatuses` excludes `rolling_back`), and **blocks the
  device purge** (`ipsecPurgeBlockingStatuses`, `internal/api/handlers/handlers_devices_purge.go:59-63`).

---

## 4. Part 1 — Per-end rollback outcomes (core fix)

### 4.1 `internal/ipsec/deploystate.go`

```go
type RollbackEndState struct {
    End       int    `json:"end"`
    DeviceID  uint   `json:"device_id"`
    CommandID string `json:"command_id,omitempty"`
    // Skipped marks an end that CANNOT be rolled back because its device is
    // gone (retired or purged). Nothing can clean a device that no longer
    // exists, so its absence is NOT a rollback failure.
    Skipped    bool   `json:"skipped,omitempty"`
    SkipReason string `json:"skip_reason,omitempty"`
}

type RollbackState struct {
    // CommandIDs is the LEGACY form: index-aligned with DeployState.Ends.
    // Records written before per-end rollbacks carry it and no Ends. It is now
    // READ-ONLY (the legacy fallback path) — Ends is authoritative.
    CommandIDs []string           `json:"command_ids"`
    StartedAt  string             `json:"started_at,omitempty"`
    Auto       bool               `json:"auto,omitempty"`
    Ends       []RollbackEndState `json:"ends,omitempty"`
}
```

`Ends` is empty on records written before this change → the poll falls back to today's
index-aligned `CommandIDs` path. **Old `deploy_json` rows keep working; no schema migration**
(`deploy_json` is a text column).

### 4.2 `internal/api/handlers/handlers_ipsec.go`

- Refactor `ipsecBuildRemoveCmd(db, …)` → `ipsecBuildRemoveCmd(dev *models.Device, …)` (takes the
  device; removes a duplicate lookup).
- New `ipsecPlanRollbackEnd(db, m, e)` returns a classified outcome:
  - device row **gone** (purged) → **skipped**, reason `end X device (id N) no longer exists`
  - `dev.RetiredAt != nil` → **skipped**, reason
    `end X (NAME) was retired on <date> — its objects were NOT removed`
  - live device, no collector → **hard error** (remains a failure — a live device genuinely cannot
    be cleaned)
  - **live OPNsense end with empty `CapturedUUIDs`** → **`RollbackUnproven`** (see 4.3)
  - otherwise → command built
- `RollbackIPSecTunnel` (`:1701`): build per end; **skipped ends do not abort the rollback**; a hard
  error marks *that end* failed but still lets the other end's command be enqueued. `400` only if
  nothing at all could be attempted.
- Auto-rollback path (`:1454-1470`): same per-end classification. It currently `break`s on the first
  build error, exactly like the manual path.

### 4.3 The false-clean on an OPNsense end with no captured UUIDs `[R3]`

`CapturedUUIDs` are merged into the deploy record **only during the deploy poll** (`:1358-1365` for
a failed apply, `:1373-1380` for a succeeded one). They are **empty** when:

- the apply command expired / its result was pruned / the report was unparseable (`:1333-1338`,
  `:1348-1351`, `:1368-1372` all set `unknown[i]` and merge nothing), or
- the tunnel never reached a terminal poll at all — e.g. it is wedged in `deploying` because the
  FortiGate was decommissioned mid-deploy. **This is precisely the operator's situation.**

An OPNsense remove whose `<uuid:NAME>` tokens have no stored UUID is **skipped by the collector**
(`internal/ipsec/vendors/opnsense/opnsense.go:222`) and the report reads `applied: true` — a
**false clean**. The poll then declares `rolled_back`, clears the record, and the OPNsense objects
are still there.

The auto-rollback path already guards this with `RollbackUnproven` (`:1449-1453`, forcing
`rollback_failed` at `:1263-1265`); **the manual and bulk paths do not**.

**Fix:** `ipsecPlanRollbackEnd` marks a live OPNsense end with empty `CapturedUUIDs` as
`RollbackUnproven`, exactly as the auto path does. The rollback then lands in `rollback_failed` with
an explicit "verify the device manually" reason instead of claiming a clean rollback.

### 4.4 One shared terminal implementation — in the database layer `[R4]`

The terminal evaluation moves out of the poll (`:1228-1296`) into `internal/database/ipsec.go`:

```go
// ResolveIPSecRollback advances a rolling_back tunnel to its terminal state.
// done=false while commands are still in flight. Performs EXACTLY ONE guarded
// write when it reaches a terminal (the F2 invariant at ipsec.go:299-336) —
// the caller must never chain a second status/deploy_json setter.
func (d *Database) ResolveIPSecRollback(id uint) (status, reason string, done bool, err error)
```

`internal/database` already imports `internal/ipsec`, so this is layer-legal. It is called by the
poll handler, the bulk endpoint, **and the new background worker** — one implementation of the
terminal rules, three callers. Rules preserved verbatim:

- a **skipped** end counts **done**, not a failure (its reason is appended to the terminal reason);
- a **non-skipped** end marked `RollbackUnproven` still forces `rollback_failed` even on a clean
  report (`:1263-1265`) — the skip path must not override it;
- a lost race (the worker already wrote the terminal) is benign: the guarded write affects 0 rows.

## 5. Part 2 — Un-wedge the state machine

- Add **`deploying`** to the rollback's `fromStatuses` (`:1750`). Safe: `ipsecHasLiveCommand`
  (`:939-961`) already returns `409` while any apply/rollback command is live, so this only unlocks
  tunnels whose commands are dead.
- **Do not** add an `ipsecStatusVerifying` constant `[R6]`: `verifying` is never persisted by any
  handler (`internal/api/handlers/handlers_devices_purge.go:56-58` says so explicitly). Dead code —
  cut.

## 6. Part 3 — Stop manufacturing "down" rows for dead peers

- **New** `internal/database/devices.go`:

  ```go
  // DeviceLifecycle is a device's rollout state for the IPSec peer checks.
  type DeviceLifecycle string
  const (
      DeviceActive  DeviceLifecycle = "active"
      DeviceRetired DeviceLifecycle = "retired"
      DeviceMissing DeviceLifecycle = "missing" // purged — the row is gone
  )
  // GetDeviceLifecycleStates resolves the lifecycle of each requested device in
  // ONE query. Cheaper than GetAllDevices (which decrypts every device's
  // secrets) and it distinguishes retired from purged, which a retired-IDs-only
  // helper cannot.
  func (d *Database) GetDeviceLifecycleStates(ids []uint) (map[uint]DeviceLifecycle, error)
  ```

  `[R5]` — one helper covers "retired" **and** "absent"; a retired-IDs-only helper cannot express
  "absent".
- `internal/ipsectelemetry/ingest.go` `expectedFor`: skip a pair whose **far-end** device is retired
  or missing. *A tunnel to a decommissioned peer can never come up — expecting its children is a
  manufactured outage.*
- Deliberately **scoped to `expectedFor`, not `GetProvisionedTunnelPairs`**: changing the shared
  pair set would make `provisionedPeer` fall back to remote-IP matching, which is *wrong* for NAT'd
  dialup peers (`handlers_connections.go:657` explains why).

## 7. Part 4 — Map: no phantom peer nodes

- `handlers_connections.go` `GetVPNMapData`: add `peer_state` and `peer_name` to `tunnelInfo`.
  `[R1]` `deviceByID` is built from `GetActiveDevices()` and therefore **cannot** yield a retired
  peer's name, and `provisionedPeer` (`:706-723`) returns only a `uint`. The name must come from
  `db.GetDevice(peer)`:
  - `GetDevice` succeeds, `RetiredAt != nil` → `peer_state: "retired"`, `peer_name: <name>`
  - `GetDevice` fails → `peer_state: "removed"`, `peer_name: ""` (the row is gone; the name is
    unrecoverable)
  - resolve per peer **once per request**, not per tunnel row (a small map built alongside
    `deviceByID`)
- `ui-v2/src/pages/TopologyWorkspace.tsx:282-315`: when `peer_state` is `retired` or `removed`,
  **skip both the external node and the edge**. (Cytoscape does *not* auto-create an implicit node
  for a dangling edge — skipping only one leaves either an orphan external node or a dangling
  edge, so both must go.) The tunnel stays visible in the device's VPN panel with `peer_name`, so
  the information is not lost — it just stops being a phantom branch on the graph.

## 8. Part 5 — ui-v2 Rollback button (so the operator can actually run it)

- `ui-v2/src/pages/TopologyWorkspace.tsx` `IpsecTunnelsSubTab`: add a **Rollback** action button,
  shown only for rollback-able statuses
  (`degraded|up|down|error|rollback_failed|deploying` — mirrors the server), behind a
  `ConfirmDialog` stating exactly what it removes.
- After the POST, poll `GET /admin/api/ipsec/tunnels/:id/deploy` until a terminal
  (`rolled_back` / `rollback_failed`), then refresh. The legacy console already has this flow
  (`cmd/api/static/js/admin-ipsec.js:1906`) — mirror it.

## 9. Part 6 — Bulk endpoint for the orphaned set

- **New** `POST /admin/api/ipsec/rollback-orphaned`.
  - Finds every tunnel with a deploy record where one end's device is retired or purged.
  - Rolls back the live end of each; records the skipped end with its reason.
  - For tunnels where *every* end is skipped, resolves straight to `rolled_back` (nothing to clean
    anywhere) via `ResolveIPSecRollback`.
  - `[R2]` Also resolves tunnels that are **already `rolling_back`** — `RollbackIPSecTunnel`'s
    `fromStatuses` excludes `rolling_back`, so such an orphan can otherwise never be re-driven and
    blocks the device purge.
  - **Also reports** orphans it cannot roll back — a tunnel with no deploy record (`draft`, or a
    `ForceResetIPSecDeploy`-cleared record whose snapshot is gone forever) — under
    `needs_manual_cleanup`, so the operator knows those OPNsense objects must be removed by hand.
    It must not silently omit them.
  - Returns a per-tunnel report: `{tunnel_id, name, status, skipped_ends[], commands[], error}`.
  - Admin-only: add `"/admin/api/ipsec/rollback-orphaned": true` to `adminOnlyRoutes`
    (`cmd/api/main.go:913-929`).
  - Audit-logged (`ipsec_deploy_reset` style).
- `cmd/api/main.go`: register the route next to the other IPSec saga routes (`:1163-1170`).

## 10. Part 7 — Background rollback reconciler `[R2]`

Today the `rolling_back → rolled_back|rollback_failed` terminal is advanced **only** by the
UI-driven `GET …/deploy` poll (verified: `GetIPSecDeployResult` is referenced by exactly one route
and by no worker). Consequences:

- the bulk endpoint's live-end tunnels never reach a terminal unless someone polls each one;
- a tunnel left `rolling_back` is stuck forever — it cannot be re-rolled-back and it **blocks the
  purge** of the retired device.

**Fix:** a background worker in the API server that advances `rolling_back` tunnels to their terminal
using the shared `ResolveIPSecRollback`.

- New `database.IPSecRollbackWorker` mirroring `DevicePurgeWorker`
  (`internal/database/purge.go`, started at `cmd/api/main.go:587-601`): `NewIPSecRollbackWorker(db)` +
  `Tick(ctx)`, ticker every ~15 s, started under the same `if isPrimary` gate and `logging.SafeGo`
  so only the singleton primary advances rollbacks.
- `Tick` selects tunnels with status `rolling_back` (a new focused DB query, not the full
  `ListIPSecTunnels`) and calls `ResolveIPSecRollback` for each. The guarded write makes concurrent
  resolution with the UI poll benign.
- **This is what makes the bulk endpoint work without a human polling N tunnels.**

## 11. Part 8 — The V2 bundle is a committed build artifact `[R7]`

`ui-v2/vite.config.ts:39-40` sets `build.outDir` to `cmd/api/static/v2`, and
`cmd/api/static/v2/v2.js` is a **committed** artifact (it changes with every UI commit). A change to
`ui-v2/src/**` does not reach the running app until:

```
cd ui-v2 && npm run build     # tsc --noEmit && vite build
```

and the regenerated `cmd/api/static/v2/` is committed with the PR. **Parts 4 and 5 both require this
step**, or the fix is invisible in the deployed console.

## 12. Part 9 — Tests

`internal/api/handlers/` (matching `prc2b2a_test.go` / `prc2b_deploy_test.go` conventions). The
harness is SQLite `:memory:` (`internal/database/testing.go:126-180`); `retired_at IS NOT NULL` and
`db.RetireDevice` behave identically to Postgres for these checks. There is no `retireDevice` helper
in the handlers package — call `db.RetireDevice(dev.ID)` directly (on `DeviceStore`), and
`db.DeleteDevice(dev.ID)` for the purged case.

| Test | Asserts |
|---|---|
| `TestRollback_RetiredPeerEnd_SkipsAndCleansLiveEnd` | retired end A → **no** command enqueued for A; command enqueued for the live OPNsense end B; poll → `rolled_back`; `deploy_json` cleared |
| `TestRollback_PurgedPeerEnd_SkipsAndCleansLiveEnd` | purged end A → same (`db.DeleteDevice`) |
| `TestRollback_AllEndsSkipped_ReachesRolledBack` | 0 commands → still `rolled_back`, record cleared |
| `TestRollback_LiveEndNoCollector_IsPerEndFailure` | live end without a collector → that end fails, the other end is **still** enqueued and cleaned |
| `TestRollback_OPNsenseEndEmptyCapturedUUIDs_ForcesRollbackFailed` `[R3]` | live OPNsense end with no captured UUIDs → **not** a false clean: `rollback_failed` + "verify manually" |
| `TestRollback_FromDeploying_IsAllowed` | `deploying` + dead apply command → 200 (was 409) |
| `TestRollback_Still409_WhenCommandLive` | guard preserved |
| `TestRollback_LegacyRecordWithoutEnds_StillPolls` | a `deploy_json` written directly via Gorm with `Rollback.CommandIDs` and no `Ends` still resolves via `CommandIDs` |
| `TestBulkRollbackOrphaned_ReportsPerTunnel` | bulk endpoint picks only tunnels with a retired peer; per-tunnel report correct |
| `TestBulkRollbackOrphaned_ReportsNeedsManualCleanup` | a tunnel with no deploy record whose peer is retired is REPORTED as `needs_manual_cleanup`, not silently omitted |
| `TestBulkRollbackOrphaned_ResolvesRollingBackOrphan` `[R2]` | an already-`rolling_back` orphan is advanced to a terminal |
| `TestResolveIPSecRollback_WorksWithoutUIPoll` `[R2]` | `ResolveIPSecRollback` drives a `rolling_back` tunnel to terminal with no HTTP poll involved |
| `TestVPNMap_RetiredPeer_PeerStateRetired` `[R1]` | `peer_state == "retired"`, `peer_name` = the retired device's name, `matched_device_id == 0` |
| `TestExpectedFor_SkipsRetiredPeer` — **in `internal/ipsectelemetry`, not `internal/api/handlers`** | `expectedFor` returns nothing for a tunnel whose peer is retired → **no synthetic `down` row** |

Plus a guardrail test in `test/guardrails/` (harness confirmed present) asserting the new admin-only
route is in the allow-list.

## 13. Operator runbook (after the fix lands)

1. `POST /admin/api/ipsec/rollback-orphaned` → rolls back the live OPNsense end of every orphaned
   tunnel, skips the retired FortiGate end with a reason, and reports any orphan it cannot roll back
   as `needs_manual_cleanup`.
2. The collector runs the `remove_ipsec` commands → OPNsense objects (connection, local/remote auth,
   child SAs, PSK, floating firewall rules) removed → the OPNsense stops reporting them. **Part 7's
   reconciler advances the tunnel to its terminal without anyone polling.**
3. Tunnels reach `rolled_back` → `deploy_json` cleared → they leave the provisioned set → the
   synthetic "down" rows stop being re-created → **the phantom peers disappear from the V2 map**.
4. Remaining stale `vpn_status` rows age out of the 3-hour grace window (`l2infer.GraceWindow`);
   Part 4 removes the phantom nodes for anything still outstanding.
5. The operator then deletes the orphaned tunnel rows (now deletable — the record is cleared).

**Legacy console:** the legacy map (`cmd/api/static/js/diagram-cytoscape.js:125-127`) shows the same
symptom as a *count* (`VPN up/total`, `down`) rather than as phantom nodes, and stale rows inflate
it for up to 3 hours. The legacy console is out of scope; the count self-corrects.

## 14. Review outcome — DeepSeek V4 Pro (read-only), 2026-10-24

**Verdict: APPROVE WITH CHANGES.** The root-cause analysis was verified as literally correct —
all 13 cited behaviours check out, including the subtle one: a *retired* device **is** returned by
`db.GetDevice`, so it builds a command that then dies at the collector, rather than failing at
build time.

Accepted findings, all folded into the parts above:

| # | Sev | Finding | Folded into |
|---|---|---|---|
| R3 | **HIGH** | `CapturedUUIDs` are merged only during the deploy poll → an OPNsense end with none produces a **false clean**; `RollbackUnproven` guards only the auto path. | 4.3 |
| R2 | **HIGH** | The `rolling_back` terminal is advanced only by the UI poll → a bulk rollback never lands, and a stuck `rolling_back` blocks the purge. | 9, 10 |
| R1 | **HIGH** | Part 4's `peer_name`/`peer_state` cannot be produced from the cited code (`deviceByID` excludes retired; `provisionedPeer` returns only a `uint`). | 7 |
| R4 | MED | The extracted resolver must not let the skip path override `RollbackUnproven`, and must keep the "exactly ONE guarded write" invariant. | 4.4 |
| R5 | LOW | A retired-IDs-only helper cannot express "absent" (purged). | 6 |
| R6 | LOW | The `verifying` constant is dead code — never persisted by any handler. | 5 |
| R7 | NIT | `cmd/api/static/v2/` is a committed build artifact; a `ui-v2/src` change is invisible until rebuilt. | 11 |

Over-engineering cut: the `verifying` constant, and the "avoids a Gin route conflict" rationale for
the bulk route path (different prefixes could never conflict).

**One correction to the review:** it claimed cytoscape auto-creates a node for a dangling edge — it
does not. The conclusion (skip **both** node and edge) still holds, but the stated mechanism was
wrong and section 7 now says so correctly.

## 15. Risks & non-goals

- **A skipped retired end may still hold objects** (if the FortiGate is somehow still powered). The
  terminal reason says so explicitly; `ForceResetIPSecDeploy`'s existing "verify and remove them
  manually" warning covers it. No reachability probe is added — that is a separate decision.
- **A live OPNsense end with no captured UUIDs will NOT report a clean rollback** `[R3]` — it
  reports `rollback_failed` + "verify manually". Deliberate: a false clean would leave the OPNsense
  dirty while claiming success. The operator gets an honest failure instead.
- **No auto-delete** of tunnel rows (operator-confirmed).
- **No schema migration** — `deploy_json` is a text column; the new field is additive and
  backward-compatible.
- **No collector-side change** — the collector repo is untouched; the server simply stops sending it
  doomed work.
- **Part 7 adds a background worker** — it is primary-gated (single instance) and uses the same
  guarded write as the poll, so it cannot race the UI into a double terminal write.

## 16. Effort / workflow

~1 worktree, ~1 PR. Server changes are the bulk (Parts 1–4, 6, 7); Parts 5, 8 and 9 are UI, build
and tests. Per the standing workflow: one QA gate (`make ci-local`), one DeepSeek Pro review
session (already done — this revision), then merge. Version bump: `0.11.x` per PR.
