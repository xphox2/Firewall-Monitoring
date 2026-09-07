# Device retire / restore / purge (plan: ~/.claude/plans/when-i-removed-a-snappy-tower.md)

## PR A — retire/restore + exclusions + orphan recovery + site guard + UI
- [x] Backend: Device.RetiredAt + migration v60; RetireDevice/RestoreDevice; DELETE repointed; UpdateDevice 409; CreateDevice 409 retired_device_id; IsUniqueViolation
- [x] Backend: ActiveDevices scope + GetActiveDevices; GetDevicesByProbe/GetDeviceIDsByProbe/MarkStale/bumpDevicesOnline/heartbeat host-key filters; poller + dashboards + reports + IRC
- [x] Backend: retire acks/resolves open alerts (CheckEscalations quiet); probe delete/decommission counts ignore retired; DeleteProbe nulls retired probe_id
- [x] Backend: migration v61 materialize_orphaned_devices (device_id > 0, name/IP parse, setval on PG)
- [x] Backend: DeleteSite guard ErrSiteHasMembers → 409
- [x] Tests: retired_scope, retire acks alerts, update 409, create 409, migration v62, site guard, probe lifecycle
- [x] UI: Devices tabs Active/Retired/All, RETIRED badge, Retire/Restore actions, same-name restore prompt, alerts marker, device-detail banner + 404 copy
- [x] Docs: CHANGELOG (new top entry), README endpoint, DATA-RETENTION, OPERATIONS; ServerVersion bump
- [x] QA: (PR #247 merged, deployed 2026-09-07 00:27 UTC, device 4 recovered) gofmt, staticcheck, build, test -count=1; adversarial diff review; PR; CI; merge; deploy rust-01; verify device 4 retired + alert link

## v0.11.240 follow-up
- [x] migration v62 close_alerts_for_retired_devices — PR #248 merged, deployed 2026-09-07 00:47 UTC, verified

## v0.11.241 — names unique among ACTIVE devices (plan approved 2026-09-07)
- [x] Backend: Name tag index-only; migration v63 partial unique index; testing.go partial index; RestoreDevice single statement; CreateDevice reuse_name wrapper + retired_count; tests; docs; changelog 0.11.241
- [x] UI: AC.choose / AC.promptText / AC.deviceOptionLabel; add-device 3-way chooser; rename-on-restore; retired date inline; pickers labelled; shell guardrail updated
- [x] QA gates; adversarial diff review; PR #249; CI; merged; deployed rust-01 2026-09-07 01:34 UTC; index shape + v0.11.241 verified

## v0.11.242 — device UUID + IPSec identity from UUID (plan approved 2026-09-07)
- [x] Backend: Device.UUID + BeforeCreate; UpdateDevice Omit(uuid); migration v64 backfill; tests; docs; changelog 0.11.242
- [x] UI: wizard defaultIdentity fwm-<uuid>; help text + placeholders; UUID on detail page + edit modal; shell guardrail
- [x] QA gates; adversarial diff review; PR #250; CI; merged; deployed rust-01 2026-09-07 02:26 UTC; 6/6 uuids populated, v0.11.242

## v0.11.243 — permanent purge job (plan approved 2026-09-07)
- [ ] Backend: DevicePurgeJob + v65; devicePurgeTables + reflection coverage; batchedDeleteWhere (ORDER BY, per-table batch, timeouts, retries, partitions); worker (CAS claim, advisory lock, stale requeue, shutdown flip); handlers + 5 admin routes + reauthCaller; docs; changelog 0.11.243
- [ ] UI: purge-device action, #purge-device-modal (estimate/name/password/2FA), PURGING badge + cancel, polling, detail banner
- [ ] QA gates; adversarial diff review; PR; CI; merge; deploy rust-01; verify worker start + version
