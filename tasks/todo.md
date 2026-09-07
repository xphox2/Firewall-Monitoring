# Device retire / restore / purge (plan: ~/.claude/plans/when-i-removed-a-snappy-tower.md)

## PR A — retire/restore + exclusions + orphan recovery + site guard + UI
- [ ] Backend: Device.RetiredAt + migration v60; RetireDevice/RestoreDevice; DELETE repointed; UpdateDevice 409; CreateDevice 409 retired_device_id; IsUniqueViolation
- [ ] Backend: ActiveDevices scope + GetActiveDevices; GetDevicesByProbe/GetDeviceIDsByProbe/MarkStale/bumpDevicesOnline/heartbeat host-key filters; poller + dashboards + reports + IRC
- [ ] Backend: retire acks/resolves open alerts (CheckEscalations quiet); probe delete/decommission counts ignore retired; DeleteProbe nulls retired probe_id
- [ ] Backend: migration v62 materialize_orphaned_devices (device_id > 0, name/IP parse, setval on PG)
- [ ] Backend: DeleteSite guard ErrSiteHasMembers → 409
- [ ] Tests: retired_scope, retire acks alerts, update 409, create 409, migration v62, site guard, probe lifecycle
- [ ] UI: Devices tabs Active/Retired/All, RETIRED badge, Retire/Restore actions, same-name restore prompt, alerts marker, device-detail banner + 404 copy
- [ ] Docs: CHANGELOG (new top entry), README endpoint, DATA-RETENTION, OPERATIONS; ServerVersion bump
- [ ] QA: gofmt, staticcheck, build, test -count=1; fable review; PR; CI; merge; deploy rust-01; verify device 4 retired + alert link

## PR B — purge job (separate plan-mode delta)
- [ ] not started
