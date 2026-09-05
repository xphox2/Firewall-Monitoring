# DB volume growth — 2026-09-05 (plan: ~/.claude/plans/why-is-the-db-cosmic-treasure.md)

Diagnosis: retention works; NUDAY-FW policy 20 `IP_BLOCK-2` syslog went 0.8M → 3.4M rows/day, 30-day window × ~1 KB/row → ~190 GB steady state. User expanded disks (root 80 GB, data 350 GB) and chose to KEEP 30 days. Expect plateau ~60–65 % by early Oct.

- [x] Step 0 — disks expanded on rust-01 (user; verified 77 GB / 344 GB)
- [ ] Item 1 — Retention page: rows/day, MB/day, projected steady-state vs volume (own plan-mode unit)
- [ ] Item 2 — days-until-full forecast + SERVER_DISK_FORECAST alert, threshold = SystemSetting (own plan-mode unit)
- [ ] Item 3 — populate threshold/current_value on SERVER_DISK_HIGH (`internal/alerts/serverdisk.go:141`) — rides with item 2
- [ ] Item 4 — (user, FortiGate) `set logtraffic-start disable` on policies 14 + 17 only; NEVER 20/24
- [ ] Item 5 — partition syslog_messages (existing program step 4); VACUUM ANALYZE + postgresql.conf tuning (pending operator steps)

## Review
(filled in as items land)
