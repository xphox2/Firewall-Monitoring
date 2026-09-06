# Off-net edge: draw only while a user is connected — 2026-09-05 (plan: ~/.claude/plans/the-https-stats-technicallabs-org-admin-precious-hamming.md)

Idle remote-access/dialup phase1s (config rows, status unknown) made the Off-Net edge DOWN (✖) on DC2-FW1 and NUDAY-FW. Fix is client-only: edge exists only while ≥1 unmatched tunnel is `up`, always green, label "N connected"; reconciled on the 15 s vpn-map poll.

- [x] `diagram-cytoscape.js`: `offnetConnected` + `offnetEdgeData` helpers; `buildElements` uses them; `updateVPNBadges` → `reconcileOffnetEdges`
- [x] guardrail `internal/shell/diagram_offnet_idle_test.go`
- [x] ServerVersion 0.11.237 + CHANGELOG entry at top
- [x] QA gates: gofmt / build / staticcheck / `go test ./... -count=1`
- [x] Local UI check (scratch PG16 + Playwright): idle → no edge; up dialup row → edge + cloud appear on the 15 s poll, label painted, particle flows, cloud fitted into view; down row → edge + cloud removed; edge added under NOC focus inherits the dim
- [x] PR #245 + 2 adversarial review rounds (round 1: label never painted by any style rule, applyFilters un-hid the graph during expansion, focus dim ignored — all fixed; round 2: sound) — merged 2026-09-06 02:38 UTC (repo has no required checks, so `--auto` merged at once; PR-branch CI was green on the identical tree)
- [x] Deployed rust-01 2026-09-06 02:55 UTC — `/api/version` = 0.11.237, container healthy, public URL serves the new diagram JS
- [ ] Follow-up (not this change): master CI run 34007013331 failed once on `internal/irc` `TestTeardownConn_UnwindsLoops_AUDIT319` (20 s timeout) with a recovered nil-pointer panic at `internal/irc/bot.go:460` — `irc.IRC()` returns nil for an empty nick and `Bot.Start` dereferences it. Passed on the PR branch and 4× locally under -race; rerun of the failed job went green on all six jobs (2026-09-06 03:05 UTC), confirming a flake.

## Post-deploy checklist (user)
- Open /admin/connections: DC2-FW1 shows NO line to the cloud; NUDAY-FW shows a green "1 connected" line while `dialup-76.66.145.45` is up.
- Connect a remote-access client to DC2-FW1: within 15 s a green "1 connected" line appears without reload; disconnect: it disappears.
- Legend "Off-Net" toggle still hides/shows the live line; clicking it opens the VPN panel.

## Review
- Off-net edge (2026-09-06): prod investigation first (DC2-FW1 RA_* / NUDAY-FW TL-RA-IKEv2 are config-only rows, status unknown, empty remote_ip; a connected peer is its own `dialup-<ip>` row) fixed the rule to "≥1 unmatched tunnel up". Client-only change, no API work. Review round 1 caught that the old label had never been painted either — worth remembering: an edge `label` in data means nothing without a `data(label)` style rule on that selector.

# DB volume growth — 2026-09-05 (plan: ~/.claude/plans/why-is-the-db-cosmic-treasure.md)

Diagnosis: retention works; NUDAY-FW policy 20 `IP_BLOCK-2` syslog went 0.8M → 3.4M rows/day, 30-day window × ~1 KB/row → ~190 GB steady state. User expanded disks (root 80 GB, data 350 GB) and chose to KEEP 30 days. Expect plateau ~60–65 % by early Oct.

- [x] Step 0 — disks expanded on rust-01 (user; verified 77 GB / 344 GB)
- [x] Item 1 — Retention page: rows/day, MB/day, projected steady-state vs volume — PR #244, v0.11.236, DEPLOYED rust-01 2026-09-06 00:15 UTC and verified (buckets flowing, data_disk_total_bytes=344 GB = df)
- [ ] Item 2 — days-until-full forecast + SERVER_DISK_FORECAST alert, threshold = SystemSetting (own plan-mode unit)
- [ ] Item 3 — populate threshold/current_value on SERVER_DISK_HIGH (`internal/alerts/serverdisk.go:141`) — rides with item 2
- [ ] Item 4 — (user, FortiGate) `set logtraffic-start disable` on policies 14 + 17 only; NEVER 20/24
- [ ] Item 5 — partition syslog_messages (existing program step 4); VACUUM ANALYZE + postgresql.conf tuning (pending operator steps)

## Review
- Item 1 (2026-09-06): plan went 3 adversarial rounds (mutex-by-value, partial-batch overcount, flush-under-lock, div-by-zero on never-analyzed, volume size vs reserved blocks, README badge); diff review found 1 defect (wall-clock-flaky test seed) — fixed. CI green, merged, deployed. Prod: 1,089 B/row on disk; first bucket 965 sev-5 rows/min.
