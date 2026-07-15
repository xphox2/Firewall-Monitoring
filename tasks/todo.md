# Open follow-ups from PR #117 review (v0.11.100, 2026-07-15)

- [x] **TELEMETRY_STALE / degraded-collection alert.** SHIPPED v0.11.101 — two-signal (vitals + interface stats) staleness detection with 3-cycle debounce, admin threshold knob, silent DEVICE_OFFLINE supersede. Deliberately out of scope (future work): Event Rules source for device-lifecycle alerts (DEVICE_OFFLINE / TELEMETRY_STALE / PROBE_DATA_LAG all bypass event-rule suppression today); per-device observed-cadence adaptive thresholds; probe-wide clock-skew detector (uniform staleness across one probe's devices while data flows).
- [ ] Spool-replay skew (pre-existing, minor): a collector draining hours of buffered batches after a server outage bumps `last_polled` to `now` per batch, holding a device that died mid-outage "online" for the drain window. If it ever bites: bump with the batch's max row timestamp clamped to now.
- [ ] `ReceiveCommandResult` doesn't bump `last_polled` despite being device-targeted SSH evidence — revisit when the probe-command allow-list grows beyond `noop` (IPSec apply).

---

# Post-publish test plan — v0.11.16 on rust-01 (2026-07-03)

Everything that changed since the last prod deploy needs a live check. Items marked
**(prod-only)** could NOT be fully verified in the local walkthrough and matter most.

## 0. Pre-flight / upgrade
- [ ] Note current prod version (`GET /api/version` or admin-page console log) — if it's below 0.10.566, Tranche 1 (RBAC/tokens/2FA) is ALSO new in this jump
- [ ] `pg_dump` backup before pulling images
- [ ] Confirm `ENCRYPTION_KEY` and `JWT_SECRET_KEY` are pinned in the compose env (key-continuity incident: losing the key orphans every stored secret)
- [ ] Pull `xphox/*:0.11.12`, restart, check api logs: migrations v20–v27 apply cleanly (all additive; existing admin keeps rights, live sessions survive, pre-upgrade JWTs honored as admin ≤24h)
- [ ] Admin page console logs `Firewall-Mon v0.11.12`
- [ ] No alert re-fire storm right after restart (restart-safe dedup should hold)

## 1. Tranche 1 — access control (skip if prod already ran 0.11.0)
- [ ] Settings → Users: create an operator + a viewer. Server issues a temp password (your typed one is ignored) and forces a change on first login
- [ ] Viewer login: role badge in sidebar ("viewer · name"), all add/edit/delete/ack buttons hidden; a forced mutation returns 403 `insufficient_role`
- [ ] API tokens: create a read-scope token, `curl -H "Authorization: Bearer fwm_…"` works, token shown once, revoke works
- [ ] TOTP 2FA: enroll a TEST account first (not your admin); verify the two-step login and one recovery code; the last-admin lockout runbook is in docs/OPERATIONS.md

## 2. Alert policy editor (v0.11.2/.6/.7/.8)
- [ ] Policy modal shows: Clear below / Mode / K columns, PagerDuty+Opsgenie+Teams checkboxes, Escalation Steps builder
- [ ] Save a policy using all of them; reload and confirm round-trip
- [ ] Validation: non-ascending step times and unknown channels are rejected with clear errors

## 3. Hysteresis F14
- [ ] On a device that hovers near its CPU/memory threshold, set "Clear below" a few points under the fire threshold
- [ ] Expect: one fire, NO fire/resolve ping-pong per poll cycle, auto-resolve only once the metric drops under the clear band

## 4. Z-score baselining F17
- [ ] Set Mode=zscore (K=3) on CPU or memory for a device with 24h+ of history
- [ ] Alert message shows "baseline threshold: X" (device's own baseline + K·σ; static threshold acts as a floor)
- [ ] A device with no history keeps behaving statically (no false quiet)

## 5. Flap suppression F13
- [ ] Defaults: 5 short-lived fire→resolve cycles (<120s active) within 60 min → further fires muted
- [ ] Alerts page shows the muted fires tagged `[FLAPPING]`, no email/Slack for them, recoveries muted too, auto-resumes when the flapping ages out
- [ ] Known cosmetic nit from the walkthrough: the suppression chip on a flap-suppressed row reads `MAINT` — don't be confused by it (fix queued)

## 6. Webhook HMAC signing F18 **(prod-only: live delivery)**
- [ ] Settings → Notifications: set Webhook Signing Secret
- [ ] Receiver MUST be on a public (non-RFC1918, non-loopback) address — the SSRF guard refuses internal targets with no bypass
- [ ] Verify `X-FirewallMon-Timestamp` + `X-FirewallMon-Signature` = HMAC-SHA256 over `timestamp.body` (verification snippet in docs/OPERATIONS.md); test button and real alerts are both signed

## 7. PagerDuty / Opsgenie / Teams **(prod-only: real keys)**
- [ ] Enter routing key / API key / Teams URL in Settings; use each Test button
- [ ] Enable the channels on a policy — routing is policy-gated hard (no presence-only fallback like legacy channels)
- [ ] Fire a real alert: PD incident opens with dedup key, severity mapped (critical→critical/P1, warning→warning/P3)
- [ ] On recovery: PD incident RESOLVES / Opsgenie alert CLOSES (no double-page), Teams card severity-colored

## 8. Escalation step chains F19 **(prod-only: success-path increment)**
- [ ] Policy with steps (e.g. step 1: Slack after 5 min; step 2: PagerDuty + email override after 15 min)
- [ ] Leave an alert unacked: step 1 fires once at ~5 min to exactly its channels, step 2 at ~15 min; acking stops the chain
- [ ] This is the one path the local walkthrough couldn't fully close: sends were SSRF-blocked, which correctly did NOT advance the step counter (retry-not-skip verified). Verify live that a SUCCESSFUL send advances EscalationCount and never double-fires
- [ ] A failing channel shows "step N send failed" in poller logs and retries next cycle

## 9. Incident grouping F12
- [ ] Take a lab device offline: DEVICE_OFFLINE notifies once + incident opens
- [ ] While it's open, other alerts for that device attach (INC#n chip in alerts table) and send NO individual notifications; other devices' alerts unaffected
- [ ] Bring it back: single summary "Incident resolved: … — N alerts over M minutes"; incident survives poller restarts while open
- [ ] `GET /admin/api/incidents` and `/admin/api/incidents/:id/alerts` return the story

## 10. MTTA/MTTR + noisiest alerts F05/F06
- [ ] Reports page preview shows the new Operations section (renders even with sparse data)
- [ ] After a few days of real acks: MTTA counts ONLY operator acks (auto-resolves excluded); MTTR includes them; recovery companions excluded
- [ ] Noisiest-alerts top-10 (type × device) shows fire counts + how many were suppressed (maintenance/flap/incident)
- [ ] Scheduled email report carries the same section

## 11. Settings page redesign (v0.11.14)
- [ ] `/admin/settings` shows the vertical section nav (Account / Access / Alerting / Notifications / Reports / Display / Detection), Account active by default
- [ ] Deep link survives refresh (`/admin/settings#notifications`); Back button unaffected by section clicks
- [ ] Edit a threshold → sticky "1 unsaved change" bar; Discard reverts; Save persists (reload to confirm)
- [ ] Typing in password / 2FA / user / token / test-email-override fields does NOT raise the bar
- [ ] Operator/viewer: no Access section, no save bar; `#access` deep link redirects to Account
- [ ] Day + Night themes and a narrow window (nav collapses to horizontal strip)

## 12. Profile page + MFA onboarding wizard (v0.11.16, migration v28)
- [ ] Migration v28 applies (admins gains email/full_name/mfa_prompt_dismissed_at)
- [ ] Profile link appears above Logout on all pages (incl. device-detail/irc/probes/sites) and in the mobile slide-in sidebar
- [ ] `/admin/profile`: username/role/member-since read-only; email + display name save and survive reload; Settings no longer has an Account section; `/admin/settings#account` redirects to the profile
- [ ] After login without 2FA: wizard offers once; "Not now" → re-offered next login; "Don't ask me again" + checkbox → never again (server-side), but the profile banner + Enable button remain
- [ ] Full enrollment on a test account: QR scans, `otpauth://` link opens the authenticator when browsing on the phone itself, wrong code shows a recoverable error, recovery codes copy + download, forced re-login with password + code works
- [ ] Forced-password-change accounts get the password modal, never the wizard
- [ ] Audit log shows the PUT /admin/api/me and mfa-decline entries with the right actor

## 13. NetFlow/IPFIX (server v0.11.20 + collector v1.3.0, migration v29)
- [ ] `migrate-status` shows v29; `\d flow_samples` on prod shows flow_source/flow_start/flow_end/firewall_event/... columns; `\d flow_rollups` shows flow_source
- [ ] Flows page renders unchanged for existing sFlow data (Source column shows "sFlow", no mixed-source banner)
- [ ] Pull collector 1.3.0 on the Synology probe; startup logs show "NetFlow/IPFIX: true (ports 2055/4739, dedup prefer-netflow)"
- [ ] `config system netflow` on the FortiGate → collector IP:2055; flows appear labeled "NetFlow v9"; byte totals sane vs SNMP interface counters
- [ ] With sFlow ALSO enabled briefly: collector logs the dedup suppression line, no mixed-source banner appears, byte totals do NOT double; disable NetFlow → sFlow resumes within ~5 min (failover)
- [ ] `go run ./cmd/netflow-test -target <collector>:2055 -proto all` from a whitelisted device IP works as a smoke tool
- [ ] Collector /metrics shows firewall_collector_netflow_events_total{event="ok"} advancing; template cache file exists under the queue dir

## Walkthrough results for reference (local, v0.11.12–.16, PG16)
All verified locally with the production AlertManager code: F14 band hold/release,
F17 dynamic threshold + static-floor suppression, F13 [FLAPPING] + muted recovery,
F12 open/attach-mute/close + INC chips + endpoints, F19 due/route/retry-not-skip,
step validation, policy round-trip, HMAC cross-verified vs independent impl,
role hiding + insufficient_role, forced first-login change, report Operations section.
