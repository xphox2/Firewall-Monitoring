# Firewall-Mon & Firewall-Collector — Engineering Security Audit (2026-07-02)

Pre-alpha adversarial security review of both repos. Method: 14 parallel finder
dimensions (frontend XSS, ingestion trust, probe-key blast radius, secrets/crypto,
auth/session, authz/route exposure, SSRF, SQL surface, DoS, collector SSH/TFTP,
algorithms lens, design-patterns lens, supply-chain, deploy hardening), each
finding verified by 3 independent refuters — only findings surviving a 2-of-3
"is this really exploitable?" vote are listed as confirmed.

**Result: 29 raw findings → 12 confirmed (6 HIGH / 4 MEDIUM / 2 LOW), 17 refuted.**

Server findings are **RESOLVED** in server v0.10.556. Collector findings are
**RESOLVED** in collector v1.2.162.

---

## HIGH

### H1 — Spoofed syslog config-change packets → SSH/TFTP config-fetch storm  · collector · RESOLVED (v1.2.162)
`cmd/collector/main.go`. The syslog receiver has no source-IP allow-list (only a
per-source PPS limiter). A spoofed UDP packet whose body carries a config-change
logid and a monitored firewall's IP is treated as a real commit; the debounce key
includes the attacker-controlled `cfgtid`, so varying it defeats the 60s debounce
and inserts unbounded live timers, each firing an SSH + full-config TFTP fetch
against the production firewall. **Fix:** gate the syslog→backup trigger on a
device-fleet source-IP allow-list (like TFTP), cap `cfgBackupTimers`, and throttle
per-device backups independent of `cfgtid`.

### H2 — IRC credentials returned in cleartext by the IRC API · server · RESOLVED (v0.10.556)
The IRC GET/echo handlers decrypted stored secrets into the JSON response.
Added `RedactIRCServer`/`RedactIRCChannel`; all read/echo paths mask, update
handlers treat the mask as "unchanged". Connect/Test still read plaintext
server-side.

### H3 — Session revocation failed open on DB error · server · RESOLVED (v0.10.556)
`ValidateToken` accepted a token when the token-version lookup errored, so a
stolen JWT survived revocation during DB stress. Now fails closed. Test:
`TestValidateToken_FailsClosedOnDBError`.

### H4 — Unauthenticated IDOR on `/api/public/*` via `device_id` · server · RESOLVED (v0.10.556)
`resolvePublicDeviceID` ignored `public_visible` for a supplied `device_id`.
Now gated on `enabled AND public_visible`.

### H5 — Public display toggles enforced client-side only · server · RESOLVED (v0.10.556)
`GetPublicVPN`/`GetPublicConnections` ignored the `public_show_*` toggles and the
connections endpoint had no device filter. Toggles now enforced server-side;
connections restricted to both-endpoints-public pairs.

### H6 — Webhook test endpoint DNS-rebind SSRF · server · RESOLVED (v0.10.556)
The test client bypassed `SafeDialContext`. Now uses the guarded transport.

---

## MEDIUM

### M1 — Probe device allow-list failed open · server · RESOLVED (v0.10.556)
`probeDeviceIDs` returned nil on error, which the ingestion guards read as
"skip enforcement". Now returns a deny-all empty set on error.

### M2 — sFlow/counter attribution trusts the datagram agent IP · collector · RESOLVED (v1.2.162)
`cmd/collector/main.go` attributes samples by the `SamplerAddress` field parsed
from the datagram body, never compared to the UDP source. A spoofed datagram can
poison a firewall's analytics/threat pipeline. **Fix:** bind attribution to the
true UDP source + a source-IP allow-list.

### M3 — Event/revision queues re-queue permanently-rejected batches forever · collector · RESOLVED (v1.2.162)
`internal/relay/relay.go`: `sendBatchesSequential` requeues on any failure, so a
permanently-rejected (4xx) batch is retried every cycle forever and evicts good
data at the byte cap. **Fix:** drop non-retryable 4xx (as the metric-queue path
already does); requeue only on transient errors.

### M4 — `config.env` world-readable in Docker · server · RESOLVED (v0.10.556)
`entrypoint.sh` wrote the JWT-secret-bearing config at 0644 on a host bind mount.
Now `chmod 0600` + `chown fwmon`.

---

## LOW

### L1 — VPN tunnel status rendered unescaped (device-detail) · server · RESOLVED (v0.10.556)
### L2 — VPN status rendered unescaped (public dashboard) · server · RESOLVED (v0.10.556)
Both status sinks now route through the escape helper. Enum-constrained today;
the public one is internet-facing, so closed as defense-in-depth.

---

## Refuted (17) — notable accepted-risk / not-materially-exploitable

The adversarial pass rejected 17 candidates. The most useful to record, because
they look scary but are intentional/mitigated:

- **HSTS not emitted behind a TLS-terminating proxy** — standard behavior (RFC 6797
  ignores HSTS over plain HTTP); the shipped nginx config re-adds it; gating on
  `X-Forwarded-Proto` would contradict `SetTrustedProxies(nil)` (AUDIT-097).
- **Threat-feed / proxy rate-limit collapse / NOC SSE ceiling** — accepted, documented
  limitations (env-only config source, opt-in, single-tenant admin-only surface).
- **SSH `HostKeyCallback` alert-only TOFU** — the documented server-authoritative
  design; MITM precondition on an isolated mgmt segment; key-auth path exists.
- **AuthManager mutex across bcrypt / login-attempt map growth** — the "rotating
  usernames" exploit never reaches bcrypt; the map has a background pruner.
- **Login mints `user_id=1` on lookup failure** — coincides with the real single
  admin ID; version desync fails closed. Hygiene, not a bypass.

Full per-finding refutation reasoning is retained in the audit run journal.

---

## Cross-repo follow-ups

The three collector findings (H1, M2, M3) were fixed in collector v1.2.162; the
syslog/sFlow source-IP allowlist (H1/M2) reuses the existing `applyTFTPAllowlist`
machinery. All 12 confirmed findings are resolved as of server v0.10.556 /
collector v1.2.162.
