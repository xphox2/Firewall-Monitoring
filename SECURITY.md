# Security Policy

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for a security vulnerability.**

Email the maintainers privately at the address listed in `LICENSE` / git log, or open a [private security advisory on GitHub](https://github.com/xphox2/Firewall-Monitoring/security/advisories/new) (preferred when the report contains exploit details).

Include:

- A description of the issue and the affected component (`cmd/api`, `cmd/poller`, `cmd/trap-receiver`, `cmd/probe`, or a vendored asset).
- The version (`git describe --tags` or the value of `ServerVersion` from `cmd/api/main.go:34` in your deployment).
- Reproduction steps. A minimal proof-of-concept is appreciated.
- Whether you have observed the issue in production or only in a lab.
- Any mitigations you have already deployed.

We will acknowledge receipt within **5 business days** and provide an initial assessment (accept / decline / need more info) within **10 business days**. A fix or risk-acceptance decision will be communicated within **30 days** for HIGH/CRITICAL severity findings, sooner for actively exploited bugs.

If you do not receive a response within 10 business days, please escalate via a GitHub issue marked `[security]` requesting a private channel — do not include the vulnerability details in the public issue.

## Supported versions

The project follows a rolling-release model. The latest tagged release on `master` is the only fully supported version. Operators on older builds should upgrade before reporting issues unless the report includes evidence the issue affects the latest release.

| Version | Supported |
|---------|-----------|
| latest tagged release | yes |
| previous minor (one back) | best-effort backports for HIGH/CRITICAL |
| older | no |

## Disclosure timeline

Default: **90 days** from acknowledgement, or release of a fix, whichever comes first. We will negotiate a shorter or longer timeline with the reporter for actively-exploited bugs or genuinely-complex remediation.

## Scope

In scope:

- The `cmd/api` HTTP server (admin panel + ingestion).
- The `cmd/poller` SNMP polling daemon.
- The `cmd/trap-receiver` SNMP trap listener (UDP 162).
- The `cmd/probe` collector binary.
- Default configuration in `config.env.example`, `docker-compose.yml`, and `Dockerfile`.
- Build-time supply chain (`go.mod`, vendored JS in `cmd/api/static/`).

Out of scope:

- Operator-introduced misconfiguration (e.g., exposing the admin panel without TLS in front of it).
- Issues in dependencies fixed upstream that we have not yet bumped (please report to the upstream first, then file an issue here once an upstream fix is available).
- DoS against the SNMP trap listener via crafted packets when `SNMP_TRAP_COMMUNITY` is unset on a build older than v0.10.250 (closed by AUDIT-012 — upgrade is the fix).

## Hardening guidance for operators

See `docs/AUDIT.md` for the current audit baseline. The most impactful operator-side controls:

- Set `JWT_SECRET_KEY`, `ADMIN_PASSWORD`, and `SNMP_TRAP_COMMUNITY` explicitly rather than relying on auto-generation.
- Front the admin panel with a reverse proxy that terminates TLS (`docker-compose.proxy.yml` provides a starting point) and configure `CORS_ALLOWED_ORIGINS` to your operator origin only.
- Run the database backups (`pg_dump` plus `/data/.jwt-secret` and `/data/.admin-password`) in step — losing the JWT secret makes every `{enc}` ciphertext in the DB unreadable.
- Keep `cmd/trap-receiver` reachable only from the device management VLAN, not the public internet.
- Review `tasks/lessons.md` and the audit findings in `docs/AUDIT.md` before exposing the panel to a hostile network.

## Hall of fame

We will credit reporters here (with permission) once their finding is resolved.

| Date | Finding | Reporter |
|------|---------|----------|

---

This policy is published under SECURITY.md as required by [GitHub's security policy convention](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository).
