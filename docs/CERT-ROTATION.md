# TLS Certificate & Credential Rotation

This document describes how to rotate the central server's TLS certificate and
the probe registration credentials.

> **Grounded in the code.** Server TLS is configured by `SERVER_ENABLE_TLS` /
> `SERVER_TLS_CERT` / `SERVER_TLS_KEY` (`internal/config/config.go`). Probe
> credentials are registration keys, rotated via the admin API. Anything this
> doc says is *not implemented* really isn't — it's called out so operators
> don't plan around a feature that doesn't exist.

## What exists today

| Component | Mechanism | Rotation |
|---|---|---|
| Public TLS (dashboard + API + probe ingestion) | One-sided TLS, `SERVER_TLS_CERT`/`SERVER_TLS_KEY` | Replace the cert files, **restart the service** |
| Probe authentication | Per-probe **registration key** (hashed at rest) | `POST /admin/api/probes/:id/regenerate-key` |

### Not implemented (don't plan around these)

- **Server-side mTLS / client-certificate verification of probes.** The server
  terminates **one-sided** TLS; it does not verify a client certificate.
  Probes authenticate with their registration key over TLS, not with a client
  cert. (The `PROBE_TLS_*` / `PROBE_MTLS_*` env vars in the config struct
  configure the *collector's* HTTPS client, not server-side client-cert
  verification.)
- **Hot cert reload (SIGHUP).** `cmd/api` does not watch for a signal to
  re-read the cert. A cert swap requires a **process restart**.
- There is no `setup.sh`, no `/api/admin/rotate-mtls` endpoint, and no
  `PROBE_FORCE_REREGISTER` flag.

## Public TLS

The server serves the admin UI, the public dashboard, and the probe API on one
listener. TLS is enabled by:

```
SERVER_ENABLE_TLS=true
SERVER_TLS_CERT=/etc/firewall-mon/tls.crt   # default
SERVER_TLS_KEY=/etc/firewall-mon/tls.key    # default
```

If `SERVER_ENABLE_TLS=true` and either path is empty, the server refuses to
start. Note the cookie interplay (AUDIT-024): set `COOKIE_SECURE=true` only
when TLS is actually terminated at or before this server, or browsers silently
drop the session cookie. For a plain-HTTP deployment behind a TLS-terminating
proxy, keep `SERVER_ENABLE_TLS=false` and let the proxy hold the cert.

### Production: Let's Encrypt

1. Install certbot: `apt install certbot`.
2. Obtain a cert: `certbot certonly --standalone -d stats.example.com`.
3. Point the server at the live files:
   ```
   SERVER_TLS_CERT=/etc/letsencrypt/live/stats.example.com/fullchain.pem
   SERVER_TLS_KEY=/etc/letsencrypt/live/stats.example.com/privkey.pem
   ```
4. certbot auto-renews ~30 days before expiry. Because there is **no SIGHUP
   reload**, add a deploy hook that restarts the service after renewal:
   ```
   certbot renew --deploy-hook "systemctl restart firewall-mon"
   ```

### Development: self-signed

Generate a throwaway cert and point `SERVER_TLS_CERT`/`SERVER_TLS_KEY` at it:

```
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls.key -out tls.crt -subj "/CN=localhost"
```

Browsers will warn — replace with a real cert before production.

### Manual / corporate CA renewal

1. Obtain the new PEM cert + key from your CA.
2. Overwrite the files at `SERVER_TLS_CERT` / `SERVER_TLS_KEY`.
3. **Restart** the server (`systemctl restart firewall-mon`). In-flight
   connections drop on restart; schedule a brief maintenance window or roll
   behind a load balancer.

## Probe credential rotation

Probes do not hold a TLS client cert; they hold a **registration key**. To
rotate one (e.g. on suspected compromise):

1. `POST /admin/api/probes/:id/regenerate-key` (admin-authenticated). This
   rotates the key and its stored registration setting in a single
   transaction (AUDIT-085).
2. Distribute the new key to the probe out-of-band and update the collector's
   `PROBE_REGISTRATION_KEY`.
3. The probe re-registers with the new key; the old key no longer resolves.

To revoke a probe entirely, `DELETE /admin/api/probes/:id` (note: this removes
the probe row only — see `docs/DATA-RETENTION.md` § Data-subject rights for the
data it leaves behind).

## Audit trail

Privileged admin actions — including key regeneration and probe deletion — are
recorded in the **`audit_logs`** table (AUDIT-078) and readable via
`GET /admin/api/audit` (filter by `?actor=`, `?action=`, `?hours=`). Failed
(4xx/5xx) attempts are recorded too. Ship the server log to your SIEM per your
policy; the audit table itself is append-only and not auto-pruned.

## Incident response (suspected server key compromise)

1. **Revoke** the cert at your CA (Let's Encrypt: revoke via the ACME client;
   corporate CA: per your CA's process).
2. **Replace** the cert + key files and **restart** the server.
3. **Rotate** probe registration keys (per probe, as above) if you suspect the
   relay traffic was observed.
4. **Review** `audit_logs` and `login_attempts` for activity in the compromise
   window.

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — cipher/protocol guidance.
- [Let's Encrypt docs](https://letsencrypt.org/docs/) — the ACME flow.
- `docs/DATA-RETENTION.md` — what a probe deletion does and doesn't remove.
- `MIGRATING.md` / `docs/SUPPORT-MATRIX.md` — probe↔server version compatibility.
