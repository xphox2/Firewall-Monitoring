# HTTPS Certificate Rotation Policy

This document describes the recommended TLS certificate rotation policy
for the Firewall-Monitoring central server. The probe side of the
deployment is covered separately in `xphox2/Firewall-Collector/SECURITY.md`.

## TL;DR

| Component | Rotation cadence | Method | Default |
|---|---|---|---|
| Public TLS (dashboard, API) | Every 90 days | Let's Encrypt via `certbot` (recommended) or manual | Self-signed at first install |
| Internal mTLS (probe ↔ server) | Every 1 year | Operator-initiated rotation via `/api/admin/rotate-mtls` | Per-probe cert at first registration |
| Service-to-service (SMTP, Slack, Discord webhooks) | N/A | TLS to those services is configured by the upstream CA | n/a |

## Public TLS (dashboard + API)

The server's public endpoint serves both the admin UI and the probe API
on the same port (default `:8443`). The recommended setup:

### Production: Let's Encrypt via certbot

1. Install certbot on the server host: `apt install certbot` (or your distro's
   equivalent).
2. Get a cert: `certbot certonly --standalone -d stats.example.com`.
3. Set `SSL_CERT_FILE=/etc/letsencrypt/live/stats.example.com/fullchain.pem` and
   `SSL_KEY_FILE=/etc/letsencrypt/live/stats.example.com/privkey.pem` in
   the server's environment.
4. certbot will auto-renew at 60 days (30 days before expiry). Add a
   `post-renew` hook to restart the server: `systemctl restart firewall-mon`.

### Self-signed (development only)

The default `setup.sh` generates a self-signed cert at first install with
365-day validity. Browsers will warn. Replace with Let's Encrypt before
production.

### Manual renewal

If you can't use Let's Encrypt (corporate CA, internal CA, etc.):
1. Get the new cert from your CA (PEM format).
2. Replace `/etc/firewall-mon/tls/fullchain.pem` and `privkey.pem` (or
   wherever your `SSL_CERT_FILE` / `SSL_KEY_FILE` point).
3. `systemctl reload firewall-mon` (the server supports SIGHUP for
   graceful cert reload without dropping in-flight connections).

## Internal mTLS (probe ↔ server)

The probe connects to the server over mTLS when `PROBE_TLS_CERT` and
`PROBE_TLS_KEY` are configured on the probe side (and the server has
`SSL_CLIENT_CA_FILE` pointing at the CA that signed the probe cert).

The probe's cert is per-deployment:
- Generation: `openssl req -new -x509 -newkey rsa:2048 -nodes -keyout probe.key -out probe.crt -days 365 -subj "/CN=firewall-collector-prod"`
- Distribution: out-of-band (scp, your secret manager of choice). Never
  committed to git.
- Rotation: 1 year is reasonable. The probe re-reads the cert on
  `SIGHUP` (the collector handles this automatically) without a restart.

When you rotate the probe cert:
1. Generate the new cert+key as above.
2. Replace `PROBE_TLS_CERT` and `PROBE_TLS_KEY` paths on the probe host.
3. `kill -HUP $(pidof firewall-collector)` — the probe re-reads the cert.
4. Update the server's `SSL_CLIENT_CA_FILE` if the new cert is signed by
   a new CA (e.g. the corporate root cert was rotated).

The collector and server are wire-compatible across a cert rotation; the
old cert is still trusted by the server until the new one is in place.

## Revocation

If a probe cert is compromised:
1. Add the cert's serial number to a Certificate Revocation List (CRL)
   and have the server check it on every mTLS handshake. (Not currently
   implemented in the server; tracked as AUDIT-067 follow-up.)
2. **Faster interim fix:** rotate `PROBE_SERVER_URL` to a different
   hostname (e.g. a maintenance URL) that the compromised probe can't
   reach. The probe will fail to heartbeat and you'll get a 4xx
   storm in the logs.

## Audit logging

The server logs the following for every mTLS handshake (with the
`PROBE_AUDIT_LOG=true` env var):
- Probe CN (common name) and serial number.
- TLS version (min allowed: 1.2, default 1.2; recommended: 1.3).
- Cipher suite (default: TLS_AES_128_GCM_SHA256, etc.).
- Client IP.
- Timestamp.

These logs are stored in `logs/audit.log` and should be shipped to
your SIEM (Loki, Splunk, Datadog) per your organization's policy.

## Incident response

If you suspect the server's private key has been compromised:
1. **Revoke** the cert at your CA (Let's Encrypt: revoke via the
   dashboard; corporate CA: per your CA's process).
2. **Replace** the cert and key on the server. `systemctl reload
   firewall-mon`.
3. **Force re-registration** of all probes. Set
   `PROBE_FORCE_REREGISTER=true` on the server for one full heartbeat
   cycle (default 60s) to invalidate all existing bearer tokens.
4. **Audit** `logs/audit.log` for any successful handshakes after the
   suspected compromise window.
5. **Notify** affected tenants per your incident response runbook
   (also see `docs/DATA-RETENTION.md` § Breach notification).

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
  for the recommended TLS 1.2 / 1.3 cipher suite list.
- [Let's Encrypt documentation](https://letsencrypt.org/docs/) for the
  ACME flow.
- [OpenSSL cookbook](https://www.feistyduck.com/library/openssl-cookbook/)
  for cert generation and inspection.
- `SECURITY.md` in the collector repo for the probe-side counterpart.
