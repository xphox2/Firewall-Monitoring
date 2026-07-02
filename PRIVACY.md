# Privacy

Firewall-Mon is **self-hosted**. It runs entirely on infrastructure you control,
and it is designed so that the maintainers of this project never see your data.

## No telemetry, no phone-home

Firewall-Mon does **not** send analytics, usage statistics, crash reports,
license checks, or "update available" pings anywhere. There is no hidden
outbound connection to the project's authors or any third party. You can verify
this: the only outbound network connections the software makes are the ones
described below, and all of them are either to **your own devices** or to
**opt-in, explicitly-configured** endpoints.

## What connects where, by default

| Traffic | Direction | Default | Notes |
|---|---|---|---|
| SNMP polling | server/probe → your firewalls | on (for configured devices) | UDP/161 to devices you add. |
| SNMP traps / syslog / sFlow | your firewalls → server/probe | on (listeners) | Inbound only; you point your devices at it. |
| Probe → server relay | probe → your server | on (if you deploy probes) | HTTPS, bearer-authenticated, to the server address you configure. |
| Email / Slack / Discord / webhook alerts | server → your endpoints | off until configured | Only to the notification targets you set. |
| IRC bot | server → your IRC server | off until configured | Posts to your ops channel. |

## Opt-in outbound features (off by default)

These reach the public internet **only if you turn them on**:

- **Threat-intelligence feeds** (`THREAT_FEEDS_ENABLED`, default `false`) —
  downloads public IP blocklists (e.g. blocklist.de, CINS, Spamhaus, Emerging
  Threats, Tor exit list) over HTTPS. The named source URLs are in the
  configuration and can be changed or disabled.
- **GeoIP enrichment** — reads **local** MaxMind `.mmdb` files from a directory
  you provide (`GEOIP_DB_DIR`). Firewall-Mon does **not** download these
  databases automatically; you supply them.

There is no automatic update checker and no dependency that calls home at runtime.

## Data you store

All monitoring data (device inventory, interface/VPN stats, syslog, flow
samples, alerts, config revisions) is stored in **your** PostgreSQL database.
Retention is configurable per data type — see
[`docs/DATA-RETENTION.md`](docs/DATA-RETENTION.md). Stored credentials (SNMP
communities, SNMPv3/SSH/IRC/SMTP secrets) are encrypted at rest with AES-256-GCM.

## Reporting a privacy concern

If you believe Firewall-Mon transmits data in a way this document does not
describe, please treat it as a security issue and report it via
[`SECURITY.md`](SECURITY.md).
