# The local instance — the real console, against the real data

The suite in `../e2e` drives a **mock** shell: the API calls are
intercepted by `page.route()` and answered from fixtures. It is fast, it
never flakes on a slow database, and it is the right shape for a gate that
runs on every push.

It is also blind to a whole class of defect. It never runs the Go server,
never touches the SQL, never applies a migration, and never renders a real
row. Two defects survived it:

- the mobile card was a `role="button"` that **contained** the row's own
  buttons — a control inside a control, which a screen reader announces
  wrongly and axe's `nested-interactive` rule catches;
- the tinted chips were **below the contrast bar** — 3.6:1, 3.8:1 and
  4.0:1 where WCAG AA wants 4.5:1 — and the light theme's green was
  marginal even as plain text on a white card.

Both were found by pointing a browser at the **real binary against a copy
of the production database**.

## What it needs

A local instance of the server, with a copy of the production data:

- a PostgreSQL with the production state (the same dump the daily backup
  makes) and the production schema;
- a bounded sample of the telemetry, because the dump leaves the 262 GB of
  append-only tables out and the console's pages read them;
- the production `ENCRYPTION_KEY`, so the stored device credentials
  decrypt;
- **every outbound target switched off** — no archive to the real bucket,
  no Slack, no Discord, no SMTP, no IRC — so the local instance cannot act
  on the production data.

The setup that assembles that is deployment-specific and lives in
`tasks/localprod/` (gitignored). The shape of it:

```bash
# 1. the state
scp server:/mnt/STORAGE/fwmon-backups/fwmon-state-latest.sql.gz .
gzip -dc fwmon-state-latest.sql.gz | psql -h 127.0.0.1 -p 5433 -d firewall_mon_local

# 2. the schema, and a sample of the telemetry
scp server:/tmp/fwmon-schema.sql .
psql -h 127.0.0.1 -p 5433 -d firewall_mon_local -f fwmon-schema.sql

# 3. the outbound targets, OFF
psql -h 127.0.0.1 -p 5433 -d firewall_mon_local -f neutralise.sql

# 4. the server, with the production key and the local paths
CONFIG_FILE=./local.env DATA_DIR=./data CONFIG_DIR=./config ./fwmon-api
```

## The scripts

They all refuse to run against anything but the local machine — the
features script writes to the database it is pointed at, so a stray run
against production would change a live device's alert configuration.

| script | what it does |
|---|---|
| `walk.mjs` | every page, at three viewports, in both themes: the console errors, the failed network requests, the horizontal overflow, and axe |
| `features.mjs` | the features the console added: the Clear control, the one-write override, the purge estimate, the toast |
| `axe-detail.mjs` | one page's axe violations, with the colours and the ratios |
| `guard.mjs` | the shared guard: the local-only check and the login |

```bash
cd ui-v2
FWMON_LOCAL_PASSWORD=... node e2e-local/walk.mjs --base http://127.0.0.1:8099
FWMON_LOCAL_PASSWORD=... node e2e-local/features.mjs --base http://127.0.0.1:8099
FWMON_LOCAL_PASSWORD=... node e2e-local/axe-detail.mjs --page /admin/v2/devices --theme light
```

`walk.mjs` exits non-zero when a page has a console error, a failed
request, a horizontal overflow or a serious/critical axe violation, so it
can be a gate as well as a survey.

## What it does NOT replace

The mocked suite stays the gate. It runs on every push in seconds and it
catches the regressions. This one needs a copy of the production data, so
it runs when the data is there — before a release, and whenever something
about the console's behaviour with real data is in doubt.
