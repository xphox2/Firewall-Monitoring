# Converting a populated table to monthly partitions

**Audience:** operators who saw a startup log line like:

```
WARNING: AUDIT-028 partition migration: "interface_stats" has existing rows; NOT auto-converting … per docs/partition-migration.md
```

Firewall-Monitor range-partitions its high-volume time-series tables by month
(`interface_stats`, `system_status`, `syslog_messages`, `syslog_summaries`,
`trap_events`, `flow_samples`) so old data is reclaimed by **dropping whole
partitions** instead of slow, bloat-inducing `DELETE`s.

On a **fresh** install these tables are created partitioned automatically (the
`partition_high_volume` migration converts them while they're empty). On an
**existing** deployment with data, the server does **not** auto-convert — a
copy-rewrite of a ~100M-row table is far too heavy to run at startup and would
hold a long lock. You run the conversion below in a maintenance window. Until you
do, the table keeps working as a plain table and retention uses batched `DELETE`
(correct, just not space-reclaiming).

> **Planned (not yet available):** a guided admin-UI migration utility that
> performs this data-preserving conversion for you (progress, safety gating,
> resumable), so you won't need to run the SQL below by hand. Until it ships, use
> the manual procedure here.

## Why it isn't automatic

Postgres cannot convert a table to partitioned in place. The procedure is
create-a-new-partitioned-table → copy the data → swap names. For a large table
that copy is minutes to hours of I/O and a heavy lock. Do it deliberately, with a
backup, not on a deploy restart.

## Before you start

- **Back up the database** (`pg_dump` or a volume snapshot). This is a destructive
  rewrite; the backup is your rollback.
- Ensure **~2× the table's size** in free disk (the copy coexists with the
  original until the swap).
- Decide your **retention window** — you can copy only the rows you intend to
  keep (e.g. last 90 days) and let the rest be discarded with the old table.
- **Stop the writers** for the table being converted (recommended):
  `systemctl stop fwmon-api fwmon-poller fwmon-trap` (or stop the container).
  Converting with writers running risks losing rows written during the copy. If a
  brief write outage is unacceptable, accept that rows written mid-copy into the
  old table after the `INSERT … SELECT` snapshot will be lost.

## Procedure (worked example: `interface_stats`)

The partition key is always `timestamp`. The composite primary key must include
it (`(id, timestamp)`), because Postgres requires the partition key in every
unique constraint.

```sql
-- 1. Swap the plain table out and create the partitioned parent.
BEGIN;
ALTER TABLE interface_stats RENAME TO interface_stats_old;
CREATE TABLE interface_stats (LIKE interface_stats_old INCLUDING DEFAULTS)
  PARTITION BY RANGE (timestamp);
ALTER TABLE interface_stats ADD PRIMARY KEY (id, timestamp);
COMMIT;

-- 2. Create one partition per month you are keeping (repeat per month present
--    in the retention window). The app's EnsurePartitions will create the
--    current month + 6 ahead on the next start, so you only need the HISTORICAL
--    months here.
CREATE TABLE interface_stats_202601 PARTITION OF interface_stats
  FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
-- … 202602, 202603, … as needed …

-- 3. Copy the data you are keeping (filter to your retention window).
INSERT INTO interface_stats
  SELECT * FROM interface_stats_old
  WHERE timestamp >= now() - interval '90 days';

-- 4. Recreate the per-partition indexes the app expects, for each historical
--    partition you created in step 2 (current+future months get theirs from
--    EnsurePartitions on next start):
CREATE INDEX idx_interface_stats_202601_device_ts    ON interface_stats_202601 (device_id, timestamp);
CREATE INDEX idx_interface_stats_202601_timestamp     ON interface_stats_202601 (timestamp);
CREATE INDEX idx_interface_stats_202601_device_idx_ts ON interface_stats_202601 (device_id, "index", timestamp);

-- 5. Drop the old table once you've verified the copy (see below).
DROP TABLE interface_stats_old;
```

### Per-table index notes

EnsurePartitions creates `(device_id, timestamp)` and `(timestamp)` on every
partition. Add these extras to your historical partitions to match:

| Table | Extra per-partition index |
|---|---|
| `interface_stats` | `(device_id, "index", timestamp)` |
| `syslog_messages`, `trap_events` | `(severity)` |
| `system_status`, `syslog_summaries`, `flow_samples` | none (the two defaults suffice) |

(For `flow_samples`' `src_addr`/`dst_addr` lookups, create those indexes on the
**parent** so future partitions inherit them.)

## Verify

```sql
-- Partition pruning: the planner should scan ONE month's partition, not the parent.
EXPLAIN SELECT * FROM interface_stats
  WHERE device_id = 1 AND timestamp BETWEEN '2026-06-01' AND '2026-06-30';
-- Look for "interface_stats_202606" in the plan and NO sibling-month partitions.
```

Restart the services. The `has existing rows` warning should no longer appear for
that table, and EnsurePartitions will report creating the current+future monthly
partitions.

## Rollback

- **Before** `DROP TABLE … _old`: reverse the swap —
  `DROP TABLE interface_stats; ALTER TABLE interface_stats_old RENAME TO interface_stats;`
- **After** the drop: restore from the backup taken in the first step.

Repeat for each table named in the warning. `syslog_messages` has dual
critical/info retention; it is safe to partition, but the app keeps using
severity-scoped `DELETE` for it (it never drops whole `syslog_messages`
partitions), so converting it is optional and only helps insert/scan locality.
