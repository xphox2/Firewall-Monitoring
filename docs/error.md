xphox@rust-01:/opt/Firewall-Monitoring$ docker logs --since 2m firewall-mon
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:01:39 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:01:39 main.go:1440: Starting SNMP Poller...
2026/06/09 00:01:39 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:01:39 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:01:39.936Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:01:39.936Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:01:39 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:01:39 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:01:39 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:39 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:39 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:39 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:39 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:39 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
time=2026-06-09T00:01:39.947Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:01:39.947Z level=INFO msg="Database initialized"
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:01:39 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for alerts
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:01:39 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:01:39 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:01:41 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:01:41 main.go:1440: Starting SNMP Poller...
2026/06/09 00:01:41 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:01:41 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:01:41 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:01:41 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:01:41.236Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:01:41.236Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:01:41 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:41 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:41 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:41 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:41 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:41 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:41 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:01:41 main.go:1471: Database connected
2026/06/09 00:01:41 main.go:53: Starting SNMP poller with interval: 1m0s
2026/06/09 00:01:41 report.go:37: Report scheduler started
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for alerts
time=2026-06-09T00:01:41.262Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:01:41.262Z level=INFO msg="Database initialized"
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:01:41 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:01:41 main.go:167: Polling 3 devices...

2026/06/09 00:01:41 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[220.499ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

time=2026-06-09T00:01:41.601Z level=INFO msg="Admin user already exists, skipping initialization"
time=2026-06-09T00:01:41.618Z level=INFO msg="Static assets: serving from embedded FS (disk dir not found)"
time=2026-06-09T00:01:41.624Z level=INFO msg="Server starting on 0.0.0.0:8080"
2026/06/09 00:01:41 Connected to irc.technicallabs.org:6697 (66.179.9.146:6697)
time=2026-06-09T00:01:42.680Z level=INFO msg="IRC: Connected to irc.technicallabs.org as Barnaby"
time=2026-06-09T00:01:42.688Z level=INFO msg="IRC: NickServ identification result: nick, type \x02/msg NickServ IDENTIFY \x1fpassword\x1f\x02.  Otherwise,"

2026/06/09 00:01:42 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1202.381ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:01:43 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[210.071ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[1.325ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[0.439ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[0.349ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[0.332ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[0.315ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[0.308ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[0.199ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:43 firewall-mon/internal/database/devices.go:250 record not found
[0.182ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:01:43 main.go:1149: Overlay auto-detect: upserted 3 connection(s)
[GIN] 2026/06/09 - 00:01:43 | 200 |   29.020187ms |      172.20.0.1 | POST     "/api/probes/2/interface-stats"

2026/06/09 00:01:43 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[2178.869ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 1 ORDER BY timestamp ASC, id ASC

2026/06/09 00:01:44 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1186.167ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:01:44 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[210.908ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

2026/06/09 00:01:44 main.go:252: Connection cleanup: removed 1 stale auto-detected connection(s)

2026/06/09 00:01:44 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[2.232ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:01:41.368',3,26,'10.25.25.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,7,'169.254.1.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,30,'192.168.35.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,22,'192.168.255.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,1,'198.55.63.193.1','255.255.255.252'),('2026-06-09 00:01:41.368',3,8,'205.207.224.142.1','255.255.255.248'),('2026-06-09 00:01:41.368',3,9,'66.179.9.158.1','255.255.255.240'),('2026-06-09 00:01:41.368',3,6,'192.168.25.254.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,38,'192.168.45.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
[GIN] 2026/06/09 - 00:01:44 | 500 |    5.896737ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
time=2026-06-09T00:01:44.683Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:44.683Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=06ed34752a5f99c3d9f082ab25d789ff err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:44.683Z level=ERROR msg="http request" req=06ed34752a5f99c3d9f082ab25d789ff method=POST path=/api/probes/2/interface-addresses status=500 latency=5.835027ms

2026/06/09 00:01:44 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[1263.204ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 2 ORDER BY timestamp ASC, id ASC
2026/06/09 00:01:44 cleanup.go:402: vendor audit: vendor="fortigate" devices=3 normalizer=rich
2026/06/09 00:01:44 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
2026/06/09 00:01:44 main.go:1492: Shutting down poller...
time=2026-06-09T00:01:44.815Z level=INFO msg="Received signal terminated, shutting down server..."
2026/06/09 00:01:44 main.go:1495: Poller exited
2026/06/09 00:01:44 main.go:118: Poller stopped
time=2026-06-09T00:01:44.815Z level=INFO msg="Server exited"
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:01:46 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:01:46 main.go:1440: Starting SNMP Poller...
2026/06/09 00:01:46 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:01:46 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:01:46 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:01:46 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:01:46.087Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:01:46.087Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:01:46 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:46 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:46 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:46 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:46 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:46 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:46 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for alerts
time=2026-06-09T00:01:46.112Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:01:46.112Z level=INFO msg="Database initialized"
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:01:46 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:01:46 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:01:47 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:01:47 main.go:1440: Starting SNMP Poller...
2026/06/09 00:01:47 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:01:47 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:01:47 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:01:47 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:01:47.462Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:01:47.462Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:01:47 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:47 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:47 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:47 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:47 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:47 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:01:47 main.go:1471: Database connected
2026/06/09 00:01:47 report.go:37: Report scheduler started
2026/06/09 00:01:47 main.go:53: Starting SNMP poller with interval: 1m0s
2026/06/09 00:01:47 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for ping_results
time=2026-06-09T00:01:47.485Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:01:47.485Z level=INFO msg="Database initialized"
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for alerts
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:01:47 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:01:47 main.go:167: Polling 3 devices...

2026/06/09 00:01:47 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[217.466ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

time=2026-06-09T00:01:47.822Z level=INFO msg="Admin user already exists, skipping initialization"
time=2026-06-09T00:01:47.839Z level=INFO msg="Static assets: serving from embedded FS (disk dir not found)"
time=2026-06-09T00:01:47.845Z level=INFO msg="Server starting on 0.0.0.0:8080"
2026/06/09 00:01:47 Connected to irc.technicallabs.org:6697 (66.179.9.146:6697)
[GIN] 2026/06/09 - 00:01:48 | 200 |   38.636268ms |      172.20.0.1 | POST     "/api/probes/2/flows"

2026/06/09 00:01:48 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[2.016ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:01:41.368',3,26,'10.25.25.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,7,'169.254.1.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,30,'192.168.35.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,22,'192.168.255.1.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,1,'198.55.63.193.1','255.255.255.252'),('2026-06-09 00:01:41.368',3,8,'205.207.224.142.1','255.255.255.248'),('2026-06-09 00:01:41.368',3,9,'66.179.9.158.1','255.255.255.240'),('2026-06-09 00:01:41.368',3,6,'192.168.25.254.1','255.255.255.0'),('2026-06-09 00:01:41.368',3,38,'192.168.45.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
time=2026-06-09T00:01:48.859Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:48.859Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=9d21099b8a18e85a0e91a72024fd3bba err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:48.859Z level=ERROR msg="http request" req=9d21099b8a18e85a0e91a72024fd3bba method=POST path=/api/probes/2/interface-addresses status=500 latency=5.773707ms
[GIN] 2026/06/09 - 00:01:48 | 500 |    5.847332ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
time=2026-06-09T00:01:48.897Z level=INFO msg="IRC: Connected to irc.technicallabs.org as Barnaby"
time=2026-06-09T00:01:48.900Z level=INFO msg="IRC: NickServ identification result: nick, type \x02/msg NickServ IDENTIFY \x1fpassword\x1f\x02.  Otherwise,"

2026/06/09 00:01:48 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1202.063ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:01:49 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[210.722ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

[GIN] 2026/06/09 - 00:01:49 | 200 |    8.042555ms |      172.20.0.1 | POST     "/api/probes/2/vpn-status"

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[1.240ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.346ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.350ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.322ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.323ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.338ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.255ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.203ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.233ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.199ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.216ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:49 firewall-mon/internal/database/devices.go:250 record not found
[0.198ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:01:49 main.go:1149: Overlay auto-detect: upserted 2 connection(s)

2026/06/09 00:01:49 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[2178.871ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 1 ORDER BY timestamp ASC, id ASC
[GIN] 2026/06/09 - 00:01:49 | 200 |   10.291933ms |      172.20.0.1 | POST     "/api/probes/2/hardware-sensors"

2026/06/09 00:01:50 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1188.157ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:01:50 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[213.543ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

2026/06/09 00:01:50 main.go:252: Connection cleanup: removed 1 stale auto-detected connection(s)

2026/06/09 00:01:50 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[1267.437ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 2 ORDER BY timestamp ASC, id ASC
2026/06/09 00:01:50 cleanup.go:402: vendor audit: vendor="fortigate" devices=3 normalizer=rich
2026/06/09 00:01:50 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
time=2026-06-09T00:01:51.041Z level=INFO msg="Received signal terminated, shutting down server..."
2026/06/09 00:01:51 main.go:1492: Shutting down poller...
2026/06/09 00:01:51 main.go:1495: Poller exited
time=2026-06-09T00:01:51.041Z level=INFO msg="Server exited"
2026/06/09 00:01:51 main.go:118: Poller stopped
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:01:52 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:01:52 main.go:1440: Starting SNMP Poller...
2026/06/09 00:01:52 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:01:52 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:01:52 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:01:52 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:01:52.759Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:01:52.760Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:01:52 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:52 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:52 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:52 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:52 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:52 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:52 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:01:52 main.go:1471: Database connected
2026/06/09 00:01:52 main.go:53: Starting SNMP poller with interval: 1m0s
2026/06/09 00:01:52 report.go:37: Report scheduler started
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for ping_results
time=2026-06-09T00:01:52.786Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:01:52.786Z level=INFO msg="Database initialized"
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for alerts
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:01:52 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:01:52 main.go:167: Polling 3 devices...

2026/06/09 00:01:53 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[215.769ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

time=2026-06-09T00:01:53.123Z level=INFO msg="Admin user already exists, skipping initialization"
time=2026-06-09T00:01:53.141Z level=INFO msg="Static assets: serving from embedded FS (disk dir not found)"
time=2026-06-09T00:01:53.145Z level=INFO msg="Server starting on 0.0.0.0:8080"
2026/06/09 00:01:53 Connected to irc.technicallabs.org:6697 (66.179.9.146:6697)
[GIN] 2026/06/09 - 00:01:53 | 200 |    6.403631ms |      172.20.0.1 | POST     "/api/probes/heartbeat"
time=2026-06-09T00:01:53.560Z level=INFO msg="Probe 2: saved 1/1 system status records (devices: map[1:true])"
[GIN] 2026/06/09 - 00:01:53 | 200 |   14.551188ms |      172.20.0.1 | POST     "/api/probes/2/system-status"
time=2026-06-09T00:01:53.572Z level=INFO msg="Probe 2: saved 1/1 system status records (devices: map[2:true])"
[GIN] 2026/06/09 - 00:01:53 | 200 |   27.350665ms |      172.20.0.1 | POST     "/api/probes/2/system-status"
time=2026-06-09T00:01:53.581Z level=INFO msg="Probe 2: saved 1/1 system status records (devices: map[3:true])"
[GIN] 2026/06/09 - 00:01:53 | 200 |     4.84758ms |      172.20.0.1 | POST     "/api/probes/2/system-status"
[GIN] 2026/06/09 - 00:01:53 | 200 |   12.792703ms |      172.20.0.1 | POST     "/api/probes/2/traps"
time=2026-06-09T00:01:53.624Z level=INFO msg="ReceivePingResults: probe 2 received 24 results"
time=2026-06-09T00:01:53.659Z level=INFO msg="ReceivePingResults: probe 2 saved 24 results"
[GIN] 2026/06/09 - 00:01:53 | 200 |   40.150902ms |      172.20.0.1 | POST     "/api/probes/2/pings"
[GIN] 2026/06/09 - 00:01:53 | 200 |  246.372824ms |      172.20.0.1 | POST     "/api/probes/2/syslog"
[GIN] 2026/06/09 - 00:01:54 | 200 |     12.4613ms |      172.20.0.1 | POST     "/api/probes/2/interface-stats"

2026/06/09 00:01:54 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[2.035ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:01:53.985',2,3,'10.10.10.1.1','255.255.255.0'),('2026-06-09 00:01:53.985',2,16,'10.255.1.1.1','255.255.255.0'),('2026-06-09 00:01:53.985',2,15,'192.168.5.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
[GIN] 2026/06/09 - 00:01:54 | 500 |    4.823622ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
time=2026-06-09T00:01:54.023Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:54.023Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=d2028f30bc27f87920f52e23641ea96c err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:54.023Z level=ERROR msg="http request" req=d2028f30bc27f87920f52e23641ea96c method=POST path=/api/probes/2/interface-addresses status=500 latency=4.754366ms
time=2026-06-09T00:01:54.200Z level=INFO msg="IRC: Connected to irc.technicallabs.org as Barnaby"
time=2026-06-09T00:01:54.205Z level=INFO msg="IRC: NickServ identification result: nick, type \x02/msg NickServ IDENTIFY \x1fpassword\x1f\x02.  Otherwise,"
[GIN] 2026/06/09 - 00:01:54 | 200 |   48.037898ms |      172.20.0.1 | POST     "/api/probes/2/syslog"

2026/06/09 00:01:54 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1193.747ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts

[GIN] 2026/06/09 - 00:01:54 | 200 |    9.068074ms |      172.20.0.1 | POST     "/api/probes/2/flows"
[GIN] 2026/06/09 - 00:01:54 | 200 |   18.500342ms |      172.20.0.1 | POST     "/api/probes/2/interface-stats"

2026/06/09 00:01:54 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[1.903ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:01:54.424',1,16,'169.254.13.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,17,'169.254.14.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,18,'169.254.15.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,39,'10.10.200.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,7,'169.254.1.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,42,'169.254.2.1.1','255.255.255.255'),('2026-06-09 00:01:54.424',1,6,'192.168.5.2.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,20,'192.168.255.2.1','255.255.255.255'),('2026-06-09 00:01:54.424',1,3,'10.10.10.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,12,'10.10.100.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,19,'76.66.145.98.1','255.255.255.255'),('2026-06-09 00:01:54.424',1,14,'169.254.11.1.1','255.255.255.0'),('2026-06-09 00:01:54.424',1,15,'169.254.12.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
time=2026-06-09T00:01:54.481Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
[GIN] 2026/06/09 - 00:01:54 | 500 |      4.9702ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
time=2026-06-09T00:01:54.481Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=25640c56d03e53fe6f059e30df1fd1fd err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:54.481Z level=ERROR msg="http request" req=25640c56d03e53fe6f059e30df1fd1fd method=POST path=/api/probes/2/interface-addresses status=500 latency=4.903003ms
[GIN] 2026/06/09 - 00:01:54 | 200 |    6.900666ms |      172.20.0.1 | POST     "/api/probes/2/processor-stats"

2026/06/09 00:01:54 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[209.237ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[1.299ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[0.365ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[0.353ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[0.412ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[0.360ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[0.348ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[0.212ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:01:54 firewall-mon/internal/database/devices.go:250 record not found
[0.210ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:01:54 main.go:1149: Overlay auto-detect: upserted 2 connection(s)

2026/06/09 00:01:54 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[2170.188ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 1 ORDER BY timestamp ASC, id ASC
[GIN] 2026/06/09 - 00:01:55 | 200 |    5.707511ms |      172.20.0.1 | POST     "/api/probes/2/security-stats"

2026/06/09 00:01:55 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1186.643ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:01:55 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[209.091ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

time=2026-06-09T00:01:56.037Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:56.037Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=b963911aad99254b1d190f74f376c746 err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:01:56.037Z level=ERROR msg="http request" req=b963911aad99254b1d190f74f376c746 method=POST path=/api/probes/2/interface-addresses status=500 latency=3.186174ms

2026/06/09 00:01:56 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[0.657ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:01:53.985',2,3,'10.10.10.1.1','255.255.255.0'),('2026-06-09 00:01:53.985',2,16,'10.255.1.1.1','255.255.255.0'),('2026-06-09 00:01:53.985',2,15,'192.168.5.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
[GIN] 2026/06/09 - 00:01:56 | 500 |     3.24237ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"

2026/06/09 00:01:56 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[1230.175ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 2 ORDER BY timestamp ASC, id ASC
2026/06/09 00:01:56 cleanup.go:402: vendor audit: vendor="fortigate" devices=3 normalizer=rich
2026/06/09 00:01:56 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
2026/06/09 00:01:56 main.go:1492: Shutting down poller...
2026/06/09 00:01:56 main.go:1495: Poller exited
time=2026-06-09T00:01:56.272Z level=INFO msg="Received signal terminated, shutting down server..."
2026/06/09 00:01:56 main.go:118: Poller stopped
time=2026-06-09T00:01:56.272Z level=INFO msg="Server exited"
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:01:58 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:01:58 main.go:1440: Starting SNMP Poller...
2026/06/09 00:01:58 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:01:58 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:01:58 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:01:58 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:01:58.832Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:01:58.832Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:01:58 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:58 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:58 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:58 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:58 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:01:58 main.go:1471: Database connected
2026/06/09 00:01:58 report.go:37: Report scheduler started
2026/06/09 00:01:58 main.go:53: Starting SNMP poller with interval: 1m0s
2026/06/09 00:01:58 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:58 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for flow_samples
time=2026-06-09T00:01:58.857Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:01:58.857Z level=INFO msg="Database initialized"
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for alerts
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:01:58 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:01:58 main.go:167: Polling 3 devices...

2026/06/09 00:01:59 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[218.809ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

time=2026-06-09T00:01:59.194Z level=INFO msg="Admin user already exists, skipping initialization"
time=2026-06-09T00:01:59.213Z level=INFO msg="Static assets: serving from embedded FS (disk dir not found)"
time=2026-06-09T00:01:59.218Z level=INFO msg="Server starting on 0.0.0.0:8080"
2026/06/09 00:01:59 Connected to irc.technicallabs.org:6697 (66.179.9.146:6697)
[GIN] 2026/06/09 - 00:02:00 | 200 |   16.845232ms |      172.20.0.1 | POST     "/api/probes/2/hardware-sensors"
[GIN] 2026/06/09 - 00:02:00 | 200 |    6.792873ms |      172.20.0.1 | POST     "/api/probes/2/processor-stats"
[GIN] 2026/06/09 - 00:02:00 | 200 |    8.369237ms |      172.20.0.1 | POST     "/api/probes/2/security-stats"
time=2026-06-09T00:02:00.269Z level=INFO msg="IRC: Connected to irc.technicallabs.org as Barnaby"
time=2026-06-09T00:02:00.272Z level=INFO msg="IRC: NickServ identification result: nick, type \x02/msg NickServ IDENTIFY \x1fpassword\x1f\x02.  Otherwise,"

2026/06/09 00:02:00 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1211.494ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:02:00 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[214.200ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

[GIN] 2026/06/09 - 00:02:00 | 200 |    11.76345ms |      172.20.0.1 | POST     "/api/probes/2/vpn-status"
[GIN] 2026/06/09 - 00:02:00 | 200 |    4.908882ms |      172.20.0.1 | POST     "/api/probes/2/hardware-sensors"

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[1.553ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.375ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.364ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.333ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.336ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.351ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.300ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.253ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.254ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.249ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.248ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.254ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.209ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.197ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.267ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:00 firewall-mon/internal/database/devices.go:250 record not found
[0.237ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:02:00 main.go:1149: Overlay auto-detect: upserted 2 connection(s)
[GIN] 2026/06/09 - 00:02:00 | 200 |    4.820562ms |      172.20.0.1 | POST     "/api/probes/2/processor-stats"
[GIN] 2026/06/09 - 00:02:00 | 200 |    4.318404ms |      172.20.0.1 | POST     "/api/probes/2/security-stats"

2026/06/09 00:02:01 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[2185.149ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 1 ORDER BY timestamp ASC, id ASC

2026/06/09 00:02:01 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1213.042ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:02:02 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[210.454ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:02:02 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[1230.686ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 2 ORDER BY timestamp ASC, id ASC
2026/06/09 00:02:02 cleanup.go:402: vendor audit: vendor="fortigate" devices=3 normalizer=rich
2026/06/09 00:02:02 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
2026/06/09 00:02:02 main.go:1492: Shutting down poller...
time=2026-06-09T00:02:02.362Z level=INFO msg="Received signal terminated, shutting down server..."
2026/06/09 00:02:02 main.go:1495: Poller exited
2026/06/09 00:02:02 main.go:118: Poller stopped
time=2026-06-09T00:02:02.362Z level=INFO msg="Server exited"
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:02:06 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:02:06 main.go:1440: Starting SNMP Poller...
2026/06/09 00:02:06 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:02:06 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:02:06 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:02:06 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:02:06.492Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:02:06.492Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:02:06 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:06 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:06 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:06 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:06 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:06 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:06 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:02:06 main.go:1471: Database connected
2026/06/09 00:02:06 report.go:37: Report scheduler started
2026/06/09 00:02:06 main.go:53: Starting SNMP poller with interval: 1m0s
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for alerts
time=2026-06-09T00:02:06.519Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:02:06.519Z level=INFO msg="Database initialized"
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:02:06 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:02:06 main.go:167: Polling 3 devices...

2026/06/09 00:02:06 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[218.452ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

2026/06/09 00:02:06 main.go:848: Device DC2-FW1: Phase2: local=192.168.5.0 - 192.168.5.255 remote=192.168.35.0 - 192.168.35.255 for connection DC2-FW1 ↔ NUDAY-FW

2026/06/09 00:02:06 firewall-mon/internal/database/devices.go:250 record not found
[1.608ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:02:06 main.go:857: VPN auto-detect: processed 1 connection(s) across 3 devices
time=2026-06-09T00:02:06.857Z level=INFO msg="Admin user already exists, skipping initialization"
time=2026-06-09T00:02:06.876Z level=INFO msg="Static assets: serving from embedded FS (disk dir not found)"
time=2026-06-09T00:02:06.880Z level=INFO msg="Server starting on 0.0.0.0:8080"
2026/06/09 00:02:06 Connected to irc.technicallabs.org:6697 (66.179.9.146:6697)
time=2026-06-09T00:02:07.941Z level=INFO msg="IRC: Connected to irc.technicallabs.org as Barnaby"
time=2026-06-09T00:02:07.948Z level=INFO msg="IRC: NickServ identification result: nick, type \x02/msg NickServ IDENTIFY \x1fpassword\x1f\x02.  Otherwise,"

2026/06/09 00:02:08 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1184.505ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:02:08 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[211.243ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.520ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.419ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.384ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.366ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.245ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.292ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.245ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.281ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:08 firewall-mon/internal/database/devices.go:250 record not found
[0.246ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 3) OR (source_device_id = 3 AND dest_device_id = 1)) AND connection_type = 'vxlan' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:02:08 main.go:1149: Overlay auto-detect: upserted 3 connection(s)

2026/06/09 00:02:08 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[2235.682ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 1 ORDER BY timestamp ASC, id ASC

2026/06/09 00:02:09 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1186.985ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:02:09 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[211.785ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:02:10 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[1241.439ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 2 ORDER BY timestamp ASC, id ASC
2026/06/09 00:02:10 cleanup.go:402: vendor audit: vendor="fortigate" devices=3 normalizer=rich
2026/06/09 00:02:10 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
2026/06/09 00:02:10 main.go:1492: Shutting down poller...
time=2026-06-09T00:02:10.083Z level=INFO msg="Received signal terminated, shutting down server..."
2026/06/09 00:02:10 main.go:1495: Poller exited
2026/06/09 00:02:10 main.go:118: Poller stopped
time=2026-06-09T00:02:10.083Z level=INFO msg="Server exited"
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:02:17 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:02:17 main.go:1440: Starting SNMP Poller...
2026/06/09 00:02:17 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:02:17 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:02:17 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:02:17 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:02:17.431Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:02:17.431Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:02:17 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:17 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:17 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:17 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:17 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:17 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:17 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:02:17 main.go:1471: Database connected
2026/06/09 00:02:17 report.go:37: Report scheduler started
2026/06/09 00:02:17 main.go:53: Starting SNMP poller with interval: 1m0s
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for alerts
time=2026-06-09T00:02:17.459Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:02:17.459Z level=INFO msg="Database initialized"
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:02:17 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:02:17 main.go:167: Polling 3 devices...

2026/06/09 00:02:17 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[217.213ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

2026/06/09 00:02:17 main.go:848: Device DC2-FW1: Phase2: local=192.168.5.0 - 192.168.5.255 remote=192.168.35.0 - 192.168.35.255 for connection DC2-FW1 ↔ NUDAY-FW
2026/06/09 00:02:17 main.go:857: VPN auto-detect: processed 1 connection(s) across 3 devices
time=2026-06-09T00:02:17.796Z level=INFO msg="Admin user already exists, skipping initialization"
time=2026-06-09T00:02:17.814Z level=INFO msg="Static assets: serving from embedded FS (disk dir not found)"
time=2026-06-09T00:02:17.817Z level=INFO msg="Server starting on 0.0.0.0:8080"
2026/06/09 00:02:17 Connected to irc.technicallabs.org:6697 (66.179.9.146:6697)
time=2026-06-09T00:02:18.875Z level=INFO msg="IRC: Connected to irc.technicallabs.org as Barnaby"
time=2026-06-09T00:02:18.880Z level=INFO msg="IRC: NickServ identification result: nick, type \x02/msg NickServ IDENTIFY \x1fpassword\x1f\x02.  Otherwise,"

2026/06/09 00:02:18 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1186.728ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:02:19 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[209.345ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.497ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.364ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.424ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.434ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.346ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.224ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.199ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.194ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.200ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.192ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.204ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:02:19 firewall-mon/internal/database/devices.go:250 record not found
[0.252ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:02:19 main.go:1149: Overlay auto-detect: upserted 3 connection(s)

2026/06/09 00:02:19 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[2216.437ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 1 ORDER BY timestamp ASC, id ASC

2026/06/09 00:02:20 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1177.746ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:02:20 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[210.920ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:02:21 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[1413.038ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 2 ORDER BY timestamp ASC, id ASC
2026/06/09 00:02:21 cleanup.go:402: vendor audit: vendor="fortigate" devices=3 normalizer=rich
2026/06/09 00:02:21 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
2026/06/09 00:02:21 main.go:1492: Shutting down poller...
2026/06/09 00:02:21 main.go:1495: Poller exited
time=2026-06-09T00:02:21.219Z level=INFO msg="Received signal terminated, shutting down server..."
2026/06/09 00:02:21 main.go:118: Poller stopped
time=2026-06-09T00:02:21.219Z level=INFO msg="Server exited"
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:02:34 main.go:1440: Starting SNMP Poller...
2026/06/09 00:02:34 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:02:34 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:02:34 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:02:34 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:02:34 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:02:34.981Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:02:34.981Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:02:34 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:34 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:34 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:34 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:34 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:34 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:02:34 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for alerts
time=2026-06-09T00:02:35.009Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:02:35.009Z level=INFO msg="Database initialized"
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:02:35 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:02:35 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
Stopping PostgreSQL...
=== Firewall Monitor Starting ===
Initializing PostgreSQL...
Existing PostgreSQL data found.
Starting PostgreSQL...
PostgreSQL ready.
Starting Firewall Monitor services...
Starting API server...
Starting SNMP poller...
Starting trap receiver...
All services started!
  API:      29
  Poller:   30
  Trap:     31
2026/06/09 00:03:01 main.go:22: Starting SNMP Trap Receiver...
2026/06/09 00:03:01 main.go:1440: Starting SNMP Poller...
2026/06/09 00:03:01 database.go:150: Database: pool max_open=5 max_idle=5
2026/06/09 00:03:01 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
time=2026-06-09T00:03:01.545Z level=INFO msg="Database: pool max_open=15 max_idle=10"
time=2026-06-09T00:03:01.545Z level=INFO msg="Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon"
2026/06/09 00:03:01 database.go:150: Database: pool max_open=10 max_idle=10
2026/06/09 00:03:01 database.go:152: Database: connected to PostgreSQL at /run/postgresql:5432/firewall_mon
2026/06/09 00:03:01 migrate.go:241: WARNING: AUDIT-146 partition setup: "interface_stats" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:03:01 migrate.go:241: WARNING: AUDIT-146 partition setup: "system_status" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:03:01 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_messages" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:03:01 migrate.go:241: WARNING: AUDIT-146 partition setup: "syslog_summaries" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:03:01 migrate.go:241: WARNING: AUDIT-146 partition setup: "trap_events" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
2026/06/09 00:03:01 migrate.go:241: WARNING: AUDIT-146 partition setup: "flow_samples" is a plain table on this deployment; skipping monthly partition creation. To convert in place, run the migration in docs/partition-migration.md (planned for a future release). Without monthly partitions, the table will grow unbounded and the cleanup cron (AUDIT-029) will eventually run full-table DELETE statements that take minutes to complete.
time=2026-06-09T00:03:01.567Z level=INFO msg="Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process)."
time=2026-06-09T00:03:01.567Z level=INFO msg="Database initialized"
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for syslog_messages
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for syslog_summaries
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for trap_events
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for flow_samples
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for ping_results
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for alerts
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for interface_stats
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for system_status
2026/06/09 00:03:01 database.go:228: Startup setup: another process holds the migration lock; skipping partition/autovacuum/vendor-audit (work is idempotent and being done by a sibling process).
2026/06/09 00:03:01 main.go:1471: Database connected
2026/06/09 00:03:01 main.go:53: Starting SNMP poller with interval: 1m0s
2026/06/09 00:03:01 report.go:37: Report scheduler started
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for processor_stats
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for process_stats
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for vpn_status
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for ha_status
2026/06/09 00:03:01 migrate.go:524: Configured autovacuum for interface_addresses
2026/06/09 00:03:01 main.go:167: Polling 3 devices...

2026/06/09 00:03:01 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[222.992ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts

time=2026-06-09T00:03:01.904Z level=INFO msg="Admin user already exists, skipping initialization"
2026/06/09 00:03:01 main.go:848: Device DC2-FW1: Phase2: local=192.168.5.0 - 192.168.5.255 remote=192.168.35.0 - 192.168.35.255 for connection DC2-FW1 ↔ NUDAY-FW
2026/06/09 00:03:01 main.go:857: VPN auto-detect: processed 1 connection(s) across 3 devices
time=2026-06-09T00:03:01.923Z level=INFO msg="Static assets: serving from embedded FS (disk dir not found)"
time=2026-06-09T00:03:01.925Z level=INFO msg="Server starting on 0.0.0.0:8080"
2026/06/09 00:03:01 Connected to irc.technicallabs.org:6697 (66.179.9.146:6697)
[GIN] 2026/06/09 - 00:03:02 | 200 |   22.601686ms |      172.20.0.1 | POST     "/api/probes/2/interface-stats"
time=2026-06-09T00:03:02.038Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:02.038Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=83d1300a1da216b69878c8e819086f54 err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:02.038Z level=ERROR msg="http request" req=83d1300a1da216b69878c8e819086f54 method=POST path=/api/probes/2/interface-addresses status=500 latency=5.225854ms

2026/06/09 00:03:02 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[2.040ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:02:57.971',2,3,'10.10.10.1.1','255.255.255.0'),('2026-06-09 00:02:57.971',2,16,'10.255.1.1.1','255.255.255.0'),('2026-06-09 00:02:57.971',2,15,'192.168.5.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
[GIN] 2026/06/09 - 00:03:02 | 500 |     5.30104ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
[GIN] 2026/06/09 - 00:03:02 | 200 |    8.855665ms |      172.20.0.1 | POST     "/api/probes/2/processor-stats"
[GIN] 2026/06/09 - 00:03:02 | 200 |   16.345201ms |      172.20.0.1 | POST     "/api/probes/2/interface-stats"

2026/06/09 00:03:02 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[0.883ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:02:58.412',1,39,'10.10.200.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,7,'169.254.1.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,16,'169.254.13.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,17,'169.254.14.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,18,'169.254.15.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,6,'192.168.5.2.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,20,'192.168.255.2.1','255.255.255.255'),('2026-06-09 00:02:58.412',1,3,'10.10.10.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,12,'10.10.100.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,19,'76.66.145.98.1','255.255.255.255'),('2026-06-09 00:02:58.412',1,42,'169.254.2.1.1','255.255.255.255'),('2026-06-09 00:02:58.412',1,14,'169.254.11.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,15,'169.254.12.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
time=2026-06-09T00:03:02.492Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:02.492Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=1fcccb28e7175475de1681bb0bd3aa5c err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:02.492Z level=ERROR msg="http request" req=1fcccb28e7175475de1681bb0bd3aa5c method=POST path=/api/probes/2/interface-addresses status=500 latency=4.482029ms
[GIN] 2026/06/09 - 00:03:02 | 500 |    4.551175ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
time=2026-06-09T00:03:02.715Z level=INFO msg="IRC: Connected to irc.technicallabs.org as Barnaby"
time=2026-06-09T00:03:02.719Z level=INFO msg="IRC: NickServ identification result: nick, type \x02/msg NickServ IDENTIFY \x1fpassword\x1f\x02.  Otherwise,"
[GIN] 2026/06/09 - 00:03:02 | 200 |    7.037522ms |      172.20.0.1 | POST     "/api/probes/2/security-stats"

2026/06/09 00:03:03 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1221.730ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:03:03 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[215.531ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.501ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.383ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.352ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.349ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.214ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.211ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.217ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.205ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.210ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ipsec' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.221ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'gre' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.196ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'tunnel' ORDER BY "device_connections"."id" LIMIT 1

2026/06/09 00:03:03 firewall-mon/internal/database/devices.go:250 record not found
[0.188ms] [rows:0] SELECT * FROM "device_connections" WHERE ((source_device_id = 1 AND dest_device_id = 2) OR (source_device_id = 2 AND dest_device_id = 1)) AND connection_type = 'ssl' ORDER BY "device_connections"."id" LIMIT 1
2026/06/09 00:03:03 main.go:1149: Overlay auto-detect: upserted 3 connection(s)

2026/06/09 00:03:03 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[2254.472ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 1 ORDER BY timestamp ASC, id ASC
[GIN] 2026/06/09 - 00:03:04 | 200 |   143.77689ms |      172.20.0.1 | POST     "/api/probes/2/syslog"

2026/06/09 00:03:04 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[2.007ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:02:57.971',2,3,'10.10.10.1.1','255.255.255.0'),('2026-06-09 00:02:57.971',2,16,'10.255.1.1.1','255.255.255.0'),('2026-06-09 00:02:57.971',2,15,'192.168.5.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
time=2026-06-09T00:03:04.074Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:04.074Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=0034793f40f87eb8883f139abc514072 err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:04.074Z level=ERROR msg="http request" req=0034793f40f87eb8883f139abc514072 method=POST path=/api/probes/2/interface-addresses status=500 latency=25.318048ms
[GIN] 2026/06/09 - 00:03:04 | 500 |   25.385459ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
[GIN] 2026/06/09 - 00:03:04 | 200 |   16.147632ms |      172.20.0.1 | POST     "/api/probes/2/flows"

2026/06/09 00:03:04 firewall-mon/internal/database/telemetry.go:70 ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)
[0.656ms] [rows:0] INSERT INTO "interface_addresses" ("timestamp","device_id","if_index","ip_address","net_mask") VALUES ('2026-06-09 00:02:58.412',1,39,'10.10.200.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,7,'169.254.1.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,16,'169.254.13.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,17,'169.254.14.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,18,'169.254.15.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,6,'192.168.5.2.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,20,'192.168.255.2.1','255.255.255.255'),('2026-06-09 00:02:58.412',1,3,'10.10.10.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,12,'10.10.100.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,19,'76.66.145.98.1','255.255.255.255'),('2026-06-09 00:02:58.412',1,42,'169.254.2.1.1','255.255.255.255'),('2026-06-09 00:02:58.412',1,14,'169.254.11.1.1','255.255.255.0'),('2026-06-09 00:02:58.412',1,15,'169.254.12.1.1','255.255.255.0') ON CONFLICT ("device_id","ip_address") DO UPDATE SET "timestamp"="excluded"."timestamp","if_index"="excluded"."if_index","net_mask"="excluded"."net_mask" RETURNING "id"
[GIN] 2026/06/09 - 00:03:04 | 500 |    4.051484ms |      172.20.0.1 | POST     "/api/probes/2/interface-addresses"
time=2026-06-09T00:03:04.506Z level=INFO msg="ReceiveInterfaceAddresses: DB save error: ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:04.506Z level=ERROR msg="Failed to save interface addresses" status=500 method=POST route=/api/probes/:id/interface-addresses req=f5c74116f299b8cde792f4b45c955ddd err="ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification (SQLSTATE 42P10)"
time=2026-06-09T00:03:04.506Z level=ERROR msg="http request" req=f5c74116f299b8cde792f4b45c955ddd method=POST path=/api/probes/2/interface-addresses status=500 latency=3.995833ms

2026/06/09 00:03:04 firewall-mon/internal/database/telemetry.go:91 SLOW SQL >= 200ms
[1177.508ms] [rows:106]
                SELECT i.* FROM interface_stats i
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_stats GROUP BY device_id) latest
                ON i.device_id = latest.device_id AND i.timestamp = latest.max_ts


2026/06/09 00:03:04 firewall-mon/internal/database/telemetry.go:80 SLOW SQL >= 200ms
[212.319ms] [rows:25]
                SELECT a.* FROM interface_addresses a
                INNER JOIN (SELECT device_id, MAX(timestamp) as max_ts FROM interface_addresses GROUP BY device_id) latest
                ON a.device_id = latest.device_id AND a.timestamp = latest.max_ts


2026/06/09 00:03:05 firewall-mon/internal/database/config_revisions.go:129 SLOW SQL >= 200ms
[1363.098ms] [rows:502] SELECT * FROM "device_config_revisions" WHERE device_id = 2 ORDER BY timestamp ASC, id ASC
2026/06/09 00:03:05 cleanup.go:402: vendor audit: vendor="fortigate" devices=3 normalizer=rich
2026/06/09 00:03:05 main.go:78: Failed to start trap receiver: SNMP_TRAP_COMMUNITY must be set to a non-empty value; refusing to start the trap listener with an open community string (AUDIT-012)
!!! Trap (pid 31) exited (status 1) — tearing down the stack for a clean restart
Stopping fwmon services...
time=2026-06-09T00:03:05.317Z level=INFO msg="Received signal terminated, shutting down server..."
time=2026-06-09T00:03:05.317Z level=INFO msg="Server exited"
2026/06/09 00:03:05 main.go:1492: Shutting down poller...
2026/06/09 00:03:05 main.go:1495: Poller exited
2026/06/09 00:03:05 main.go:118: Poller stopped
Stopping PostgreSQL...
