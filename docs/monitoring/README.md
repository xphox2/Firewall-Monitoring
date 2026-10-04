# Monitoring Firewall-Mon with Prometheus

Firewall-Mon exposes Prometheus metrics on all three daemons. This directory has
a ready-to-adapt [`prometheus.yml`](prometheus.yml) scrape config.

> The metrics carry only aggregate timings/counters and route *templates*, never
> secrets. The poller and trap-receiver listeners are unauthenticated
> (Prometheus convention) and default to loopback — bind them to an internal
> interface or firewall the scrape ports. The **API** endpoint shares port 8080
> with the collectors, which is usually internet-facing, so it is gated (v0.11.288):
>
> - `METRICS_TOKEN` **unset** (default): served only to a loopback peer
>   (`127.0.0.1` / `::1`); every other client gets a 404. A Prometheus in the
>   same container (or a host-networked one) can scrape it; a Prometheus on
>   the Docker host reaches a bridge-networked container from the bridge
>   gateway, not loopback, so it needs `METRICS_TOKEN`.
> - `METRICS_TOKEN` **set** (`openssl rand -hex 32`): every request — loopback
>   included — must send `Authorization: Bearer <token>`; anything else is 401.
>   In `prometheus.yml`: `authorization: { credentials: "<token>" }` (or
>   `credentials_file`). The peer is the socket address, never
>   `X-Forwarded-For`, so a scrape through the reverse proxy needs the token too.

## Endpoints

| Daemon | Address | Notes |
|---|---|---|
| API | `:8080/metrics` | HTTP latency histogram + Go runtime + process + DB pool. Loopback only, or `Authorization: Bearer $METRICS_TOKEN` |
| Poller | `POLLER_METRICS_ADDR` (default `127.0.0.1:9101`) | set to a reachable interface, or `"off"` to disable |
| Trap receiver | `TRAP_METRICS_ADDR` (default `127.0.0.1:9102`) | as above |

## Metrics exposed

- **`fwmon_http_request_duration_seconds`** — histogram of API request latency,
  labelled `method`, `route` (matched template, so cardinality is bounded), and
  `status`. Its `_count` child doubles as the request counter.
- **Go runtime / process** (from the client_golang default collectors):
  `go_goroutines`, `go_memstats_*`, `process_resident_memory_bytes`,
  `process_cpu_seconds_total`, `process_open_fds`, …
- **DB connection pool** (label `db_name="fwmon"`): `go_sql_open_connections`,
  `go_sql_in_use_connections`, `go_sql_idle_connections`,
  `go_sql_max_open_connections`, `go_sql_wait_count_total`,
  `go_sql_wait_duration_seconds_total`, and the `*_closed_total` counters.

## Useful PromQL

```promql
# Request rate by route
sum by (route) (rate(fwmon_http_request_duration_seconds_count[5m]))

# p95 API latency
histogram_quantile(0.95, sum by (le) (rate(fwmon_http_request_duration_seconds_bucket[5m])))

# Error rate (5xx) as a fraction of all requests
sum(rate(fwmon_http_request_duration_seconds_count{status=~"5.."}[5m]))
  / sum(rate(fwmon_http_request_duration_seconds_count[5m]))

# API resident memory
process_resident_memory_bytes{component="api"}

# Goroutine count (leak watch)
go_goroutines{component="api"}

# DB pool saturation (in-use vs pool ceiling)
go_sql_in_use_connections{db_name="fwmon"} / go_sql_max_open_connections{db_name="fwmon"}
```

## Alerting starters

```yaml
groups:
  - name: fwmon
    rules:
      - alert: FwmonApiDown
        expr: up{job="fwmon-api"} == 0
        for: 2m
        labels: { severity: critical }
        annotations: { summary: "Firewall-Mon API is not being scraped" }

      - alert: FwmonHighErrorRate
        expr: |
          sum(rate(fwmon_http_request_duration_seconds_count{status=~"5.."}[5m]))
            / sum(rate(fwmon_http_request_duration_seconds_count[5m])) > 0.05
        for: 10m
        labels: { severity: warning }
        annotations: { summary: "API 5xx rate above 5%" }

      - alert: FwmonGoroutineLeak
        expr: go_goroutines{job="fwmon-api"} > 5000
        for: 30m
        labels: { severity: warning }
        annotations: { summary: "API goroutine count unusually high" }
```

## Grafana dashboard

A prebuilt dashboard ships as [`grafana-dashboard.json`](grafana-dashboard.json):
API health (up, request rate by route, latency quantiles, error rates, slowest
routes), Go runtime for all three daemons (goroutines, memory, CPU, FDs), and
DB pool health (connections, saturation, connection wait).

To import: Grafana → **Dashboards → New → Import** → upload
`grafana-dashboard.json` → pick your Prometheus datasource when prompted. The
job/component labels match the scrape config in [`prometheus.yml`](prometheus.yml)
(`fwmon-api` / `fwmon-poller` / `fwmon-trap`); if you renamed the jobs, adjust
the panel queries accordingly. Poller/trap panels stay empty until their
`*_METRICS_ADDR` endpoints are reachable by Prometheus.
