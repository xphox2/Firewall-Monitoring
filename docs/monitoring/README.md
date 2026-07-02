# Monitoring Firewall-Mon with Prometheus

Firewall-Mon exposes Prometheus metrics on all three daemons. This directory has
a ready-to-adapt [`prometheus.yml`](prometheus.yml) scrape config.

> `/metrics` is **unauthenticated by design** (Prometheus convention). Bind it to
> an internal interface or firewall the scrape ports — it carries only aggregate
> timings/counters and route *templates*, never secrets.

## Endpoints

| Daemon | Address | Notes |
|---|---|---|
| API | `:8080/metrics` | HTTP latency histogram + Go runtime + process + DB pool |
| Poller | `POLLER_METRICS_ADDR` (default `127.0.0.1:9101`) | set to a reachable interface, or `"off"` to disable |
| Trap receiver | `TRAP_METRICS_ADDR` (default `127.0.0.1:9102`) | as above |

## Metrics exposed

- **`fwmon_http_request_duration_seconds`** — histogram of API request latency,
  labelled `method`, `route` (matched template, so cardinality is bounded), and
  `status`. Its `_count` child doubles as the request counter.
- **Go runtime / process** (from the client_golang default collectors):
  `go_goroutines`, `go_memstats_*`, `process_resident_memory_bytes`,
  `process_cpu_seconds_total`, `process_open_fds`, …
- **DB connection pool** (`go_sql_stats_*`): open / in-use / idle connections,
  wait count, wait duration.

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

# DB pool saturation (in-use vs open)
go_sql_stats_connections_in_use / go_sql_stats_connections_open
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

A prebuilt Grafana dashboard JSON is not shipped yet — build panels from the
PromQL above, or import any generic Go-process dashboard and add the
`fwmon_http_request_duration_seconds` panels.
