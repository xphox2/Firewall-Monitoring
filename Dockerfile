# Stage 1: Build the Go binaries
FROM golang:1.25-alpine AS builder

WORKDIR /build

# AUDIT-103: the builder installs no C toolchain. Every binary is compiled
# with CGO_ENABLED=0 (see the go build lines below), so a C compiler was
# never invoked — installing one only bloated the build stage and slowed
# image builds. Pure-Go builds need nothing beyond the golang base image.

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY web ./web

# AUDIT-102: reproducible builds. `-trimpath` strips the local /build and
# module-cache paths from the binary (otherwise the same source on two
# machines yields different bytes), and `-buildvcs=false` keeps VCS stamping
# out of the binary so a dirty/clean working tree or a different commit
# context doesn't change the output. Together they make the four binaries
# byte-identical across build hosts given the same source + toolchain.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o fwmon-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o fwmon-poller ./cmd/poller
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o fwmon-trap ./cmd/trap-receiver

# Stage 2: Final Alpine image with embedded PostgreSQL
# alpine 3.21 — 3.19 reached end-of-life ~Nov 2025 (2026-06-23 audit, M13).
# Verified against the alpine 3.21 package index that every package below still
# resolves: postgresql16 / postgresql16-contrib are 16.14-r0 in 3.21 main, so
# PostgreSQL stays at MAJOR 16 — existing PGDATA directories remain compatible
# and no pg_upgrade is required on deploy. su-exec (0.2-r3) is also in 3.21 main.
FROM alpine:3.21

RUN apk add --no-cache ca-certificates bash wget su-exec postgresql16 postgresql16-contrib

RUN addgroup -S fwmon && adduser -S fwmon -G fwmon

RUN mkdir -p /app /data /data/pgdata /config && chown -R fwmon:fwmon /data /config

WORKDIR /app

COPY --from=builder /build/fwmon-api .
COPY --from=builder /build/fwmon-poller .
COPY --from=builder /build/fwmon-trap .
COPY web ./web
COPY config.env.example ./config.env.example

RUN chmod +x fwmon-*

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

RUN chown -R fwmon:fwmon /app

# Web UI/API + probe relay ingest (8080) and the SNMP trap receiver (162/udp).
# The server runs no raw syslog/sFlow/ICMP listener — those live on the edge
# collector, which relays already-parsed telemetry over 8080.
EXPOSE 8080 162/udp

# AUDIT-091: HEALTHCHECK drives Docker's `container is ready` vs
# `container is alive` distinction. The 3-process entrypoint (api,
# poller, trap-receiver) plus embedded Postgres means "the process is
# running" is not the same as "the service is ready to serve requests"
# — a Postgres that's still recovering from a crash, for example,
# would have a healthy-looking container that returns 500 on the first
# API call. The endpoint we hit (/api/health) is now meaningful as of
# the same commit (see CHANGELOG v0.10.264): it pings the DB with a
# 1-second timeout and returns 503 if anything is wrong, so the wget
# exit code propagates correctly.
#
# --interval=30s: how often to check. 30s is a reasonable default —
#   fast enough that an unhealthy container is detected within a
#   minute, slow enough that the DB isn't hammered with SELECT 1.
# --timeout=3s: 1s DB deadline + 2s for HTTP / TCP overhead. If this
#   fires, the API itself is wedged (Postgres ping would have
#   returned in 1s).
# --start-period=20s: the entrypoint starts Postgres, the schema
#   migrates, the API binary boots. 20s is a safe lower bound for
#   embedded-Postgres cold start on the smallest supported instance
#   type.
# --retries=3: three consecutive failures = unhealthy. With the 30s
#   interval, that's a 60-90 second unhealthy-to-restart window,
#   which matches the systemd RestartSec on the native path.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD wget -qO- http://localhost:8080/api/health || exit 1

# AUDIT-101: OCI image labels were hardcoded (the version was caught
# stale at v0.10.237 and v0.10.239 in past releases). The fix is to
# declare the version (and other labels) as ARG values that the
# build can override, with sensible defaults so a `docker build .`
# without --build-arg still produces a working image labeled "dev".
#
# The CI workflow (Makefile / .github/workflows/release.yml — AUDIT-004
# deferred halves) passes --build-arg VERSION=<tag> so the published
# image carries the right metadata. .source / .revision / .created
# follow the OCI image-spec annotations spec:
#   https://github.com/opencontainers/image-spec/blob/main/annotations.md
#
# .licenses pins the SPDX expression for the project (MIT per
# LICENSE), and .vendor is the org name. The title and description
# stay hardcoded — they're not versioned, so making them ARGs would
# be ceremony with no benefit.
#
# Build-arg order matters: ARG before the first FROM is in a global
# scope; the same ARG re-declared in the second stage is what makes
# it available to LABEL. ARG defaults are what `docker build .` gets
# when no --build-arg is passed.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED="1970-01-01T00:00:00Z"

LABEL org.opencontainers.image.title="Firewall Mon" \
      org.opencontainers.image.description="Self-hosted firewall monitoring with SNMP, sFlow, syslog, and IRC alerting" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/xphox2/Firewall-Monitoring" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Firewall-Mon Contributors" \
      org.opencontainers.image.url="https://github.com/xphox2/Firewall-Monitoring" \
      maintainer="Firewall-Mon Contributors"

ENTRYPOINT ["./entrypoint.sh"]
