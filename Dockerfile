# Stage 1: Build the Go binaries
FROM golang:1.23-alpine AS builder

WORKDIR /build

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY web ./web

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-poller ./cmd/poller
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-trap ./cmd/trap-receiver
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-probe ./cmd/probe

# Stage 2: Final Alpine image with embedded PostgreSQL
FROM alpine:3.19

RUN apk add --no-cache ca-certificates bash wget su-exec postgresql16 postgresql16-contrib

RUN addgroup -S fwmon && adduser -S fwmon -G fwmon

RUN mkdir -p /app /data /data/pgdata /config && chown -R fwmon:fwmon /data /config

WORKDIR /app

COPY --from=builder /build/fwmon-api .
COPY --from=builder /build/fwmon-poller .
COPY --from=builder /build/fwmon-trap .
COPY --from=builder /build/fwmon-probe .
COPY web ./web
COPY config.env.example ./config.env.example

RUN chmod +x fwmon-*

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

RUN chown -R fwmon:fwmon /app

EXPOSE 8080 162/udp 514/udp 6343/udp 8089

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

LABEL org.opencontainers.image.title="Firewall Mon" \
      org.opencontainers.image.version="0.10.264"

ENTRYPOINT ["./entrypoint.sh"]
