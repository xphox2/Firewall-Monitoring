# Stage 1: Build the Go binaries
FROM golang:1.21-alpine AS builder

WORKDIR /build

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-poller ./cmd/poller
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-trap ./cmd/trap-receiver
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fwmon-probe ./cmd/probe

# Stage 2: Final Alpine image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates bash wget

RUN mkdir -p /app /data /config

WORKDIR /app

COPY --from=builder /build/fwmon-api .
COPY --from=builder /build/fwmon-poller .
COPY --from=builder /build/fwmon-trap .
COPY --from=builder /build/fwmon-probe .
COPY web ./web
COPY config.env.example ./config.env

RUN chmod +x fwmon-*

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8080 162/udp 514/udp 6343/udp 8089

ENTRYPOINT ["./entrypoint.sh"]
