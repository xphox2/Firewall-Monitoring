# Stage 1: Build the Go binaries
FROM golang:1.21-alpine AS builder

WORKDIR /build

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fortigate-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fortigate-poller ./cmd/poller
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fortigate-trap ./cmd/trap-receiver

# Stage 2: Final Alpine image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates bash wget

RUN mkdir -p /app /data /config

WORKDIR /app

COPY --from=builder /build/fortigate-api .
COPY --from=builder /build/fortigate-poller .
COPY --from=builder /build/fortigate-trap .
COPY web ./web
COPY config.env.example ./config.env

RUN chmod +x fortigate-*

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8080 162/udp

ENTRYPOINT ["./entrypoint.sh"]
