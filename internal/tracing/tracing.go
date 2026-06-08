// Package tracing wires OpenTelemetry distributed tracing into the fwmon
// services (AUDIT-150).
//
// Before this, the cross-process probe→api call was invisible end-to-end: a
// relay retry showed up as three unrelated `log.Printf` lines with no shared
// correlation ID, and there was no way to see where request latency went across
// the SNMP poll → batch → HTTP → DB chain. This package adopts
// `go.opentelemetry.io/otel`, exports spans over OTLP/HTTP to any collector
// (Tempo/Jaeger/Honeycomb/…), and propagates W3C trace context across the
// probe→api boundary so the whole call is one connected trace.
//
// **It is OFF by default.** Nothing initializes, no exporter goroutine runs, and
// the gin middleware / http transport wrappers are no-ops unless tracing is
// explicitly enabled, so a default deployment sees zero behaviour change and
// zero overhead. Enable with:
//
//	OTEL_TRACES_ENABLED=true
//	OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318   (OTLP/HTTP; standard otel env var)
//	OTEL_EXPORTER_OTLP_HEADERS=...                            (optional, e.g. auth)
//
// Init reads the standard `OTEL_EXPORTER_OTLP_*` environment variables via the
// otlptracehttp exporter, so all collector/endpoint/TLS/header config uses the
// documented OpenTelemetry conventions rather than bespoke fwmon settings.
package tracing

import (
	"context"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Enabled reports whether tracing is switched on (OTEL_TRACES_ENABLED truthy).
// All instrumentation is gated on this so the disabled path adds no spans and no
// overhead.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// noopShutdown is returned when tracing is disabled so callers can always
// `defer shutdown(ctx)` unconditionally.
func noopShutdown(context.Context) error { return nil }

// Init installs the global tracer provider and W3C propagator when tracing is
// enabled, and returns a shutdown func that flushes buffered spans. When
// disabled it leaves the global no-op provider in place and returns a no-op
// shutdown (and a nil error), so callers need no special-casing:
//
//	shutdown, err := tracing.Init(ctx, "fwmon-api", version)
//	if err != nil { log.Printf("tracing: %v", err) }
//	defer shutdown(context.Background())
func Init(ctx context.Context, serviceName, version string) (func(context.Context) error, error) {
	if !Enabled() {
		return noopShutdown, nil
	}

	// otlptracehttp.New consumes the standard OTEL_EXPORTER_OTLP_* env vars
	// (endpoint, headers, TLS, compression). No bespoke config surface.
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return noopShutdown, err
	}

	res := resource.NewSchemaless(
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	// W3C TraceContext + Baggage so the probe→api hop (and any fronting proxy)
	// share one trace via the `traceparent` header.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}
