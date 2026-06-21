package shell

import (
	"os"
	"strings"
	"testing"
)

// TestOpenTelemetryTracingWired_AUDIT150 pins the OpenTelemetry tracing
// integration: the tracing package exists with the default-off gate, the api
// server installs the gin span middleware, the probe relay wraps its HTTP
// transport for client spans + propagation, and the slog logger stamps
// trace/span IDs. Guards against any of these seams being torn out.
func TestOpenTelemetryTracingWired_AUDIT150(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}

	// Core package: default-off gate + OTLP exporter + global provider/propagator.
	core := read("../tracing/tracing.go")
	for _, kw := range []string{"OTEL_TRACES_ENABLED", "otlptracehttp", "SetTracerProvider", "SetTextMapPropagator"} {
		if !strings.Contains(core, kw) {
			t.Errorf("tracing.go missing %q (AUDIT-150).", kw)
		}
	}

	// Hand-rolled gin middleware + transport wrapper (no contrib gin upgrade).
	httpFile := read("../tracing/http.go")
	for _, kw := range []string{"func GinMiddleware(", "func WrapTransport(", "Extract", "Inject", "SpanKindServer", "SpanKindClient"} {
		if !strings.Contains(httpFile, kw) {
			t.Errorf("tracing/http.go missing %q (AUDIT-150).", kw)
		}
	}

	// api server installs the middleware before RequestLogger (so logs get trace_id).
	apiMain := read("../../cmd/api/main.go")
	if !strings.Contains(apiMain, "tracing.Init(") || !strings.Contains(apiMain, "tracing.GinMiddleware(") {
		t.Error("cmd/api/main.go must call tracing.Init and install tracing.GinMiddleware (AUDIT-150).")
	}

	// (The bundled probe's relay client that wrapped its transport for the
	// cross-process probe→api span was removed with cmd/probe; the production
	// probe is the Firewall-Collector repo, which carries its own tracing seam.)

	// slog handler stamps trace/span IDs from the span context.
	logg := read("../logging/logging.go")
	for _, kw := range []string{"traceHandler", "trace_id", "span_id", "SpanContextFromContext"} {
		if !strings.Contains(logg, kw) {
			t.Errorf("logging.go missing %q (AUDIT-150 log↔trace correlation).", kw)
		}
	}
}
