package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func init() { gin.SetMode(gin.TestMode) }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEnabled(t *testing.T) {
	cases := map[string]bool{"true": true, "1": true, "YES": true, "on": true, "false": false, "": false, "nope": false}
	for v, want := range cases {
		t.Setenv("OTEL_TRACES_ENABLED", v)
		if got := Enabled(); got != want {
			t.Errorf("Enabled() with OTEL_TRACES_ENABLED=%q = %v, want %v", v, got, want)
		}
	}
}

func TestInit_Disabled_ReturnsNoopShutdown(t *testing.T) {
	t.Setenv("OTEL_TRACES_ENABLED", "false")
	shutdown, err := Init(context.Background(), "svc", "v1")
	if err != nil {
		t.Fatalf("Init disabled: unexpected err %v", err)
	}
	if shutdown == nil {
		t.Fatal("Init must return a non-nil shutdown even when disabled")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown returned %v, want nil", err)
	}
}

func TestGinMiddleware_Disabled_IsPassthrough(t *testing.T) {
	t.Setenv("OTEL_TRACES_ENABLED", "false")
	r := gin.New()
	r.Use(GinMiddleware("svc"))
	called := false
	r.GET("/x", func(c *gin.Context) {
		called = true
		// No tracing → no valid span on the context.
		if trace.SpanContextFromContext(c.Request.Context()).IsValid() {
			t.Error("disabled middleware should not put a valid span on the context")
		}
		c.Status(http.StatusOK)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if !called {
		t.Fatal("handler was not reached through the disabled middleware")
	}
}

func TestWrapTransport_Disabled_ReturnsBaseUnchanged(t *testing.T) {
	t.Setenv("OTEL_TRACES_ENABLED", "false")
	base := &http.Transport{}
	if got := WrapTransport(base); got != base {
		t.Error("disabled WrapTransport must return the base transport unchanged")
	}
}

// setupRecorder installs an in-memory, synchronous span recorder as the global
// provider (with a W3C propagator) and enables tracing, restoring globals after.
func setupRecorder(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	t.Setenv("OTEL_TRACES_ENABLED", "true")
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
		_ = tp.Shutdown(context.Background())
	})
	return exp
}

// TestCrossProcessPropagation is the headline AUDIT-150 proof: a client request
// through WrapTransport injects a traceparent header that the server-side
// GinMiddleware extracts, so the client span and the server span share ONE trace
// ID — the probe→api call is one connected trace, not three orphan log lines.
func TestCrossProcessPropagation(t *testing.T) {
	exp := setupRecorder(t)

	// --- client side: WrapTransport injects propagation headers ---
	var forwarded http.Header
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		forwarded = r.Header.Clone()
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header)}, nil
	})
	client := &http.Client{Transport: WrapTransport(base)}
	req, _ := http.NewRequest("POST", "http://api.local/api/probes/1/system-statuses", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_ = resp.Body.Close()

	if forwarded.Get("traceparent") == "" {
		t.Fatal("WrapTransport did not inject a traceparent header")
	}

	// --- server side: GinMiddleware extracts it and continues the trace ---
	var serverTraceID trace.TraceID
	r := gin.New()
	r.Use(GinMiddleware("fwmon-api"))
	r.POST("/api/probes/:id/system-statuses", func(c *gin.Context) {
		serverTraceID = trace.SpanContextFromContext(c.Request.Context()).TraceID()
		c.Status(http.StatusOK)
	})
	sreq := httptest.NewRequest("POST", "/api/probes/1/system-statuses", nil)
	sreq.Header = forwarded // carry the injected traceparent across the "process boundary"
	r.ServeHTTP(httptest.NewRecorder(), sreq)

	spans := exp.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("want 2 recorded spans (client + server), got %d", len(spans))
	}
	if spans[0].SpanContext.TraceID() != spans[1].SpanContext.TraceID() {
		t.Errorf("client and server spans are on different traces: %s vs %s",
			spans[0].SpanContext.TraceID(), spans[1].SpanContext.TraceID())
	}
	if serverTraceID != spans[0].SpanContext.TraceID() {
		t.Errorf("server handler context trace %s != recorded trace %s", serverTraceID, spans[0].SpanContext.TraceID())
	}
	// The server span should be named by the route template (bounded cardinality).
	var sawRouteName bool
	for _, s := range spans {
		if s.Name == "/api/probes/:id/system-statuses" {
			sawRouteName = true
		}
	}
	if !sawRouteName {
		t.Error("server span should be named by the route template /api/probes/:id/system-statuses")
	}
}
