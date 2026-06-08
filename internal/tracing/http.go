package tracing

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// instrumentationName labels the spans this package emits.
const instrumentationName = "firewall-mon/internal/tracing"

// GinMiddleware returns a gin middleware that opens a server span per request,
// extracting any inbound W3C trace context (so a probe→api call continues the
// probe's trace) and putting the span on the request context so downstream
// handlers and the slog access log inherit the trace/span IDs. Hand-rolled on
// the otel API rather than pulling the otelgin contrib module, which would force
// a gin minor-version upgrade. Returns a pass-through when tracing is disabled.
func GinMiddleware(serviceName string) gin.HandlerFunc {
	if !Enabled() {
		return func(c *gin.Context) { c.Next() }
	}
	tracer := otel.Tracer(instrumentationName)
	prop := otel.GetTextMapPropagator()
	return func(c *gin.Context) {
		ctx := prop.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		// Use the route template (e.g. /api/devices/:id) as the span name so
		// cardinality stays bounded; fall back to the method for unmatched routes.
		name := c.FullPath()
		if name == "" {
			name = c.Request.Method
		}

		ctx, span := tracer.Start(ctx, name,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.route", c.FullPath()),
				attribute.String("http.target", c.Request.URL.Path),
			),
		)
		defer span.End()

		c.Request = c.Request.WithContext(ctx)
		c.Next()

		status := c.Writer.Status()
		span.SetAttributes(attribute.Int("http.status_code", status))
		if status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(status))
		}
	}
}

// WrapTransport wraps an http.RoundTripper so outbound requests open a client
// span and inject the W3C `traceparent` header, connecting this process's trace
// to the server it calls (the probe→api hop AUDIT-150 calls out as invisible).
// Returns base unchanged when tracing is disabled. A nil base means
// http.DefaultTransport.
func WrapTransport(base http.RoundTripper) http.RoundTripper {
	if !Enabled() {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &roundTripper{
		base:   base,
		tracer: otel.Tracer(instrumentationName),
		prop:   otel.GetTextMapPropagator(),
	}
}

type roundTripper struct {
	base   http.RoundTripper
	tracer trace.Tracer
	prop   propagation.TextMapPropagator
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, span := rt.tracer.Start(req.Context(), "HTTP "+req.Method,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.method", req.Method),
			attribute.String("http.url", req.URL.String()),
		),
	)
	defer span.End()

	// Clone onto the span context and inject the propagation headers.
	req = req.Clone(ctx)
	rt.prop.Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return resp, err
	}
	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
	if resp.StatusCode >= 500 {
		span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
	}
	return resp, nil
}
