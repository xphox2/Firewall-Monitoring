package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// validSpanCtx returns a context carrying a fixed, valid OTel span context.
func validSpanCtx(t *testing.T) (context.Context, string, string) {
	t.Helper()
	const traceHex = "0102030405060708090a0b0c0d0e0f10"
	const spanHex = "0102030405060708"
	tid, err := trace.TraceIDFromHex(traceHex)
	if err != nil {
		t.Fatalf("trace id: %v", err)
	}
	sid, err := trace.SpanIDFromHex(spanHex)
	if err != nil {
		t.Fatalf("span id: %v", err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
	return trace.ContextWithSpanContext(context.Background(), sc), traceHex, spanHex
}

// TestTraceHandler_StampsTraceID verifies AUDIT-150 log↔trace correlation: a
// record logged with an active span carries trace_id/span_id; one without does not.
func TestTraceHandler_StampsTraceID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(traceHandler{slog.NewJSONHandler(&buf, nil)})

	ctx, traceHex, spanHex := validSpanCtx(t)
	logger.InfoContext(ctx, "with span")
	out := buf.String()
	if !strings.Contains(out, traceHex) {
		t.Errorf("log line missing trace_id %s: %s", traceHex, out)
	}
	if !strings.Contains(out, spanHex) {
		t.Errorf("log line missing span_id %s: %s", spanHex, out)
	}

	buf.Reset()
	logger.InfoContext(context.Background(), "no span")
	if out := buf.String(); strings.Contains(out, "trace_id") {
		t.Errorf("log line without a span must not carry trace_id: %s", out)
	}
}

// TestTraceHandler_WithAttrsKeepsStamping ensures the stamping survives a logger
// derived via With(...) (the embedded handler's WithAttrs would otherwise unwrap us).
func TestTraceHandler_WithAttrsKeepsStamping(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(traceHandler{slog.NewJSONHandler(&buf, nil)}).With("component", "x")

	ctx, traceHex, _ := validSpanCtx(t)
	logger.InfoContext(ctx, "derived")
	if out := buf.String(); !strings.Contains(out, traceHex) {
		t.Errorf("derived logger lost trace stamping: %s", out)
	}
}
