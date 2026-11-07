package logging

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// The request line every subcommand writes, through slog's JSON handler
// and through this one, so the cost of the added attributes and redaction
// shows next to the baseline.
func benchLog(b *testing.B, log *slog.Logger, ctx context.Context) {
	b.ReportAllocs()
	for b.Loop() {
		log.LogAttrs(ctx, slog.LevelInfo, "request",
			slog.String("request_id", "4bf92f3577b34da6"), slog.String("method", "POST"),
			slog.String("route", "/v1/check"), slog.Int("status", 200), slog.Int64("duration_us", 412))
	}
}

func BenchmarkJSONHandler(b *testing.B) {
	benchLog(b, slog.New(slog.NewJSONHandler(io.Discard, nil)), context.Background())
}

func BenchmarkHandler(b *testing.B) {
	benchLog(b, NewLogger(io.Discard, Options{Subcommand: "serve"}), context.Background())
}

func BenchmarkHandlerWithContext(b *testing.B) {
	ctx := WithTenant(WithCorrelationID(context.Background(), NewCorrelationID()), "acme")
	benchLog(b, NewLogger(io.Discard, Options{Subcommand: "serve"}), ctx)
}

func BenchmarkHandlerWithContextInGroup(b *testing.B) {
	ctx := WithCorrelationID(context.Background(), NewCorrelationID())
	benchLog(b, NewLogger(io.Discard, Options{Subcommand: "serve"}).WithGroup("http"), ctx)
}

// BenchmarkHandlerDisabled is a debug line at info: the cost every
// disabled call site pays.
func BenchmarkHandlerDisabled(b *testing.B) {
	log := NewLogger(io.Discard, Options{})
	ctx := WithCorrelationID(context.Background(), "c")
	b.ReportAllocs()
	for b.Loop() {
		log.LogAttrs(ctx, slog.LevelDebug, "request", slog.Int("status", 200))
	}
}

func BenchmarkRedactTaggedStruct(b *testing.B) {
	log := NewLogger(io.Discard, Options{})
	c := creds{User: "alice", Password: "x", Key: []byte("k")}
	b.ReportAllocs()
	for b.Loop() {
		log.Info("login", "creds", c)
	}
}
