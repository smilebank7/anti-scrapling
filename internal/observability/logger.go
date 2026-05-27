package observability

import (
	"context"
	"log/slog"
	"os"
)

type contextKey string

const loggerCtxKey contextKey = "logger"

// NewLogger returns a slog.Logger with a JSON handler writing to stderr at the given level.
func NewLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// WithRequest stores a logger enriched with request_id and ip into ctx.
func WithRequest(ctx context.Context, requestID, ip string) context.Context {
	logger := FromContext(ctx).With(
		slog.String("request_id", requestID),
		slog.String("ip", ip),
	)
	return context.WithValue(ctx, loggerCtxKey, logger)
}

// FromContext retrieves the logger stored by WithRequest, or slog.Default() if none.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerCtxKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
