package observability_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/smilebank7/anti-scrapling/internal/observability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger_ReturnsNonNil(t *testing.T) {
	logger := observability.NewLogger(slog.LevelInfo)
	require.NotNil(t, logger)
}

func TestWithRequest_EnrichesLogger(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	original := slog.Default()
	slog.SetDefault(base)
	defer slog.SetDefault(original)

	ctx := context.Background()
	ctx = observability.WithRequest(ctx, "req-abc", "10.0.0.1")

	got := observability.FromContext(ctx)
	require.NotNil(t, got)
	got.Info("handled")

	out := buf.String()
	assert.Contains(t, out, "req-abc", "want request_id in JSON output")
	assert.Contains(t, out, "10.0.0.1", "want ip in JSON output")
}

func TestFromContext_FallsBackToDefault(t *testing.T) {
	logger := observability.FromContext(context.Background())
	assert.NotNil(t, logger)
}

func TestWithRequest_Chained(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	original := slog.Default()
	slog.SetDefault(base)
	defer slog.SetDefault(original)

	ctx := context.Background()
	ctx = observability.WithRequest(ctx, "id-1", "1.1.1.1")
	ctx = observability.WithRequest(ctx, "id-2", "2.2.2.2")

	observability.FromContext(ctx).Info("chained")
	out := buf.String()

	assert.Contains(t, out, "id-2", "most recent request_id should win")
	assert.Contains(t, out, "2.2.2.2", "most recent ip should win")
}
