package observability_test

import (
	"net/http/httptest"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/observability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealth_LivezAlwaysOK(t *testing.T) {
	h := observability.NewHealth()
	rr := httptest.NewRecorder()
	h.LivezHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	assert.Equal(t, 200, rr.Code)
}

func TestHealth_LivezOKWhenNotReady(t *testing.T) {
	h := observability.NewHealth()
	rr := httptest.NewRecorder()
	h.LivezHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	assert.Equal(t, 200, rr.Code, "liveness must be 200 regardless of readiness state")
}

func TestHealth_ReadyzInitiallyNotReady(t *testing.T) {
	h := observability.NewHealth()
	rr := httptest.NewRecorder()
	h.ReadyzHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/readyz", nil))
	assert.Equal(t, 503, rr.Code)
}

func TestHealth_ReadyzToggle(t *testing.T) {
	h := observability.NewHealth()

	h.SetReady(true)
	rr := httptest.NewRecorder()
	h.ReadyzHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/readyz", nil))
	require.Equal(t, 200, rr.Code)

	h.SetReady(false)
	rr2 := httptest.NewRecorder()
	h.ReadyzHandler().ServeHTTP(rr2, httptest.NewRequest("GET", "/readyz", nil))
	require.Equal(t, 503, rr2.Code)
}

func TestHealth_ReadyAccessor(t *testing.T) {
	h := observability.NewHealth()
	assert.False(t, h.Ready())
	h.SetReady(true)
	assert.True(t, h.Ready())
	h.SetReady(false)
	assert.False(t, h.Ready())
}
