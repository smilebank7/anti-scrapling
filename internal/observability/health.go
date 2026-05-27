package observability

import (
	"net/http"
	"sync/atomic"
)

// Health manages liveness and readiness probe state.
type Health struct {
	ready atomic.Bool
}

// NewHealth returns a Health with readiness initially false.
func NewHealth() *Health {
	return &Health{}
}

// SetReady flips the readiness gate.
func (h *Health) SetReady(ready bool) {
	h.ready.Store(ready)
}

// Ready reports whether the service has declared itself ready.
func (h *Health) Ready() bool {
	return h.ready.Load()
}

// LivezHandler handles /healthz — always 200 OK.
func (h *Health) LivezHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
}

// ReadyzHandler handles /readyz — 200 when ready, 503 otherwise.
func (h *Health) ReadyzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if h.ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready\n"))
		}
	})
}
