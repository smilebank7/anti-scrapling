package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/proxy"
	"github.com/anti-scrapling/anti-scrapling/internal/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newUpstream(handler http.HandlerFunc) (*httptest.Server, func()) {
	srv := httptest.NewServer(handler)
	return srv, srv.Close
}

func TestForward_200(t *testing.T) {
	upstream, stop := newUpstream(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	p, err := proxy.New(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	p.Forward(rr, req, "")
	assert.Equal(t, http.StatusOK, rr.Code)
	for _, c := range rr.Result().Cookies() {
		assert.NotEqual(t, token.DefaultCookieName, c.Name, "no pass cookie expected")
	}
}

func TestForward_302(t *testing.T) {
	upstream, stop := newUpstream(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/new-location", http.StatusFound)
	})
	defer stop()

	p, err := proxy.New(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	p.Forward(rr, req, "")
	assert.Equal(t, http.StatusFound, rr.Code)
}

func TestForward_500(t *testing.T) {
	upstream, stop := newUpstream(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer stop()

	p, err := proxy.New(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	p.Forward(rr, req, "")
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestForward_CookieSet_WhenPassTokenNonEmpty(t *testing.T) {
	upstream, stop := newUpstream(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	p, err := proxy.New(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	p.Forward(rr, req, "tok123")

	var found *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == token.DefaultCookieName {
			found = c
			break
		}
	}
	require.NotNil(t, found, "expected __as_pass cookie")
	assert.Equal(t, "tok123", found.Value)
}

func TestForward_NoCookie_WhenPassTokenEmpty(t *testing.T) {
	upstream, stop := newUpstream(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	p, err := proxy.New(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	p.Forward(rr, req, "")

	for _, c := range rr.Result().Cookies() {
		assert.NotEqual(t, token.DefaultCookieName, c.Name)
	}
}

func TestForward_XForwardedHeaders(t *testing.T) {
	var gotXFF, gotXFP, gotXFH string
	upstream, stop := newUpstream(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotXFP = r.Header.Get("X-Forwarded-Proto")
		gotXFH = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	p, err := proxy.New(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"
	req.RemoteAddr = "10.0.0.1:9000"
	rr := httptest.NewRecorder()

	p.Forward(rr, req, "")

	assert.Contains(t, gotXFF, "10.0.0.1", "X-Forwarded-For must contain client IP")
	assert.Equal(t, "http", gotXFP)
	assert.Equal(t, "example.com", gotXFH)
}

func TestForward_HopByHopStripped(t *testing.T) {
	var gotConnection, gotKeepAlive string
	upstream, stop := newUpstream(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("Connection")
		gotKeepAlive = r.Header.Get("Keep-Alive")
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	p, err := proxy.New(upstream.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	rr := httptest.NewRecorder()

	p.Forward(rr, req, "")

	assert.Empty(t, gotConnection)
	assert.Empty(t, gotKeepAlive)
}
