package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/server"
	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test source file location")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func waitAddr(t *testing.T, srv *server.Server, configured string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		addr := srv.Addr()
		if addr != configured {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not bind within deadline (configured: %s)", configured)
	return ""
}

func TestBuildAndServe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream ok\n")
	}))
	t.Cleanup(upstream.Close)

	root := projectRoot(t)
	configPath := filepath.Join(root, "policies", "default.yaml")

	cfg, err := loadConfig(configPath)
	require.NoError(t, err, "loadConfig failed")

	cfg.Target = upstream.URL
	cfg.Bind = "127.0.0.1:0"
	cfg.KeyFile = filepath.Join(t.TempDir(), "token.key")

	d, err := buildDeps(cfg)
	require.NoError(t, err, "buildDeps failed")
	t.Cleanup(func() { _ = d.cache.Close() })

	adminSrv := server.New("127.0.0.1:0", buildAdminHandler(d), nil)
	adminErrCh := make(chan error, 1)
	go func() { adminErrCh <- adminSrv.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = adminSrv.Stop(ctx)
		<-adminErrCh
	})

	mainSrv := server.New("127.0.0.1:0", buildMainHandler(d), nil)
	mainErrCh := make(chan error, 1)
	go func() { mainErrCh <- mainSrv.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = mainSrv.Stop(ctx)
		<-mainErrCh
	})

	adminAddr := waitAddr(t, adminSrv, "127.0.0.1:0")
	mainAddr := waitAddr(t, mainSrv, "127.0.0.1:0")

	d.health.SetReady(true)

	t.Run("healthz", func(t *testing.T) {
		resp, err := http.Get("http://" + adminAddr + "/healthz")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("readyz", func(t *testing.T) {
		resp, err := http.Get("http://" + adminAddr + "/readyz")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("challenge_page_is_html", func(t *testing.T) {
		resp, err := http.Get("http://" + mainAddr + "/__as/challenge?origin=/")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		ct := resp.Header.Get("Content-Type")
		assert.True(t, strings.HasPrefix(ct, "text/html"), "Content-Type = %q, want text/html prefix", ct)
	})

	t.Run("root_without_token_challenges_or_denies", func(t *testing.T) {
		client := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Get("http://" + mainAddr + "/")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t,
			resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusForbidden,
			"expected 302 or 403, got %d", resp.StatusCode)

		if resp.StatusCode == http.StatusFound {
			loc := resp.Header.Get("Location")
			assert.Contains(t, loc, "/__as/challenge",
				"redirect should point to challenge page, Location = %q", loc)
		}
	})

	t.Run("admin_audit_json", func(t *testing.T) {
		resp, err := http.Get("http://" + adminAddr + "/admin/audit")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		ct := resp.Header.Get("Content-Type")
		assert.Contains(t, ct, "application/json")
	})

	t.Run("v1_decide_returns_decision", func(t *testing.T) {
		body := strings.NewReader(`{"method":"GET","path":"/","host":"x","remote_ip":"1.2.3.4","headers":{},"header_order":[]}`)
		resp, err := http.Post("http://"+adminAddr+"/v1/decide", "application/json", body)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
		var dec types.Decision
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&dec))
		assert.NotEmpty(t, dec.Verdict)
		assert.NotEmpty(t, dec.RequestID)
	})

	t.Run("v1_decide_empty_body_is_400", func(t *testing.T) {
		resp, err := http.Post("http://"+adminAddr+"/v1/decide", "application/json", strings.NewReader(""))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("v1_policy_returns_yaml", func(t *testing.T) {
		resp, err := http.Get("http://" + adminAddr + "/v1/policy")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "yaml")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "version:")
	})
}
