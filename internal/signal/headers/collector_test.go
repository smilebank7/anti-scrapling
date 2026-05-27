package headers

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testdataDir = "../../../testdata/headers/"

func parseFixture(t *testing.T, path string) (headerOrder []string, h http.Header) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "fixture %s", path)

	h = make(http.Header)
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		idx := strings.Index(line, ": ")
		if idx < 0 {
			continue
		}
		name := line[:idx]
		value := line[idx+2:]
		h.Add(name, value)
		headerOrder = append(headerOrder, name)
	}
	return headerOrder, h
}

func makeCtx(t *testing.T, fixture, remoteIP string) types.RequestContext {
	t.Helper()
	order, h := parseFixture(t, testdataDir+fixture)
	req := &http.Request{Header: h}
	return types.RequestContext{
		Ctx:         context.Background(),
		Request:     req,
		RemoteIP:    remoteIP,
		Headers:     h,
		HeaderOrder: order,
	}
}

func TestCollector_RealBrowserScoresZero(t *testing.T) {
	browsers := []string{
		"chrome131_get.txt",
		"firefox134_get.txt",
		"safari18_get.txt",
	}
	for _, fixture := range browsers {
		t.Run(fixture, func(t *testing.T) {
			c := NewCollector()
			ctx := makeCtx(t, fixture, "10.0.0.1")
			signals, err := c.Collect(ctx)
			require.NoError(t, err)
			assert.Empty(t, signals, "real browser fixture should produce 0 signals; got: %v", signals)
		})
	}
}

func TestCollector_ScraperProducesAnomalies(t *testing.T) {
	scrapers := []string{
		"curl_cffi_chrome131_get.txt",
		"curl_default_get.txt",
		"python_requests_get.txt",
	}
	for _, fixture := range scrapers {
		t.Run(fixture, func(t *testing.T) {
			c := NewCollector()
			ctx := makeCtx(t, fixture, "10.0.0.2")
			signals, err := c.Collect(ctx)
			require.NoError(t, err)
			assert.NotEmpty(t, signals, "scraper fixture should produce ≥1 anomaly signal")
		})
	}
}

func TestCollector_BrowserForgeQuirkTriggered(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36`)
	h.Add("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	h.Add("Sec-Fetch-Site", "?1")
	h.Add("Sec-Fetch-Mode", "navigate")
	h.Add("Sec-Fetch-User", "?1")
	h.Add("Sec-Fetch-Dest", "document")

	order := []string{
		"Host", "Connection", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Upgrade-Insecure-Requests", "User-Agent", "Accept",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
		"Accept-Encoding", "Accept-Language",
	}

	c := NewCollector()
	ctx := types.RequestContext{
		Ctx:         context.Background(),
		Request:     &http.Request{Header: h},
		RemoteIP:    "10.0.0.3",
		Headers:     h,
		HeaderOrder: order,
	}

	signals, err := c.Collect(ctx)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, s := range signals {
		names[s.Name] = true
	}
	assert.True(t, names[SignalBrowserForgeQuirk], "browserforge_quirk should fire for Sec-Fetch-Site: ?1")
}

func TestCollector_GoogleRefererAnomaly(t *testing.T) {
	c := NewCollector()
	h := make(http.Header)
	h.Add("User-Agent", "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36")
	h.Add("Referer", "https://www.google.com/")
	h.Add("Accept", "*/*")
	h.Add("Accept-Encoding", "gzip, deflate")
	h.Add("Accept-Language", "en-US,en;q=0.9")
	h.Add("Connection", "keep-alive")
	h.Add("Sec-Fetch-Site", "cross-site")
	h.Add("Sec-Fetch-Mode", "navigate")

	order := []string{
		"Host", "Connection", "User-Agent", "Accept",
		"Sec-Fetch-Site", "Sec-Fetch-Mode",
		"Accept-Encoding", "Accept-Language", "Referer",
	}

	var triggered bool
	for i := 0; i < 100; i++ {
		ctx := types.RequestContext{
			Ctx:         context.Background(),
			Request:     &http.Request{Header: h},
			RemoteIP:    "10.0.0.4",
			Headers:     h,
			HeaderOrder: order,
		}
		sigs, err := c.Collect(ctx)
		require.NoError(t, err)
		for _, s := range sigs {
			if s.Name == SignalGoogleRefererAnomaly {
				triggered = true
			}
		}
	}
	assert.True(t, triggered, "google_referer_anomaly should fire after 100 Google-referer requests")
}

func TestCollector_Name(t *testing.T) {
	assert.Equal(t, "headers", NewCollector().Name())
}

func TestCollector_ImplementsInterface(t *testing.T) {
	var _ types.SignalCollector = NewCollector()
}
