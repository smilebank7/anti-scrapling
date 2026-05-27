package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/token"
	"golang.org/x/net/http2"
)

// Proxy is a reverse-proxy forwarder wrapping httputil.ReverseProxy.
type Proxy struct {
	rp     *httputil.ReverseProxy
	target *url.URL
}

// New constructs a Proxy that forwards to targetURL with HTTP/2 backend support.
func New(targetURL string) (*Proxy, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid target URL: %w", err)
	}

	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if err := http2.ConfigureTransport(t); err != nil {
		return nil, fmt.Errorf("proxy: configure http2 transport: %w", err)
	}

	rp := &httputil.ReverseProxy{
		Director:  newDirector(u),
		Transport: t,
	}

	return &Proxy{rp: rp, target: u}, nil
}

// Forward optionally injects the pass-token cookie then reverse-proxies the request.
// If passToken is non-empty, the __as_pass cookie is written to w before forwarding.
func (p *Proxy) Forward(w http.ResponseWriter, r *http.Request, passToken string) {
	if passToken != "" {
		token.SetCookie(w, token.DefaultCookieName, passToken, time.Hour, r.TLS != nil)
	}
	p.rp.ServeHTTP(w, r)
}

func newDirector(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = joinPath(target.Path, req.URL.Path)

		switch {
		case target.RawQuery == "" || req.URL.RawQuery == "":
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		default:
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}

		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}

		StripHopByHop(req.Header)

		proto := "http"
		if req.TLS != nil {
			proto = "https"
		}
		req.Header.Set("X-Forwarded-Proto", proto)
		req.Header.Set("X-Forwarded-Host", req.Host)

		req.Host = target.Host
	}
}

func joinPath(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		if a == "" {
			return b
		}
		return a + "/" + b
	}
	return a + b
}
