package proxy

import (
	"net/http"
	"strings"
)

// HopByHopHeaders lists the headers that must not be forwarded through a proxy per RFC 7230 §6.1.
var HopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// StripHopByHop removes hop-by-hop headers from h.
// It also removes any header names listed in the Connection header value.
func StripHopByHop(h http.Header) {
	for _, v := range h["Connection"] {
		for _, field := range strings.Split(v, ",") {
			if f := strings.TrimSpace(field); f != "" {
				h.Del(f)
			}
		}
	}
	for _, name := range HopByHopHeaders {
		h.Del(name)
	}
}
