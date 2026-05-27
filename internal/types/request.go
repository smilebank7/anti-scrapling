package types

import (
	"context"
	"net/http"
)

// RequestContext carries all per-request data passed to SignalCollectors.
type RequestContext struct {
	Ctx      context.Context
	Request  *http.Request
	RemoteIP string

	// ClientHello is the raw TLS ClientHello bytes captured at handshake time.
	ClientHello []byte

	// JA3 is the JA3 fingerprint computed by the tls collector.
	JA3 string

	// JA4 is the JA4 fingerprint computed by the tls collector.
	JA4 string

	// Headers is the canonical header map with preserved case.
	Headers http.Header

	// HeaderOrder lists header names in the order they were received over the wire.
	HeaderOrder []string
}
