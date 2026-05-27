package http2

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

const (
	h2AkamaiMismatchSignal = "h2_akamai_mismatch"
	ja4hUnknownSignal      = "ja4h_unknown"

	h2AkamaiMismatchScore = 35
	ja4hUnknownScore      = 20
)

var defaultKnownAkamai = map[string]string{
	"1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p": "chrome131",
	"1:65536,4:131072,5:16384|12517377|0|m,a,s,p":          "firefox134",
}

var defaultKnownJA4H = map[string]string{
	"ge11cn060000_7c8a3eaa8540_2c6e4f16ff14": "chrome131",
	"ge11cn060000_b5d4f0c8a3d1_e17a92c3b8f4": "firefox134",
}

type frameBytesContextKey struct{}

// Collector computes HTTP/2 Akamai and JA4H signals for a request.
type Collector struct {
	KnownAkamai map[string]string
	KnownJA4H   map[string]string
}

// NewCollector returns a Collector with the built-in browser fingerprints from
// testdata/http2.
func NewCollector() *Collector {
	return &Collector{
		KnownAkamai: cloneStringMap(defaultKnownAkamai),
		KnownJA4H:   cloneStringMap(defaultKnownJA4H),
	}
}

// WithFrameBytes stores raw HTTP/2 frame bytes on a context for Collector.
func WithFrameBytes(ctx context.Context, frameBytes []byte) context.Context {
	copyBytes := append([]byte(nil), frameBytes...)
	return context.WithValue(ctx, frameBytesContextKey{}, copyBytes)
}

// FrameBytesFromContext retrieves HTTP/2 frame bytes stored by WithFrameBytes.
func FrameBytesFromContext(ctx context.Context) ([]byte, bool) {
	if ctx == nil {
		return nil, false
	}
	frameBytes, ok := ctx.Value(frameBytesContextKey{}).([]byte)
	if !ok || len(frameBytes) == 0 {
		return nil, false
	}
	return append([]byte(nil), frameBytes...), true
}

// Name returns the unique collector name.
func (c *Collector) Name() string {
	return "http2"
}

// Collect computes JA4H for HTTP/1.1 or HTTP/2 requests and, when raw HTTP/2
// frames were attached with WithFrameBytes, computes the Akamai H2 fingerprint.
func (c *Collector) Collect(ctx types.RequestContext) ([]types.Signal, error) {
	if ctx.Request == nil {
		return nil, nil
	}

	collector := c
	if collector == nil {
		collector = NewCollector()
	}
	if collector.KnownAkamai == nil {
		collector.KnownAkamai = defaultKnownAkamai
	}
	if collector.KnownJA4H == nil {
		collector.KnownJA4H = defaultKnownJA4H
	}

	signals := make([]types.Signal, 0, 2)
	request := requestWithContextHeaders(ctx)
	ja4h := ComputeJA4H(request, ctx.HeaderOrder)
	if ja4h != "" {
		if _, ok := collector.KnownJA4H[ja4h]; !ok {
			signals = append(signals, types.Signal{
				Name:   ja4hUnknownSignal,
				Score:  ja4hUnknownScore,
				Reason: "JA4H fingerprint is not in the known browser baseline",
				Detail: map[string]any{"ja4h": ja4h},
			})
		}
	}

	frameBytes, ok := frameBytesFromRequestContext(ctx)
	if !ok {
		return signals, nil
	}

	akamai, err := ComputeAkamaiFingerprintBytes(frameBytes)
	if err != nil {
		return signals, err
	}
	if akamai == "" {
		return signals, nil
	}

	if signal := collector.akamaiSignal(ctx.Request, akamai); signal != nil {
		signals = append(signals, *signal)
	}

	return signals, nil
}

func (c *Collector) akamaiSignal(req *http.Request, akamai string) *types.Signal {
	if expected := expectedAkamaiForRequest(req); expected != "" {
		if akamai == expected {
			return nil
		}
		return &types.Signal{
			Name:   h2AkamaiMismatchSignal,
			Score:  h2AkamaiMismatchScore,
			Reason: "HTTP/2 Akamai fingerprint does not match the declared browser family",
			Detail: map[string]any{"akamai": akamai, "expected": expected},
		}
	}

	if _, ok := c.KnownAkamai[akamai]; ok {
		return nil
	}
	return &types.Signal{
		Name:   h2AkamaiMismatchSignal,
		Score:  h2AkamaiMismatchScore,
		Reason: "HTTP/2 Akamai fingerprint is not in the known browser baseline",
		Detail: map[string]any{"akamai": akamai},
	}
}

func requestWithContextHeaders(ctx types.RequestContext) *http.Request {
	req := ctx.Request
	if req == nil || len(ctx.Headers) == 0 {
		return req
	}
	clone := new(http.Request)
	*clone = *req
	clone.Header = ctx.Headers.Clone()
	return clone
}

func frameBytesFromRequestContext(ctx types.RequestContext) ([]byte, bool) {
	if frameBytes, ok := FrameBytesFromContext(ctx.Ctx); ok {
		return frameBytes, true
	}
	if ctx.Request != nil {
		return FrameBytesFromContext(ctx.Request.Context())
	}
	return nil, false
}

func expectedAkamaiForRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	ua := strings.ToLower(req.UserAgent())
	switch {
	case strings.Contains(ua, "firefox/134"):
		return "1:65536,4:131072,5:16384|12517377|0|m,a,s,p"
	case strings.Contains(ua, "chrome/131") || strings.Contains(ua, "chromium/131"):
		return "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p"
	default:
		return ""
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func signalListString(signals []types.Signal) string {
	names := make([]string, 0, len(signals))
	for _, signal := range signals {
		names = append(names, fmt.Sprintf("%s:%d", signal.Name, signal.Score))
	}
	return strings.Join(names, ",")
}
