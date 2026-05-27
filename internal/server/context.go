package server

import "context"

type captureContextKey struct{}

// ContextWithCapture stores a TLS ClientHello capture on ctx.
func ContextWithCapture(ctx context.Context, capture *ClientHelloCapture) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if capture == nil {
		return ctx
	}
	return context.WithValue(ctx, captureContextKey{}, cloneCapture(capture))
}

// CaptureFromContext returns the TLS ClientHello capture stored on ctx, if any.
func CaptureFromContext(ctx context.Context) *ClientHelloCapture {
	if ctx == nil {
		return nil
	}
	capture, ok := ctx.Value(captureContextKey{}).(*ClientHelloCapture)
	if !ok || capture == nil {
		return nil
	}
	return cloneCapture(capture)
}
