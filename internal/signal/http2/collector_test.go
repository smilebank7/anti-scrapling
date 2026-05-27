package http2

import (
	"context"
	"net/http"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

func TestCollectorReturnsGracefullyWithoutHTTP2Frames(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "python-requests/2.32.3")

	signals, err := NewCollector().Collect(types.RequestContext{
		Ctx:         context.Background(),
		Request:     req,
		HeaderOrder: []string{"Host", "User-Agent"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(signals) != 1 || signals[0].Name != ja4hUnknownSignal || signals[0].Score != ja4hUnknownScore {
		t.Fatalf("unexpected signals: %v", signals)
	}
}

func TestCollectorDetectsAkamaiMismatch(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36")

	chromeJA4H := ComputeJA4H(req, []string{"Host", "User-Agent"})
	collector := &Collector{
		KnownAkamai: cloneStringMap(defaultKnownAkamai),
		KnownJA4H:   map[string]string{chromeJA4H: "test"},
	}
	ctx := WithFrameBytes(context.Background(), synthesizeFramesFromAkamai(t, "1:65536,4:131072,5:16384|12517377|0|m,a,s,p"))

	signals, err := collector.Collect(types.RequestContext{
		Ctx:         ctx,
		Request:     req,
		HeaderOrder: []string{"Host", "User-Agent"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(signals) != 1 || signals[0].Name != h2AkamaiMismatchSignal || signals[0].Score != h2AkamaiMismatchScore {
		t.Fatalf("unexpected signals: %v", signals)
	}
}

func TestFrameBytesContextCopiesData(t *testing.T) {
	original := []byte{1, 2, 3}
	ctx := WithFrameBytes(context.Background(), original)
	original[0] = 9

	got, ok := FrameBytesFromContext(ctx)
	if !ok {
		t.Fatal("FrameBytesFromContext did not find frame bytes")
	}
	got[1] = 9
	again, ok := FrameBytesFromContext(ctx)
	if !ok {
		t.Fatal("FrameBytesFromContext did not find frame bytes on second read")
	}
	if string(got) == string(again) || again[0] != 1 || again[1] != 2 {
		t.Fatalf("frame bytes were not copied defensively: got=%v again=%v", got, again)
	}
}
