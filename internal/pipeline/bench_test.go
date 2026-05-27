package pipeline_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/cache"
	"github.com/smilebank7/anti-scrapling/internal/pipeline"
	"github.com/smilebank7/anti-scrapling/internal/types"
)

func newRealisticPipeline(withCache bool) *pipeline.Pipeline {
	collectors := []types.SignalCollector{
		&mockCollector{name: "tls", delay: 50 * time.Microsecond},
		&mockCollector{name: "http2", delay: 50 * time.Microsecond},
		&mockCollector{name: "headers", delay: 50 * time.Microsecond},
		&mockCollector{name: "ip", delay: 50 * time.Microsecond},
	}
	cfg := pipeline.PipelineConfig{Collectors: collectors}
	if withCache {
		cfg.Cache = cache.NewMemory(10_000)
		cfg.CacheTTL = 60 * time.Second
	}
	return pipeline.New(cfg)
}

func BenchmarkPipeline_Decide_Uncached(b *testing.B) {
	p := newRealisticPipeline(false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := makeReq(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), "", "Mozilla/5.0")
		p.Decide(context.Background(), req, false)
	}
}

func BenchmarkPipeline_Decide_Cached(b *testing.B) {
	p := newRealisticPipeline(true)
	req := makeReq("10.0.0.1", "", "Mozilla/5.0")
	p.Decide(context.Background(), req, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Decide(context.Background(), req, false)
	}
}

func TestPipelineP99(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping P99 measurement in short mode")
	}

	p := newRealisticPipeline(false)

	const N = 1000
	latencies := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		req := makeReq(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), "", "Mozilla/5.0")
		start := time.Now()
		p.Decide(context.Background(), req, false)
		latencies[i] = time.Since(start)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	p50 := latencies[N*50/100]
	p95 := latencies[N*95/100]
	p99 := latencies[N*99/100]
	t.Logf("pipeline latency (N=%d, 4 collectors×50µs each): P50=%v P95=%v P99=%v (target <2ms)", N, p50, p95, p99)

	if p99 > 2*time.Millisecond {
		t.Logf("WARN: P99 %v exceeds 2ms target", p99)
	}
}
