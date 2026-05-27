package pipeline_test

import (
	"context"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/cache"
	"github.com/anti-scrapling/anti-scrapling/internal/pipeline"
	"github.com/anti-scrapling/anti-scrapling/internal/policy"
	"github.com/anti-scrapling/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCollector struct {
	name    string
	signals []types.Signal
	calls   int64
	delay   time.Duration
}

func (m *mockCollector) Name() string { return m.name }

func (m *mockCollector) Collect(_ types.RequestContext) ([]types.Signal, error) {
	atomic.AddInt64(&m.calls, 1)
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return m.signals, nil
}

func (m *mockCollector) callCount() int64 { return atomic.LoadInt64(&m.calls) }

func makeReq(ip, ja3, ua string) types.RequestContext {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Header.Set("User-Agent", ua)
	return types.RequestContext{
		Ctx:      context.Background(),
		Request:  r,
		RemoteIP: ip,
		JA3:      ja3,
		Headers:  r.Header,
	}
}

func TestDecide_AllCollectorsInvoked(t *testing.T) {
	c1 := &mockCollector{name: "c1"}
	c2 := &mockCollector{name: "c2"}
	c3 := &mockCollector{name: "c3"}

	p := pipeline.New(pipeline.PipelineConfig{
		Collectors: []types.SignalCollector{c1, c2, c3},
	})

	p.Decide(context.Background(), makeReq("1.2.3.4", "", "Mozilla/5.0"), false)

	assert.Equal(t, int64(1), c1.callCount())
	assert.Equal(t, int64(1), c2.callCount())
	assert.Equal(t, int64(1), c3.callCount())
}

func TestDecide_Parallel(t *testing.T) {
	delay := 20 * time.Millisecond
	collectors := []types.SignalCollector{
		&mockCollector{name: "c1", delay: delay},
		&mockCollector{name: "c2", delay: delay},
		&mockCollector{name: "c3", delay: delay},
		&mockCollector{name: "c4", delay: delay},
	}
	p := pipeline.New(pipeline.PipelineConfig{Collectors: collectors})

	start := time.Now()
	p.Decide(context.Background(), makeReq("1.2.3.4", "", "Mozilla/5.0"), false)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 3*delay,
		"collectors must run in parallel: elapsed=%v, serial would be %v", elapsed, 4*delay)
}

func TestDecide_CacheHitSkipsCollectors(t *testing.T) {
	c := &mockCollector{name: "c1", signals: []types.Signal{{Name: "sig", Score: 10}}}
	p := pipeline.New(pipeline.PipelineConfig{
		Collectors: []types.SignalCollector{c},
		Cache:      cache.NewMemory(100),
		CacheTTL:   60 * time.Second,
	})

	req := makeReq("1.2.3.4", "", "Mozilla/5.0")
	d1 := p.Decide(context.Background(), req, false)
	require.Equal(t, int64(1), c.callCount())

	d2 := p.Decide(context.Background(), req, false)
	assert.Equal(t, int64(1), c.callCount(), "cache hit must not invoke collector again")
	assert.Equal(t, d1.Verdict, d2.Verdict)
	assert.Equal(t, d1.Score, d2.Score)
}

func TestDecide_HighScore_Deny(t *testing.T) {
	collectors := []types.SignalCollector{
		&mockCollector{name: "c1", signals: []types.Signal{{Name: "s1", Score: 25}}},
		&mockCollector{name: "c2", signals: []types.Signal{{Name: "s2", Score: 25}}},
		&mockCollector{name: "c3", signals: []types.Signal{{Name: "s3", Score: 25}}},
		&mockCollector{name: "c4", signals: []types.Signal{{Name: "s4", Score: 25}}},
	}
	p := pipeline.New(pipeline.PipelineConfig{
		Collectors: collectors,
		Policy: &types.PolicyConfig{
			Scoring: types.ScoringConfig{DenyThreshold: 80, ChallengeThreshold: 50},
			Policy:  types.PolicySection{Default: "allow"},
		},
	})

	d := p.Decide(context.Background(), makeReq("1.2.3.4", "", "Mozilla/5.0"), false)
	assert.Equal(t, types.VerdictDeny, d.Verdict)
	assert.Equal(t, 100, d.Score)
}

func TestDecide_PolicyEvaluationRuns(t *testing.T) {
	policyCfg := &types.PolicyConfig{
		Policy: types.PolicySection{
			Default: "allow",
			Rules: []types.PolicyRule{
				{Name: "force-deny", Match: map[string]any{"score": ">=20"}, Action: "deny"},
			},
		},
		Scoring: types.ScoringConfig{DenyThreshold: 80, ChallengeThreshold: 50},
	}
	eval, err := policy.NewEvaluator(policyCfg)
	require.NoError(t, err)

	p := pipeline.New(pipeline.PipelineConfig{
		Collectors: []types.SignalCollector{
			&mockCollector{name: "c1", signals: []types.Signal{{Name: "s1", Score: 30}}},
		},
		Evaluator: eval,
		Policy:    policyCfg,
	})

	d := p.Decide(context.Background(), makeReq("1.2.3.4", "", "Mozilla/5.0"), false)
	assert.Equal(t, types.VerdictDeny, d.Verdict, "policy rule must override threshold-based allow")
	assert.Equal(t, "force-deny", d.PolicyName)
}

func TestDecide_ValidToken_Bypasses(t *testing.T) {
	p := pipeline.New(pipeline.PipelineConfig{
		Collectors: []types.SignalCollector{
			&mockCollector{name: "c1", signals: []types.Signal{{Name: "s1", Score: 60}}},
		},
		Policy: &types.PolicyConfig{
			Scoring: types.ScoringConfig{DenyThreshold: 80, ChallengeThreshold: 50},
			Policy:  types.PolicySection{Default: "allow"},
		},
	})

	d := p.Decide(context.Background(), makeReq("1.2.3.4", "", "Mozilla/5.0"), true)
	assert.Equal(t, types.VerdictAllow, d.Verdict, "valid token must bypass challenge at score 60")
}

func TestDecide_CacheDifferentTokenState(t *testing.T) {
	c := &mockCollector{name: "c1", signals: []types.Signal{{Name: "s1", Score: 60}}}
	p := pipeline.New(pipeline.PipelineConfig{
		Collectors: []types.SignalCollector{c},
		Cache:      cache.NewMemory(100),
		Policy: &types.PolicyConfig{
			Scoring: types.ScoringConfig{DenyThreshold: 80, ChallengeThreshold: 50},
			Policy:  types.PolicySection{Default: "allow"},
		},
	})

	req := makeReq("1.2.3.4", "", "Mozilla/5.0")
	d1 := p.Decide(context.Background(), req, false)
	d2 := p.Decide(context.Background(), req, true)

	assert.Equal(t, types.VerdictChallenge, d1.Verdict)
	assert.Equal(t, types.VerdictAllow, d2.Verdict)
	assert.Equal(t, int64(2), c.callCount(), "different token states must use separate cache slots")
}

func TestDecide_EmptyCollectors(t *testing.T) {
	p := pipeline.New(pipeline.PipelineConfig{})
	d := p.Decide(context.Background(), makeReq("1.2.3.4", "", "ua"), false)
	assert.Equal(t, types.VerdictAllow, d.Verdict)
	assert.Equal(t, 0, d.Score)
}
