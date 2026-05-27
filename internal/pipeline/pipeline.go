// Package pipeline orchestrates signal collectors in parallel, applies policy, and returns decisions.
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/cache"
	"github.com/smilebank7/anti-scrapling/internal/decision"
	"github.com/smilebank7/anti-scrapling/internal/policy"
	"github.com/smilebank7/anti-scrapling/internal/types"
)

const defaultCacheTTL = 60 * time.Second

type PipelineConfig struct {
	Collectors []types.SignalCollector
	Evaluator  *policy.Evaluator
	Cache      cache.Cache
	CacheTTL   time.Duration
	Policy     *types.PolicyConfig
}

type Pipeline struct {
	collectors []types.SignalCollector
	evaluator  *policy.Evaluator
	cache      cache.Cache
	cacheTTL   time.Duration
	policy     *types.PolicyConfig
}

func New(cfg PipelineConfig) *Pipeline {
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	return &Pipeline{
		collectors: cfg.Collectors,
		evaluator:  cfg.Evaluator,
		cache:      cfg.Cache,
		cacheTTL:   ttl,
		policy:     cfg.Policy,
	}
}

// Decide runs the pipeline: cache check → parallel collection → combine → cache store → return.
// Cache key encodes (remote_ip, ja3, ua_hash, hasValidToken) so each token state is independent.
func (p *Pipeline) Decide(ctx context.Context, req types.RequestContext, hasValidToken bool) types.Decision {
	key := computeCacheKey(req, hasValidToken)

	if p.cache != nil {
		if data, hit, _ := p.cache.Get(ctx, key); hit && len(data) > 0 {
			var d types.Decision
			if err := json.Unmarshal(data, &d); err == nil {
				return d
			}
		}
	}

	signals := p.collectParallel(req)
	d := decision.Combine(signals, p.policy, buildRequestInfo(req), hasValidToken, p.buildEvalFn())

	if p.cache != nil {
		if data, err := json.Marshal(d); err == nil {
			_ = p.cache.Set(ctx, key, data, p.cacheTTL)
		}
	}

	return d
}

// collectParallel runs all collectors concurrently. Each goroutine owns a dedicated slot so no
// mutex is needed during writes; WaitGroup provides the happens-before relationship.
// Collector errors are swallowed because adversaries may deliberately trigger parse failures.
func (p *Pipeline) collectParallel(req types.RequestContext) []types.Signal {
	n := len(p.collectors)
	if n == 0 {
		return nil
	}

	type slot struct{ sigs []types.Signal }
	slots := make([]slot, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i, c := range p.collectors {
		i, c := i, c
		go func() {
			defer wg.Done()
			sigs, _ := c.Collect(req)
			slots[i].sigs = sigs
		}()
	}
	wg.Wait()

	total := 0
	for i := range slots {
		total += len(slots[i].sigs)
	}
	if total == 0 {
		return nil
	}
	all := make([]types.Signal, 0, total)
	for i := range slots {
		all = append(all, slots[i].sigs...)
	}
	return all
}

// buildEvalFn bridges policy.Evaluator → decision.EvalCtx to avoid an import cycle
// between the decision and policy packages.
func (p *Pipeline) buildEvalFn() func(decision.EvalCtx) decision.EvalResult {
	if p.evaluator == nil {
		return nil
	}
	eval := p.evaluator
	return func(ec decision.EvalCtx) decision.EvalResult {
		polCtx := policy.EvaluationContext{
			Request: policy.RequestInfo{
				Method:    ec.RequestInfo.Method,
				Path:      ec.RequestInfo.Path,
				Host:      ec.RequestInfo.Host,
				UserAgent: ec.RequestInfo.UserAgent,
			},
			IP: policy.IPInfo{
				Address:  ec.RequestInfo.RemoteIP,
				Category: ec.RequestInfo.IPCategory,
			},
			JA3:           ec.RequestInfo.JA3,
			JA4:           ec.RequestInfo.JA4,
			Score:         ec.Score,
			HasValidToken: ec.HasValidToken,
			Signals:       make(map[string]int, len(ec.Signals)),
		}
		for name, sig := range ec.Signals {
			polCtx.Signals[name] = sig.Score
		}
		action, rule, err := eval.Evaluate(polCtx)
		if err != nil {
			return decision.EvalResult{Action: decision.ActionNone}
		}
		ruleName := ""
		if rule != nil {
			ruleName = rule.Name
		}
		return decision.EvalResult{
			Action:   decision.Action(action),
			RuleName: ruleName,
		}
	}
}

func computeCacheKey(req types.RequestContext, hasValidToken bool) string {
	ua := ""
	path := ""
	if req.Request != nil {
		ua = req.Request.UserAgent()
		if req.Request.URL != nil {
			path = req.Request.URL.Path
		}
	}
	uaDigest := sha256.Sum256([]byte(ua))
	// Path must be part of the cache key because policy rules can match on path
	// (e.g. /healthz allow, /__as/* allow) — without it, the first request from
	// an IP would shadow subsequent requests on different paths.
	raw := fmt.Sprintf("%s\x00%s\x00%x\x00%s\x00%v", req.RemoteIP, req.JA3, uaDigest[:8], path, hasValidToken)
	digest := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", digest)
}

func buildRequestInfo(req types.RequestContext) decision.RequestInfo {
	info := decision.RequestInfo{
		RemoteIP: req.RemoteIP,
		JA3:      req.JA3,
		JA4:      req.JA4,
	}
	if req.Request != nil {
		info.Method = req.Request.Method
		info.Host = req.Request.Host
		info.UserAgent = req.Request.UserAgent()
		if req.Request.URL != nil {
			info.Path = req.Request.URL.Path
		}
	}
	return info
}
