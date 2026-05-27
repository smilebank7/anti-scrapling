package policy

import (
	"fmt"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

type Action string

const (
	ActionAllow     Action = "allow"
	ActionChallenge Action = "challenge"
	ActionDeny      Action = "deny"
)

type RequestInfo struct {
	Method    string
	Path      string
	Host      string
	UserAgent string
}

type IPInfo struct {
	Address  string
	Category string
	ASN      string
}

type EvaluationContext struct {
	Request       RequestInfo
	IP            IPInfo
	JA3           string
	JA4           string
	Score         int
	HasValidToken bool
	Signals       map[string]int
}

type Evaluator struct {
	config *types.PolicyConfig
	rules  []*CompiledRule
}

// NewEvaluator compiles all rules from cfg and returns a ready Evaluator.
func NewEvaluator(cfg *types.PolicyConfig) (*Evaluator, error) {
	rules := make([]*CompiledRule, 0, len(cfg.Policy.Rules))
	for i := range cfg.Policy.Rules {
		cr, err := compileRule(&cfg.Policy.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("policy: compile rules[%d] %q: %w", i, cfg.Policy.Rules[i].Name, err)
		}
		rules = append(rules, cr)
	}
	return &Evaluator{config: cfg, rules: rules}, nil
}

// Evaluate iterates rules in order and returns the first matching rule's action.
// Falls back to policy.default when no rule matches; rule is nil in that case.
func (e *Evaluator) Evaluate(ctx EvaluationContext) (Action, *types.PolicyRule, error) {
	activation := buildActivation(ctx)
	for _, cr := range e.rules {
		out, _, err := cr.Program.Eval(activation)
		if err != nil {
			return "", nil, fmt.Errorf("policy: eval rule %q: %w", cr.Rule.Name, err)
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return "", nil, fmt.Errorf("policy: rule %q returned non-bool: %T", cr.Rule.Name, out.Value())
		}
		if matched {
			return Action(cr.Rule.Action), cr.Rule, nil
		}
	}
	return Action(e.config.Policy.Default), nil, nil
}

func buildActivation(ctx EvaluationContext) map[string]any {
	signals := make(map[string]any, len(ctx.Signals))
	for k, v := range ctx.Signals {
		signals[k] = int64(v)
	}
	return map[string]any{
		"request": map[string]any{
			"method":     ctx.Request.Method,
			"path":       ctx.Request.Path,
			"host":       ctx.Request.Host,
			"user_agent": ctx.Request.UserAgent,
		},
		"ip": map[string]any{
			"address":  ctx.IP.Address,
			"category": ctx.IP.Category,
			"asn":      ctx.IP.ASN,
		},
		"ja3":             ctx.JA3,
		"ja4":             ctx.JA4,
		"score":           int64(ctx.Score),
		"has_valid_token": ctx.HasValidToken,
		"signals":         signals,
	}
}
