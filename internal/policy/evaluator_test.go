package policy_test

import (
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/policy"
	"github.com/anti-scrapling/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildTestConfig() *types.PolicyConfig {
	return &types.PolicyConfig{
		Version: 1,
		Policy: types.PolicySection{
			Default: "challenge",
			Rules: []types.PolicyRule{
				{
					Name:   "allow-healthcheck",
					Match:  map[string]any{"path": "/healthz"},
					Action: "allow",
				},
				{
					Name:   "deny-known-scrapers",
					Match:  map[string]any{"ja3_in": []any{"@curl_cffi/*", "@python-requests"}},
					Action: "deny",
					Reason: "TLS signature matches known scraper library",
				},
				{
					Name:   "deny-datacenter-high-score",
					Match:  map[string]any{"ip_category": "datacenter", "score": ">=80"},
					Action: "deny",
				},
				{
					Name:   "challenge-suspicious",
					Match:  map[string]any{"score": ">=50"},
					Action: "challenge",
				},
				{
					Name:   "allow-verified",
					Match:  map[string]any{"has_valid_token": true},
					Action: "allow",
				},
			},
		},
	}
}

func TestEvaluator_Healthcheck(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/healthz"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-healthcheck", rule.Name)
}

func TestEvaluator_KnownScraper_CurlCffi(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/api/products"},
		JA3:     "curl_cffi/abc123",
		Score:   10,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-known-scrapers", rule.Name)
}

func TestEvaluator_KnownScraper_PythonRequests(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/api/data"},
		JA3:     "python-requests",
		Score:   5,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-known-scrapers", rule.Name)
}

func TestEvaluator_ScoreBasedChallenge(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/products"},
		IP:      policy.IPInfo{Address: "1.2.3.4", Category: "residential"},
		Score:   55,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-suspicious", rule.Name)
}

func TestEvaluator_LowScoreDefaultFallthrough(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/page"},
		Score:   10,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	assert.Nil(t, rule, "no rule matched; rule must be nil")
}

func TestEvaluator_ValidTokenBypass(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request:       policy.RequestInfo{Method: "GET", Path: "/dashboard"},
		Score:         20,
		HasValidToken: true,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-verified", rule.Name)
}

func TestEvaluator_DatacenterHighScore(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/data"},
		IP:      policy.IPInfo{Address: "10.0.0.1", Category: "datacenter"},
		Score:   85,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-datacenter-high-score", rule.Name)
}

func TestEvaluator_DatacenterLowScore_Challenge(t *testing.T) {
	eval, err := policy.NewEvaluator(buildTestConfig())
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/data"},
		IP:      policy.IPInfo{Address: "10.0.0.1", Category: "datacenter"},
		Score:   55,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-suspicious", rule.Name)
}

func TestEvaluator_RawCELExpression(t *testing.T) {
	cfg := &types.PolicyConfig{
		Version: 1,
		Policy: types.PolicySection{
			Default: "deny",
			Rules: []types.PolicyRule{
				{
					Name:   "complex-allow",
					Match:  map[string]any{"expr": `score < 30 && ip.category != "datacenter"`},
					Action: "allow",
				},
			},
		},
	}
	eval, err := policy.NewEvaluator(cfg)
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		IP:    policy.IPInfo{Category: "residential"},
		Score: 20,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "complex-allow", rule.Name)
}

func TestEvaluator_PathPrefix(t *testing.T) {
	cfg := &types.PolicyConfig{
		Version: 1,
		Policy: types.PolicySection{
			Default: "allow",
			Rules: []types.PolicyRule{
				{
					Name:   "deny-api",
					Match:  map[string]any{"path_prefix": "/api/"},
					Action: "deny",
				},
			},
		},
	}
	eval, err := policy.NewEvaluator(cfg)
	require.NoError(t, err)

	action, rule, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Path: "/api/users"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-api", rule.Name)

	action2, rule2, err := eval.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Path: "/about"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action2)
	assert.Nil(t, rule2)
}
