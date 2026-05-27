package policy_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func noSignals() map[string]int {
	return map[string]int{
		"ja3_known_scraper":                0,
		"runtime_error_stack_pw_signature": 0,
		"runtime_console_debug_disabled":   0,
		"canvas_seeded_noise":              0,
		"nav_webdriver_set":                0,
	}
}

func loadBothPolicies(t *testing.T) (defaultEval, strictEval *policy.Evaluator) {
	t.Helper()
	root := repoRoot()

	defaultCfg, err := policy.Load(filepath.Join(root, "policies", "default.yaml"))
	require.NoError(t, err, "default.yaml must load without error")

	strictCfg, err := policy.Load(filepath.Join(root, "policies", "strict.yaml"))
	require.NoError(t, err, "strict.yaml must load without error")

	de, err := policy.NewEvaluator(defaultCfg)
	require.NoError(t, err, "default evaluator must compile")

	se, err := policy.NewEvaluator(strictCfg)
	require.NoError(t, err, "strict evaluator must compile")

	return de, se
}

func TestConformance_BothPoliciesLoad(t *testing.T) {
	de, se := loadBothPolicies(t)
	assert.NotNil(t, de)
	assert.NotNil(t, se)
}

func TestConformance_Healthcheck_Default_Allow(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/healthz"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-healthcheck", rule.Name)
}

func TestConformance_Healthcheck_Strict_Allow(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/healthz"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-healthcheck", rule.Name)
}

func TestConformance_Readyz_Default_Allow(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/readyz"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-readyz", rule.Name)
}

func TestConformance_Readyz_Strict_Allow(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/readyz"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-readyz", rule.Name)
}

func TestConformance_ChallengeAssets_Default_Allow(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/__as/challenge.js"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-challenge-assets", rule.Name)
}

func TestConformance_ChallengeAssets_Strict_Allow(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/__as/pow.wasm"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-challenge-assets", rule.Name)
}

func TestConformance_ValidToken_Score30_Default_Allow(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request:       policy.RequestInfo{Method: "GET", Path: "/dashboard"},
		Score:         30,
		HasValidToken: true,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-valid-token", rule.Name)
}

func TestConformance_ValidToken_Score30_Strict_Allow(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request:       policy.RequestInfo{Method: "GET", Path: "/dashboard"},
		Score:         30,
		HasValidToken: true,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-valid-token", rule.Name)
}

func TestConformance_TorIP_Default_Challenge(t *testing.T) {
	de, _ := loadBothPolicies(t)
	sigs := noSignals()
	sigs["tor_exit"] = 1
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/products"},
		IP:      policy.IPInfo{Address: "185.220.101.1", Category: "tor"},
		Score:   50,
		Signals: sigs,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-suspicious", rule.Name)
}

func TestConformance_TorIP_Strict_Deny(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/products"},
		IP:      policy.IPInfo{Address: "185.220.101.1", Category: "tor"},
		Score:   50,
		Signals: map[string]int{"tor_exit": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-datacenter-ip", rule.Name)
}

func TestConformance_DatacenterIP_LowScore_Default_Challenge(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/page"},
		IP:      policy.IPInfo{Address: "34.0.0.1", Category: "datacenter"},
		Score:   5,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	assert.Nil(t, rule)
}

func TestConformance_DatacenterIP_LowScore_Strict_Deny(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/page"},
		IP:      policy.IPInfo{Address: "34.0.0.1", Category: "datacenter"},
		Score:   5,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-datacenter-ip", rule.Name)
}

func TestConformance_KnownScraperSignal_Default_Deny(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/api/data"},
		Score:   100,
		Signals: map[string]int{"ja3_known_scraper": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-known-scraper-libs", rule.Name)
}

func TestConformance_KnownScraperSignal_Strict_Deny(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/api/data"},
		Score:   100,
		Signals: map[string]int{"ja3_known_scraper": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-any-high-weight-signal", rule.Name)
}

func TestConformance_PWSignal_Default_Deny(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/checkout"},
		Score:   70,
		Signals: map[string]int{"runtime_error_stack_pw_signature": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-known-scraper-libs", rule.Name)
}

func TestConformance_PWSignal_Strict_Deny(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/checkout"},
		Score:   70,
		Signals: map[string]int{"runtime_error_stack_pw_signature": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-any-high-weight-signal", rule.Name)
}

func TestConformance_ConsoleDebugDisabled_Default_Challenge(t *testing.T) {
	de, _ := loadBothPolicies(t)
	sigs := noSignals()
	sigs["runtime_console_debug_disabled"] = 1
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/login"},
		Score:   60,
		Signals: sigs,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-suspicious", rule.Name)
}

func TestConformance_ConsoleDebugDisabled_Strict_Deny(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/login"},
		Score:   60,
		Signals: map[string]int{"runtime_console_debug_disabled": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-any-high-weight-signal", rule.Name)
}

func TestConformance_CanvasSeededNoise_Default_Challenge(t *testing.T) {
	de, _ := loadBothPolicies(t)
	sigs := noSignals()
	sigs["canvas_seeded_noise"] = 1
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/shop"},
		Score:   50,
		Signals: sigs,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-suspicious", rule.Name)
}

func TestConformance_CanvasSeededNoise_Strict_Deny(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/shop"},
		Score:   50,
		Signals: map[string]int{"canvas_seeded_noise": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-any-high-weight-signal", rule.Name)
}

func TestConformance_ResidentialClean_Default_Challenge(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/home"},
		IP:      policy.IPInfo{Address: "98.0.0.1", Category: "residential"},
		Score:   0,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	assert.Nil(t, rule)
}

func TestConformance_ResidentialClean_Strict_Allow(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/home"},
		IP:      policy.IPInfo{Address: "98.0.0.1", Category: "residential"},
		Score:   0,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-residential-clean", rule.Name)
}

func TestConformance_Score60_Default_Challenge(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/catalog"},
		Score:   60,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-suspicious", rule.Name)
}

func TestConformance_Score60_Strict_Challenge(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/catalog"},
		IP:      policy.IPInfo{Category: "residential"},
		Score:   60,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-everyone-else", rule.Name)
}

func TestConformance_Score85_Default_Deny(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/api/prices"},
		Score:   85,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-headless-extreme", rule.Name)
}

func TestConformance_Score85_Strict_Challenge(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/api/prices"},
		IP:      policy.IPInfo{Category: "residential"},
		Score:   85,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-everyone-else", rule.Name)
}

func TestConformance_WebdriverSet_Default_Challenge(t *testing.T) {
	de, _ := loadBothPolicies(t)
	sigs := noSignals()
	sigs["nav_webdriver_set"] = 1
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/"},
		Score:   60,
		Signals: sigs,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-suspicious", rule.Name)
}

func TestConformance_WebdriverSet_Strict_Deny(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/"},
		Score:   60,
		Signals: map[string]int{"nav_webdriver_set": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-any-high-weight-signal", rule.Name)
}

func TestConformance_Strict_DefaultDeny_NoSignals(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/unknown"},
		IP:      policy.IPInfo{Address: "34.0.0.1", Category: "datacenter"},
		Score:   0,
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	require.NotNil(t, rule)
	assert.Equal(t, "deny-datacenter-ip", rule.Name)
}

func TestConformance_Strict_DefaultDeny_UnknownCategory_ZeroScore(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/unknown"},
		IP:      policy.IPInfo{Address: "1.2.3.4", Category: "unknown"},
		Score:   0,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionDeny, action)
	assert.Nil(t, rule)
}

func TestConformance_MetricsPath_Default_Allow(t *testing.T) {
	de, _ := loadBothPolicies(t)
	action, rule, err := de.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/metrics"},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionAllow, action)
	require.NotNil(t, rule)
	assert.Equal(t, "allow-metrics-internal", rule.Name)
}

func TestConformance_ResidentialMediumScore_Strict_Challenge(t *testing.T) {
	_, se := loadBothPolicies(t)
	action, rule, err := se.Evaluate(policy.EvaluationContext{
		Request: policy.RequestInfo{Method: "GET", Path: "/products"},
		IP:      policy.IPInfo{Address: "98.0.0.1", Category: "residential"},
		Score:   15,
		Signals: noSignals(),
	})
	require.NoError(t, err)
	assert.Equal(t, policy.ActionChallenge, action)
	require.NotNil(t, rule)
	assert.Equal(t, "challenge-everyone-else", rule.Name)
}
