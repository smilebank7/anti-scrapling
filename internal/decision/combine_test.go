package decision_test

import (
	"testing"

	"github.com/smilebank7/anti-scrapling/internal/decision"
	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noEval(_ decision.EvalCtx) decision.EvalResult { return decision.EvalResult{} }

func sig(score int) []types.Signal {
	if score == 0 {
		return nil
	}
	return []types.Signal{{Name: "test_signal", Score: score}}
}

func policy50_80() *types.PolicyConfig {
	return &types.PolicyConfig{
		Scoring: types.ScoringConfig{
			ChallengeThreshold: 50,
			DenyThreshold:      80,
		},
	}
}

func TestCombine_ZeroScore_Allow(t *testing.T) {
	d := decision.Combine(nil, policy50_80(), decision.RequestInfo{}, false, noEval)
	assert.Equal(t, types.VerdictAllow, d.Verdict)
	assert.Equal(t, 0, d.Score)
	assert.NotZero(t, d.Timestamp)
}

func TestCombine_Score60_Challenge(t *testing.T) {
	d := decision.Combine(sig(60), policy50_80(), decision.RequestInfo{}, false, noEval)
	assert.Equal(t, types.VerdictChallenge, d.Verdict)
	assert.Equal(t, 60, d.Score)
}

func TestCombine_Score85_Deny(t *testing.T) {
	d := decision.Combine(sig(85), policy50_80(), decision.RequestInfo{}, false, noEval)
	assert.Equal(t, types.VerdictDeny, d.Verdict)
	assert.Equal(t, 85, d.Score)
}

func TestCombine_ValidToken_Score60_Allow(t *testing.T) {
	d := decision.Combine(sig(60), policy50_80(), decision.RequestInfo{}, true, noEval)
	assert.Equal(t, types.VerdictAllow, d.Verdict)
	assert.Equal(t, "token_bypass", d.PolicyName)
	require.Len(t, d.Reasons, 1)
	assert.Equal(t, "token_bypass", d.Reasons[0])
}

func TestCombine_ValidToken_Score85_Deny(t *testing.T) {
	d := decision.Combine(sig(85), policy50_80(), decision.RequestInfo{}, true, noEval)
	assert.Equal(t, types.VerdictDeny, d.Verdict)
}

func TestCombine_EvalFn_ExplicitAllow_OverridesHighScore(t *testing.T) {
	evalFn := func(_ decision.EvalCtx) decision.EvalResult {
		return decision.EvalResult{Action: decision.ActionAllow, RuleName: "allow-healthcheck"}
	}
	d := decision.Combine(sig(85), policy50_80(), decision.RequestInfo{}, false, evalFn)
	assert.Equal(t, types.VerdictAllow, d.Verdict)
	assert.Equal(t, "allow-healthcheck", d.PolicyName)
	require.Len(t, d.Reasons, 1)
	assert.Equal(t, "allow-healthcheck", d.Reasons[0])
}

func TestCombine_EvalFn_ExplicitDeny_OverridesLowScore(t *testing.T) {
	evalFn := func(_ decision.EvalCtx) decision.EvalResult {
		return decision.EvalResult{Action: decision.ActionDeny, RuleName: "deny-known-scraper"}
	}
	d := decision.Combine(sig(5), policy50_80(), decision.RequestInfo{}, false, evalFn)
	assert.Equal(t, types.VerdictDeny, d.Verdict)
	assert.Equal(t, "deny-known-scraper", d.PolicyName)
}

func TestCombine_EmptySignals_Allow(t *testing.T) {
	d := decision.Combine([]types.Signal{}, policy50_80(), decision.RequestInfo{}, false, noEval)
	assert.Equal(t, types.VerdictAllow, d.Verdict)
	assert.Equal(t, 0, d.Score)
}

func TestCombine_WeightOverride_RaisesScore(t *testing.T) {
	p := &types.PolicyConfig{
		Scoring: types.ScoringConfig{
			Weights:            map[string]int{"ja3_mismatch": 60},
			ChallengeThreshold: 50,
			DenyThreshold:      80,
		},
	}
	signals := []types.Signal{{Name: "ja3_mismatch", Score: 5}}
	d := decision.Combine(signals, p, decision.RequestInfo{}, false, noEval)
	assert.Equal(t, types.VerdictChallenge, d.Verdict)
	assert.Equal(t, 60, d.Score)
	assert.Equal(t, 60, d.Signals[0].Score)
}

func TestCombine_ScoreClamped_To100(t *testing.T) {
	signals := []types.Signal{
		{Name: "a", Score: 60},
		{Name: "b", Score: 60},
	}
	d := decision.Combine(signals, policy50_80(), decision.RequestInfo{}, false, noEval)
	assert.Equal(t, 100, d.Score)
	assert.Equal(t, types.VerdictDeny, d.Verdict)
}

func TestCombine_NilPolicy_UsesDefaults(t *testing.T) {
	assert.Equal(t, types.VerdictAllow, decision.Combine(sig(10), nil, decision.RequestInfo{}, false, noEval).Verdict)
	assert.Equal(t, types.VerdictChallenge, decision.Combine(sig(60), nil, decision.RequestInfo{}, false, noEval).Verdict)
	assert.Equal(t, types.VerdictDeny, decision.Combine(sig(85), nil, decision.RequestInfo{}, false, noEval).Verdict)
}

func TestCombine_EvalFn_ReceivesCorrectCtx(t *testing.T) {
	var captured decision.EvalCtx
	evalFn := func(ctx decision.EvalCtx) decision.EvalResult {
		captured = ctx
		return decision.EvalResult{}
	}
	ri := decision.RequestInfo{Method: "GET", Path: "/api", JA3: "abc", IPCategory: "datacenter"}
	signals := []types.Signal{{Name: "datacenter_ip", Score: 55}}
	decision.Combine(signals, policy50_80(), ri, false, evalFn)

	assert.Equal(t, 55, captured.Score)
	assert.False(t, captured.HasValidToken)
	assert.Equal(t, "GET", captured.RequestInfo.Method)
	assert.Equal(t, "/api", captured.RequestInfo.Path)
	assert.Equal(t, "abc", captured.RequestInfo.JA3)
	assert.Equal(t, "datacenter", captured.RequestInfo.IPCategory)
	assert.Equal(t, 55, captured.Signals["datacenter_ip"].Score)
}

func TestCombine_EvalFn_Challenge_Action(t *testing.T) {
	evalFn := func(_ decision.EvalCtx) decision.EvalResult {
		return decision.EvalResult{Action: decision.ActionChallenge, RuleName: "challenge-suspicious"}
	}
	d := decision.Combine(sig(10), policy50_80(), decision.RequestInfo{}, false, evalFn)
	assert.Equal(t, types.VerdictChallenge, d.Verdict)
	assert.Equal(t, "challenge-suspicious", d.PolicyName)
}

func TestCombine_SignalsPreservedInDecision(t *testing.T) {
	signals := []types.Signal{
		{Name: "a", Score: 20, Reason: "reason-a"},
		{Name: "b", Score: 25, Reason: "reason-b"},
	}
	d := decision.Combine(signals, policy50_80(), decision.RequestInfo{}, false, noEval)
	require.Len(t, d.Signals, 2)
	assert.Equal(t, "a", d.Signals[0].Name)
	assert.Equal(t, "b", d.Signals[1].Name)
}

func TestCombine_ScoreExactlyAtDenyThreshold_Deny(t *testing.T) {
	d := decision.Combine(sig(80), policy50_80(), decision.RequestInfo{}, false, noEval)
	assert.Equal(t, types.VerdictDeny, d.Verdict)
}

func TestCombine_ScoreExactlyAtChallengeThreshold_Challenge(t *testing.T) {
	d := decision.Combine(sig(50), policy50_80(), decision.RequestInfo{}, false, noEval)
	assert.Equal(t, types.VerdictChallenge, d.Verdict)
}

func TestCombine_ValidToken_ScoreAtDenyThreshold_Deny(t *testing.T) {
	d := decision.Combine(sig(80), policy50_80(), decision.RequestInfo{}, true, noEval)
	assert.Equal(t, types.VerdictDeny, d.Verdict)
}

func TestCombine_NilEvalFn_ThresholdFallback(t *testing.T) {
	d := decision.Combine(sig(60), policy50_80(), decision.RequestInfo{}, false, nil)
	assert.Equal(t, types.VerdictChallenge, d.Verdict)
	assert.Equal(t, "threshold_challenge", d.PolicyName)
}
