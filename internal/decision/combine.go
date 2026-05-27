package decision

import (
	"time"

	"github.com/smilebank7/anti-scrapling/internal/types"
)

const (
	defaultDenyThreshold      = 80
	defaultChallengeThreshold = 50
)

type Action string

const (
	ActionAllow     Action = "allow"
	ActionChallenge Action = "challenge"
	ActionDeny      Action = "deny"
	ActionNone      Action = ""
)

type EvalResult struct {
	Action   Action
	RuleName string
}

type EvalCtx struct {
	Score         int
	Signals       map[string]types.Signal
	RequestInfo   RequestInfo
	HasValidToken bool
}

type RequestInfo struct {
	Method     string
	Path       string
	Host       string
	UserAgent  string
	RemoteIP   string
	JA3        string
	JA4        string
	IPCategory string
}

func Combine(
	signals []types.Signal,
	policy *types.PolicyConfig,
	requestInfo RequestInfo,
	hasValidToken bool,
	evalFn func(EvalCtx) EvalResult,
) types.Decision {
	weighted := make([]types.Signal, len(signals))
	copy(weighted, signals)

	if policy != nil && len(policy.Scoring.Weights) > 0 {
		for i, sig := range weighted {
			if w, ok := policy.Scoring.Weights[sig.Name]; ok {
				weighted[i].Score = w
			}
		}
	}

	total := 0
	for _, sig := range weighted {
		total += sig.Score
	}
	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	denyThreshold := defaultDenyThreshold
	challengeThreshold := defaultChallengeThreshold
	if policy != nil {
		if policy.Scoring.DenyThreshold > 0 {
			denyThreshold = policy.Scoring.DenyThreshold
		}
		if policy.Scoring.ChallengeThreshold > 0 {
			challengeThreshold = policy.Scoring.ChallengeThreshold
		}
	}

	if hasValidToken && total < denyThreshold {
		return types.Decision{
			Verdict:    types.VerdictAllow,
			Score:      total,
			Signals:    weighted,
			Reasons:    []string{"token_bypass"},
			PolicyName: "token_bypass",
			Timestamp:  time.Now().UnixNano(),
		}
	}

	if evalFn != nil {
		sigMap := make(map[string]types.Signal, len(weighted))
		for _, s := range weighted {
			sigMap[s.Name] = s
		}
		ctx := EvalCtx{
			Score:         total,
			Signals:       sigMap,
			RequestInfo:   requestInfo,
			HasValidToken: hasValidToken,
		}
		if result := evalFn(ctx); result.Action != ActionNone {
			return evalDecision(result.Action, result.RuleName, total, weighted)
		}
	}

	switch {
	case total >= denyThreshold:
		return types.Decision{
			Verdict:    types.VerdictDeny,
			Score:      total,
			Signals:    weighted,
			PolicyName: "threshold_deny",
			Timestamp:  time.Now().UnixNano(),
		}
	case total >= challengeThreshold:
		return types.Decision{
			Verdict:    types.VerdictChallenge,
			Score:      total,
			Signals:    weighted,
			PolicyName: "threshold_challenge",
			Timestamp:  time.Now().UnixNano(),
		}
	default:
		return types.Decision{
			Verdict:    types.VerdictAllow,
			Score:      total,
			Signals:    weighted,
			PolicyName: "threshold_allow",
			Timestamp:  time.Now().UnixNano(),
		}
	}
}

func evalDecision(action Action, ruleName string, score int, signals []types.Signal) types.Decision {
	var verdict types.Verdict
	switch action {
	case ActionAllow:
		verdict = types.VerdictAllow
	case ActionDeny:
		verdict = types.VerdictDeny
	default:
		verdict = types.VerdictChallenge
	}
	return types.Decision{
		Verdict:    verdict,
		Score:      score,
		Signals:    signals,
		Reasons:    []string{ruleName},
		PolicyName: ruleName,
		Timestamp:  time.Now().UnixNano(),
	}
}
