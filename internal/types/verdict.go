package types

// Verdict is the outcome of the decision engine for a single request.
type Verdict string

// Verdict constants for the three possible outcomes of the decision engine.
const (
	VerdictAllow     Verdict = "ALLOW"
	VerdictChallenge Verdict = "CHALLENGE"
	VerdictDeny      Verdict = "DENY"
)

// Decision is the full output of the scoring and policy engine for one request.
type Decision struct {
	Verdict    Verdict  `json:"verdict"`
	Score      int      `json:"score"`
	Signals    []Signal `json:"signals"`
	Reasons    []string `json:"reasons"`
	PolicyName string   `json:"policy_name"`
	Timestamp  int64    `json:"timestamp"`
	RequestID  string   `json:"request_id"`
}
