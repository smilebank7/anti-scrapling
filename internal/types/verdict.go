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
	// Verdict is the action to take: ALLOW, CHALLENGE, or DENY.
	Verdict Verdict

	// Score is the aggregate risk score accumulated from all signals.
	Score int

	// Signals lists every signal that contributed to the score.
	Signals []Signal

	// Reasons contains matched policy rule names that influenced the verdict.
	Reasons []string

	// PolicyName is which rule produced the final verdict.
	PolicyName string

	// Timestamp is Unix epoch nanoseconds when the decision was made.
	Timestamp int64

	// RequestID is the correlation ID for this request.
	RequestID string
}
