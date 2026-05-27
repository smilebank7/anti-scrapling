package types

// Signal is one observation about a request that contributes to the risk score.
type Signal struct {
	Name   string         `json:"name"`
	Score  int            `json:"score"`
	Reason string         `json:"reason"`
	Detail map[string]any `json:"detail,omitempty"`
}

// SignalCollector is implemented by each detection module in internal/signal/*.
type SignalCollector interface {
	// Name returns the unique collector identifier, e.g. "tls", "headers".
	Name() string

	// Collect inspects the RequestContext and returns all triggered signals.
	Collect(ctx RequestContext) ([]Signal, error)
}
