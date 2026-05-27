package types

// Signal is one observation about a request that contributes to the risk score.
type Signal struct {
	// Name identifies the signal, e.g. "ja3_mismatch", "header_order_anomaly".
	Name string

	// Score is the weight from policy.scoring.weights.
	Score int

	// Reason is a human-readable explanation, used in audit log.
	Reason string

	// Detail holds optional structured detail for the signal.
	Detail map[string]any
}

// SignalCollector is implemented by each detection module in internal/signal/*.
type SignalCollector interface {
	// Name returns the unique collector identifier, e.g. "tls", "headers".
	Name() string

	// Collect inspects the RequestContext and returns all triggered signals.
	Collect(ctx RequestContext) ([]Signal, error)
}
