package types

// DecisionRequest is the body of POST /v1/decide used by SDK adapters.
type DecisionRequest struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Host        string            `json:"host"`
	RemoteIP    string            `json:"remote_ip"`
	Headers     map[string]string `json:"headers"`      // canonical header map
	HeaderOrder []string          `json:"header_order"` // header names in received order
	JA3         string            `json:"ja3,omitempty"`
	JA4         string            `json:"ja4,omitempty"`
	Token       string            `json:"token,omitempty"` // current pass-cookie value, if any
}
