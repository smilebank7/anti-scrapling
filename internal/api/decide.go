// Package api provides HTTP handlers for the SDK-facing admin API.
package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/pipeline"
	"github.com/anti-scrapling/anti-scrapling/internal/token"
	"github.com/anti-scrapling/anti-scrapling/internal/types"
	"github.com/google/uuid"
)

// DecideHandler is the POST /v1/decide handler for SDK adapters.
// Body: types.DecisionRequest JSON. Response: types.Decision JSON.
type DecideHandler struct {
	Pipeline *pipeline.Pipeline
	Verifier *token.Verifier
}

func (h *DecideHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Body == nil {
		http.Error(w, "bad request: empty body", http.StatusBadRequest)
		return
	}

	var req types.DecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.RemoteIP == "" {
		http.Error(w, "bad request: remote_ip required", http.StatusBadRequest)
		return
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	rawPath := req.Path
	if rawPath == "" {
		rawPath = "/"
	}

	// Build a synthetic http.Request so collectors that inspect the request
	// object (method, path, host, headers) function without a live connection.
	syntheticReq, err := http.NewRequestWithContext(r.Context(), method, (&url.URL{Path: rawPath}).String(), http.NoBody)
	if err != nil {
		http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	syntheticReq.Host = req.Host
	for k, v := range req.Headers {
		syntheticReq.Header.Set(k, v)
	}

	reqCtx := types.RequestContext{
		Ctx:     r.Context(),
		Request: syntheticReq,
		// ClientHello is intentionally nil: SDK calls arrive over plain HTTP,
		// not a real TLS handshake. JA3/JA4 are forwarded via DecisionRequest.
		RemoteIP:    req.RemoteIP,
		JA3:         req.JA3,
		JA4:         req.JA4,
		Headers:     syntheticReq.Header,
		HeaderOrder: req.HeaderOrder,
	}

	hasValidToken := false
	if req.Token != "" && h.Verifier != nil {
		vc := token.VerifyContext{
			IP:  req.RemoteIP,
			JA3: req.JA3,
			JA4: req.JA4,
			UA:  req.Headers["User-Agent"],
		}
		if _, verifyErr := h.Verifier.Verify(req.Token, vc); verifyErr == nil {
			hasValidToken = true
		}
	}

	dec := h.Pipeline.Decide(r.Context(), reqCtx, hasValidToken)
	if dec.RequestID == "" {
		dec.RequestID = uuid.NewString()
	}
	if dec.Timestamp == 0 {
		dec.Timestamp = time.Now().UnixNano()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dec)
}
