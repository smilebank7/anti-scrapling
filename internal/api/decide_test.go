package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/api"
	"github.com/anti-scrapling/anti-scrapling/internal/pipeline"
	"github.com/anti-scrapling/anti-scrapling/internal/policy"
	"github.com/anti-scrapling/anti-scrapling/internal/token"
	"github.com/anti-scrapling/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func minimalPolicy(defaultAction string) *types.PolicyConfig {
	return &types.PolicyConfig{
		Scoring: types.ScoringConfig{
			Weights:            map[string]int{},
			DenyThreshold:      80,
			ChallengeThreshold: 40,
		},
		Policy: types.PolicySection{Default: defaultAction},
	}
}

type mockCollector struct {
	name    string
	signals []types.Signal
}

func (m *mockCollector) Name() string { return m.name }
func (m *mockCollector) Collect(_ types.RequestContext) ([]types.Signal, error) {
	return m.signals, nil
}

func newHandler(t *testing.T, cfg *types.PolicyConfig, collectors []types.SignalCollector) *api.DecideHandler {
	t.Helper()
	eval, err := policy.NewEvaluator(cfg)
	require.NoError(t, err)
	pl := pipeline.New(pipeline.PipelineConfig{
		Collectors: collectors,
		Evaluator:  eval,
		Policy:     cfg,
	})
	return &api.DecideHandler{Pipeline: pl}
}

func TestDecideHandler_ValidRequest(t *testing.T) {
	h := newHandler(t, minimalPolicy("allow"), nil)

	body := `{"method":"GET","path":"/","host":"example.com","remote_ip":"1.2.3.4","headers":{},"header_order":[]}`
	r := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var dec types.Decision
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &dec))
	assert.Equal(t, types.VerdictAllow, dec.Verdict)
	assert.NotEmpty(t, dec.RequestID)
	assert.NotZero(t, dec.Timestamp)
}

func TestDecideHandler_EmptyBody(t *testing.T) {
	h := newHandler(t, minimalPolicy("allow"), nil)

	r := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(""))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideHandler_MethodNotAllowed(t *testing.T) {
	h := newHandler(t, minimalPolicy("allow"), nil)

	r := httptest.NewRequest(http.MethodGet, "/v1/decide", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestDecideHandler_HighSignalDeny(t *testing.T) {
	cfg := &types.PolicyConfig{
		Scoring: types.ScoringConfig{
			Weights:            map[string]int{"scraper_detected": 100},
			DenyThreshold:      80,
			ChallengeThreshold: 40,
		},
		Policy: types.PolicySection{
			Default: "challenge",
			Rules: []types.PolicyRule{
				{Name: "deny-high-score", Match: map[string]any{"expr": "score >= 80"}, Action: "deny"},
			},
		},
	}
	h := &api.DecideHandler{
		Pipeline: func() *pipeline.Pipeline {
			eval, err := policy.NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			return pipeline.New(pipeline.PipelineConfig{
				Collectors: []types.SignalCollector{
					&mockCollector{name: "mock", signals: []types.Signal{
						{Name: "scraper_detected", Score: 100, Reason: "mock high-signal"},
					}},
				},
				Evaluator: eval,
				Policy:    cfg,
			})
		}(),
	}

	body := `{"method":"GET","path":"/","host":"example.com","remote_ip":"10.0.0.1","headers":{},"header_order":[]}`
	r := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var dec types.Decision
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &dec))
	assert.Equal(t, types.VerdictDeny, dec.Verdict)
}

func TestDecideHandler_TokenAllow(t *testing.T) {
	key := []byte("test-secret-key-for-testing-only-32b")
	issuer := token.NewIssuer(key, time.Hour, nil)
	verifier := token.NewVerifier(key, nil)

	tok, err := issuer.Issue(token.IssueContext{Score: 0, IP: "1.2.3.4"})
	require.NoError(t, err)

	cfg := &types.PolicyConfig{
		Scoring: types.ScoringConfig{
			Weights:            map[string]int{},
			DenyThreshold:      80,
			ChallengeThreshold: 40,
		},
		Policy: types.PolicySection{
			Default: "challenge",
			Rules: []types.PolicyRule{
				{Name: "allow-valid-token", Match: map[string]any{"has_valid_token": true}, Action: "allow"},
			},
		},
	}

	eval, err := policy.NewEvaluator(cfg)
	require.NoError(t, err)
	pl := pipeline.New(pipeline.PipelineConfig{Evaluator: eval, Policy: cfg})

	h := &api.DecideHandler{Pipeline: pl, Verifier: verifier}

	body := `{"method":"GET","path":"/","host":"example.com","remote_ip":"1.2.3.4","headers":{},"header_order":[],"token":"` + tok + `"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var dec types.Decision
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &dec))
	assert.Equal(t, types.VerdictAllow, dec.Verdict)
}
