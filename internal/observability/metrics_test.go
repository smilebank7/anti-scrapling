package observability_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/observability"
	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetrics_AllFiveNamesInScrape(t *testing.T) {
	m := observability.NewMetrics()

	d := types.Decision{
		Verdict: types.VerdictAllow,
		Score:   10,
		Reasons: []string{"allow-healthcheck"},
		Signals: []types.Signal{{Name: "ja3_mismatch", Score: 10, Reason: "mismatch"}},
	}
	m.RecordDecision(d, 1*time.Millisecond)
	m.RecordChallenge("issued")
	m.RecordPassToken("verified")

	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	require.Equal(t, 200, rr.Code)

	body := rr.Body.String()
	for _, name := range []string{
		"anti_scrapling_decisions_total",
		"anti_scrapling_decision_latency_seconds",
		"anti_scrapling_signals_total",
		"anti_scrapling_challenges_total",
		"anti_scrapling_pass_tokens_total",
	} {
		assert.True(t, strings.Contains(body, name), "missing metric: %s", name)
	}
}

func TestMetrics_RecordDecision_CountsCorrectly(t *testing.T) {
	m := observability.NewMetrics()

	d := types.Decision{
		Verdict: types.VerdictDeny,
		Reasons: []string{"deny-known-scrapers"},
	}
	m.RecordDecision(d, 500*time.Microsecond)
	m.RecordDecision(d, 800*time.Microsecond)

	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	body := rr.Body.String()
	assert.True(t, strings.Contains(body, `verdict="DENY"`), "want DENY label in body")
	assert.True(t, strings.Contains(body, "} 2"), "want counter value 2")
}

func TestMetrics_RecordSignals(t *testing.T) {
	m := observability.NewMetrics()

	d := types.Decision{
		Verdict: types.VerdictChallenge,
		Signals: []types.Signal{
			{Name: "header_order_anomaly"},
			{Name: "ua_ch_mismatch"},
		},
	}
	m.RecordDecision(d, time.Millisecond)

	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	body := rr.Body.String()
	assert.True(t, strings.Contains(body, "header_order_anomaly"), "want signal name in body")
	assert.True(t, strings.Contains(body, "ua_ch_mismatch"), "want signal name in body")
}

func TestMetrics_ChallengeAndPassToken(t *testing.T) {
	m := observability.NewMetrics()

	m.RecordChallenge("issued")
	m.RecordChallenge("solved")
	m.RecordChallenge("failed")
	m.RecordPassToken("issued")
	m.RecordPassToken("verified")
	m.RecordPassToken("rejected")

	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	body := rr.Body.String()
	assert.True(t, strings.Contains(body, `outcome="issued"`), "want outcome=issued label")
	assert.True(t, strings.Contains(body, `outcome="solved"`), "want outcome=solved label")
	assert.True(t, strings.Contains(body, `outcome="rejected"`), "want outcome=rejected label")
}
