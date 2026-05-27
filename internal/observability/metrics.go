package observability

import (
	"net/http"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the set of Prometheus instrumentation for anti-scrapling.
type Metrics struct {
	reg             *prometheus.Registry
	decisionsTotal  *prometheus.CounterVec
	decisionLatency *prometheus.HistogramVec
	signalsTotal    *prometheus.CounterVec
	challengesTotal *prometheus.CounterVec
	passTokensTotal *prometheus.CounterVec
}

// NewMetrics registers all five metrics on a fresh custom registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	decisionsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "anti_scrapling_decisions_total",
			Help: "Total decisions partitioned by verdict and first matched reason.",
		},
		[]string{"verdict", "reason"},
	)
	decisionLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "anti_scrapling_decision_latency_seconds",
			Help:    "Decision engine latency in seconds, partitioned by verdict.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"verdict"},
	)
	signalsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "anti_scrapling_signals_total",
			Help: "Total signals fired by the detection pipeline, partitioned by signal name.",
		},
		[]string{"name"},
	)
	challengesTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "anti_scrapling_challenges_total",
			Help: "Total challenge events (issued|solved|failed).",
		},
		[]string{"outcome"},
	)
	passTokensTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "anti_scrapling_pass_tokens_total",
			Help: "Total pass-token events (issued|verified|rejected).",
		},
		[]string{"outcome"},
	)

	reg.MustRegister(
		decisionsTotal,
		decisionLatency,
		signalsTotal,
		challengesTotal,
		passTokensTotal,
	)

	return &Metrics{
		reg:             reg,
		decisionsTotal:  decisionsTotal,
		decisionLatency: decisionLatency,
		signalsTotal:    signalsTotal,
		challengesTotal: challengesTotal,
		passTokensTotal: passTokensTotal,
	}
}

// RecordDecision records a completed decision: counter + latency histogram + per-signal counters.
func (m *Metrics) RecordDecision(d types.Decision, latency time.Duration) {
	reason := ""
	if len(d.Reasons) > 0 {
		reason = d.Reasons[0]
	}
	verdict := string(d.Verdict)
	m.decisionsTotal.WithLabelValues(verdict, reason).Inc()
	m.decisionLatency.WithLabelValues(verdict).Observe(latency.Seconds())
	for _, s := range d.Signals {
		m.signalsTotal.WithLabelValues(s.Name).Inc()
	}
}

// RecordChallenge increments challenges_total; outcome ∈ {issued, solved, failed}.
func (m *Metrics) RecordChallenge(outcome string) {
	m.challengesTotal.WithLabelValues(outcome).Inc()
}

// RecordPassToken increments pass_tokens_total; outcome ∈ {issued, verified, rejected}.
func (m *Metrics) RecordPassToken(outcome string) {
	m.passTokensTotal.WithLabelValues(outcome).Inc()
}

// Handler returns the Prometheus scrape handler for the /metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
