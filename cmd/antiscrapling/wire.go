package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/cache"
	"github.com/anti-scrapling/anti-scrapling/internal/challenge"
	"github.com/anti-scrapling/anti-scrapling/internal/observability"
	"github.com/anti-scrapling/anti-scrapling/internal/pipeline"
	"github.com/anti-scrapling/anti-scrapling/internal/policy"
	"github.com/anti-scrapling/anti-scrapling/internal/proxy"
	"github.com/anti-scrapling/anti-scrapling/internal/server"
	signalheaders "github.com/anti-scrapling/anti-scrapling/internal/signal/headers"
	signalhttp2 "github.com/anti-scrapling/anti-scrapling/internal/signal/http2"
	signalip "github.com/anti-scrapling/anti-scrapling/internal/signal/ip"
	signaltls "github.com/anti-scrapling/anti-scrapling/internal/signal/tls"
	"github.com/anti-scrapling/anti-scrapling/internal/token"
	"github.com/anti-scrapling/anti-scrapling/internal/types"
	"github.com/google/uuid"
)

type appConfig struct {
	Policy  *types.PolicyConfig
	Bind    string
	Target  string
	KeyFile string
}

type deps struct {
	cfg           *appConfig
	logger        *slog.Logger
	metrics       *observability.Metrics
	health        *observability.Health
	audit         *observability.Audit
	tokenIssuer   *token.Issuer
	tokenVerifier *token.Verifier
	cache         cache.Cache
	evaluator     *policy.Evaluator
	pl            *pipeline.Pipeline
	challengeSvc  *challenge.Service
	rev           *proxy.Proxy
}

func loadConfig(configPath string) (*appConfig, error) {
	pol, err := policy.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	bind := pol.Listener.Bind
	if v := os.Getenv("AS_BIND"); v != "" {
		bind = v
	}
	target := pol.Listener.Target
	if v := os.Getenv("AS_TARGET"); v != "" {
		target = v
	}
	keyFile := pol.Token.SecretFile
	if v := os.Getenv("AS_TOKEN_SECRET_FILE"); v != "" {
		keyFile = v
	}
	if keyFile == "" {
		keyFile = "/tmp/anti-scrapling-token.key"
	}

	return &appConfig{
		Policy:  pol,
		Bind:    bind,
		Target:  target,
		KeyFile: keyFile,
	}, nil
}

func buildDeps(cfg *appConfig) (*deps, error) {
	d := &deps{cfg: cfg}

	d.logger = observability.NewLogger(slog.LevelInfo)
	d.metrics = observability.NewMetrics()
	d.health = observability.NewHealth()
	d.audit = observability.NewAudit(0)

	tokenKey, err := token.LoadKey(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("token key: %w", err)
	}
	ttl := 24 * time.Hour
	if cfg.Policy.Token.TTL != "" {
		if parsed, err := time.ParseDuration(cfg.Policy.Token.TTL); err == nil {
			ttl = parsed
		}
	}
	d.tokenIssuer = token.NewIssuer(tokenKey, ttl, cfg.Policy.Token.BindTo)
	d.tokenVerifier = token.NewVerifier(tokenKey, cfg.Policy.Token.BindTo)

	c, err := cache.New(&cfg.Policy.Cache)
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}
	d.cache = c

	tlsC := signaltls.NewCollector()
	headersC := signalheaders.NewCollector()
	ipC, err := signalip.New(65536)
	if err != nil {
		return nil, fmt.Errorf("ip collector: %w", err)
	}
	h2C := signalhttp2.NewCollector()

	collectors := []types.SignalCollector{tlsC, headersC, ipC, h2C}

	eval, err := policy.NewEvaluator(cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("policy evaluator: %w", err)
	}
	d.evaluator = eval

	cacheTTL := time.Duration(cfg.Policy.Cache.TTLSeconds) * time.Second
	d.pl = pipeline.New(pipeline.PipelineConfig{
		Collectors: collectors,
		Evaluator:  eval,
		Cache:      d.cache,
		CacheTTL:   cacheTTL,
		Policy:     cfg.Policy,
	})

	powDiff := cfg.Policy.Challenge.PowDifficulty
	if powDiff <= 0 {
		powDiff = 4
	}
	denyThreshold := cfg.Policy.Scoring.DenyThreshold
	if denyThreshold <= 0 {
		denyThreshold = 80
	}
	challengeIssuer, err := challenge.NewChallengeIssuer(powDiff)
	if err != nil {
		return nil, fmt.Errorf("challenge issuer: %w", err)
	}
	d.challengeSvc = challenge.NewService(challengeIssuer, d.tokenIssuer, denyThreshold, ttl, &noopBeaconIngestor{})

	if cfg.Target != "" {
		p, err := proxy.New(cfg.Target)
		if err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
		d.rev = p
	}

	return d, nil
}

type noopBeaconIngestor struct{}

func (n *noopBeaconIngestor) Ingest(_ types.BehaviorBeacon) error { return nil }

func buildMainHandler(d *deps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/__as/challenge", d.challengeSvc.HandleChallenge)
	mux.HandleFunc("/__as/verify", d.challengeSvc.HandleVerify)
	mux.HandleFunc("/__as/bundle.js", d.challengeSvc.HandleBundle)
	mux.HandleFunc("/__as/beacon", d.challengeSvc.HandleBeacon)
	mux.HandleFunc("/__as/sw.js", d.challengeSvc.HandleSW)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		start := time.Now()

		capture := server.CaptureFromContext(ctx)
		reqCtx := buildRequestContext(r, capture)

		hasValidToken := false
		if cookieVal := token.GetCookie(r, token.DefaultCookieName); cookieVal != "" {
			if _, err := d.tokenVerifier.Verify(cookieVal, token.VerifyContext{}); err == nil {
				hasValidToken = true
				d.metrics.RecordPassToken("verified")
			} else {
				d.metrics.RecordPassToken("rejected")
			}
		}

		dec := d.pl.Decide(ctx, reqCtx, hasValidToken)
		d.metrics.RecordDecision(dec, time.Since(start))

		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.NewString()
		}
		d.audit.Record(observability.AuditEntry{
			Timestamp: time.Now(),
			RequestID: reqID,
			IP:        reqCtx.RemoteIP,
			URL:       r.URL.String(),
			Verdict:   dec.Verdict,
			Score:     dec.Score,
			Signals:   dec.Signals,
			Reasons:   dec.Reasons,
		})

		switch dec.Verdict {
		case types.VerdictAllow:
			if d.rev != nil {
				d.rev.Forward(w, r, "")
			} else {
				http.Error(w, "no upstream configured", http.StatusBadGateway)
			}
		case types.VerdictChallenge:
			d.metrics.RecordChallenge("issued")
			origin := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, "/__as/challenge?origin="+origin, http.StatusFound)
		default:
			d.logger.Warn("request denied",
				"request_id", reqID,
				"ip", reqCtx.RemoteIP,
				"score", dec.Score,
				"reasons", dec.Reasons,
			)
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	})

	return mux
}

func buildRequestContext(r *http.Request, capture *server.ClientHelloCapture) types.RequestContext {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	var rawHello []byte
	if capture != nil {
		rawHello = capture.Raw
	}

	return types.RequestContext{
		Ctx:         r.Context(),
		Request:     r,
		RemoteIP:    host,
		ClientHello: rawHello,
		Headers:     r.Header,
	}
}

func buildAdminHandler(d *deps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/healthz", d.health.LivezHandler())
	mux.Handle("/readyz", d.health.ReadyzHandler())
	mux.Handle("/admin/audit", d.audit.HTTPHandler())
	return mux
}

func buildServerTLSConfig(tlsCfg *types.TLSConfig) *server.TLSConfig {
	if tlsCfg == nil {
		return nil
	}
	return &server.TLSConfig{
		Cert: tlsCfg.Cert,
		Key:  tlsCfg.Key,
	}
}
