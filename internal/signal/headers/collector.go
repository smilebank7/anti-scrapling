package headers

import "github.com/smilebank7/anti-scrapling/internal/types"

const (
	SignalHeaderOrderAnomaly   = "header_order_anomaly"
	SignalUACHMismatch         = "ua_ch_mismatch"
	SignalSecFetchInvalid      = "secfetch_invalid"
	SignalBrowserForgeQuirk    = "browserforge_quirk"
	SignalGoogleRefererAnomaly = "google_referer_anomaly"

	scoreHeaderOrderAnomaly   = 20
	scoreUACHMismatch         = 25
	scoreSecFetchInvalid      = 15
	scoreBrowserForgeQuirk    = 40
	scoreGoogleRefererAnomaly = 10
)

// Collector implements types.SignalCollector for HTTP header analysis.
type Collector struct {
	referer *RefererTracker
}

// NewCollector returns a ready-to-use header Collector.
func NewCollector() *Collector {
	return &Collector{
		referer: NewRefererTracker(100, 0.80),
	}
}

// Name implements types.SignalCollector.
func (c *Collector) Name() string { return "headers" }

// Collect implements types.SignalCollector.
func (c *Collector) Collect(ctx types.RequestContext) ([]types.Signal, error) {
	var out []types.Signal

	if anomaly, reason := IsOrderAnomaly(ctx.HeaderOrder); anomaly {
		out = append(out, types.Signal{
			Name:   SignalHeaderOrderAnomaly,
			Score:  scoreHeaderOrderAnomaly,
			Reason: reason,
		})
	}

	if mismatch, reason := CheckUACHConsistency(ctx.Request.Header); mismatch {
		out = append(out, types.Signal{
			Name:   SignalUACHMismatch,
			Score:  scoreUACHMismatch,
			Reason: reason,
		})
	}

	if invalid, reason := ValidateSecFetch(ctx.Request.Header); invalid {
		out = append(out, types.Signal{
			Name:   SignalSecFetchInvalid,
			Score:  scoreSecFetchInvalid,
			Reason: reason,
		})
	}

	if quirk, reason := DetectBrowserForgeQuirk(ctx.Request.Header); quirk {
		out = append(out, types.Signal{
			Name:   SignalBrowserForgeQuirk,
			Score:  scoreBrowserForgeQuirk,
			Reason: reason,
		})
	}

	if c.referer.Observe(ctx.RemoteIP, ctx.Request.Header.Get("Referer")) {
		out = append(out, types.Signal{
			Name:   SignalGoogleRefererAnomaly,
			Score:  scoreGoogleRefererAnomaly,
			Reason: "Google referer ratio exceeds 80% over the last 100 requests from this IP",
		})
	}

	return out, nil
}
