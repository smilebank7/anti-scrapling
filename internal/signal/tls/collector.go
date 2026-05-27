package tls

import (
	"strings"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

const (
	ja3MismatchSignal     = "ja3_mismatch"
	ja3KnownScraperSignal = "ja3_known_scraper"
	ja4UnknownSignal      = "ja4_unknown"

	ja3MismatchScore     = 40
	ja3KnownScraperScore = 100
	ja4UnknownScore      = 30
)

// Collector computes TLS JA3/JA4 fingerprints and emits TLS risk signals.
type Collector struct{}

var _ types.SignalCollector = Collector{}

// NewCollector constructs a TLS signal collector.
func NewCollector() Collector {
	return Collector{}
}

// Name returns the unique collector identifier.
func (Collector) Name() string {
	return "tls"
}

// Collect computes JA3/JA4 from RequestContext and returns triggered TLS signals.
func (Collector) Collect(ctx types.RequestContext) ([]types.Signal, error) {
	ja3String, ja3Hash := normalizeJA3(ctx.JA3)
	ja4String := strings.TrimSpace(ctx.JA4)
	var hello *ClientHello
	signals := make([]types.Signal, 0, 3)

	if len(ctx.ClientHello) > 0 {
		parsedHello, err := ParseClientHello(ctx.ClientHello)
		if err != nil {
			return nil, err
		}
		hello = parsedHello
		computedJA3 := JA3String(hello)
		computedJA3Hash := JA3Hash(computedJA3)

		if ja3String != "" && ja3String != computedJA3 && ja3Hash != computedJA3Hash {
			signals = append(signals, ja3MismatchSignalDetail(
				"raw ClientHello JA3 differs from request context",
				map[string]any{
					"context_ja3":  ctx.JA3,
					"computed_ja3": computedJA3,
					"ja3_hash":     computedJA3Hash,
				},
			))
		}

		ja3String = computedJA3
		ja3Hash = computedJA3Hash
		ja4String = JA4String(hello)
	}

	if info, ok := lookupDenylistedJA3(ja3Hash); ok {
		signals = append(signals, types.Signal{
			Name:   ja3KnownScraperSignal,
			Score:  ja3KnownScraperScore,
			Reason: "JA3 hash matches a known scraper TLS stack",
			Detail: map[string]any{
				"action":  "deny",
				"family":  info.family,
				"library": info.library,
				"ja3":     ja3String,
				"hash":    ja3Hash,
			},
		})
	}

	if ja3MismatchByUserAgent(ctx, ja3Hash) && !hasSignal(signals, ja3MismatchSignal) {
		signals = append(signals, ja3MismatchSignalDetail(
			"JA3 browser family conflicts with User-Agent family",
			map[string]any{
				"ja3":        ja3String,
				"ja3_hash":   ja3Hash,
				"user_agent": requestUserAgent(ctx),
			},
		))
	}

	if ja4String != "" {
		if _, ok := lookupKnownJA4(ja4String); !ok {
			signals = append(signals, types.Signal{
				Name:   ja4UnknownSignal,
				Score:  ja4UnknownScore,
				Reason: "JA4 fingerprint is not in the real-browser allowlist",
				Detail: map[string]any{
					"ja4":      ja4String,
					"ja3_hash": ja3Hash,
				},
			})
		}
	}

	return signals, nil
}

func normalizeJA3(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if strings.Contains(value, ",") {
		return value, JA3Hash(value)
	}
	return "", strings.ToLower(value)
}

func ja3MismatchByUserAgent(ctx types.RequestContext, ja3Hash string) bool {
	if ja3Hash == "" {
		return false
	}
	info, ok := lookupJA3Family(ja3Hash)
	if !ok || !isBrowserFamily(info.family) {
		return false
	}
	uaFamily := userAgentFamily(requestUserAgent(ctx))
	if !isBrowserFamily(uaFamily) {
		return false
	}
	return uaFamily != info.family
}

func ja3MismatchSignalDetail(reason string, detail map[string]any) types.Signal {
	return types.Signal{
		Name:   ja3MismatchSignal,
		Score:  ja3MismatchScore,
		Reason: reason,
		Detail: detail,
	}
}

func hasSignal(signals []types.Signal, name string) bool {
	for _, signal := range signals {
		if signal.Name == name {
			return true
		}
	}
	return false
}

func requestUserAgent(ctx types.RequestContext) string {
	if ctx.Request == nil {
		return ""
	}
	return ctx.Request.UserAgent()
}
