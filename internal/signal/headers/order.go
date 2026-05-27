package headers

import "strings"

var canonicalOrders = map[string][]string{
	// Chrome 130+: Client Hints appear before User-Agent over HTTP/1.1 navigation.
	"chrome": {
		"host",
		"connection",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"accept-encoding",
		"accept-language",
	},
	// Firefox 120+: no Client Hints; User-Agent leads.
	"firefox": {
		"host",
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"connection",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
	},
	// Safari 17+: no Client Hints, no Sec-Fetch-* headers.
	"safari": {
		"host",
		"connection",
		"accept",
		"user-agent",
		"accept-language",
		"accept-encoding",
	},
}

// canonicalMatchThreshold: ≥60% of a canonical list must appear in order to count as a match.
// Chosen to absorb optional headers (e.g. Referer, Cookie) without false positives.
const canonicalMatchThreshold = 0.60

func lowerHeader(name string) string { return strings.ToLower(name) }

func subsequenceScore(observed, canonical []string) int {
	ci := 0
	for _, h := range observed {
		if ci >= len(canonical) {
			break
		}
		if h == canonical[ci] {
			ci++
		}
	}
	return ci
}

// MatchesAnyCanonical returns true when the observed header order is consistent with at
// least one known browser canonical sequence.
func MatchesAnyCanonical(observedOrder []string) bool {
	normalized := make([]string, len(observedOrder))
	for i, h := range observedOrder {
		normalized[i] = lowerHeader(h)
	}
	for _, canonical := range canonicalOrders {
		score := subsequenceScore(normalized, canonical)
		threshold := int(float64(len(canonical)) * canonicalMatchThreshold)
		if score >= threshold {
			return true
		}
	}
	return false
}

// IsOrderAnomaly returns (true, reason) when the observed header order cannot be
// reconciled with any known browser canonical ordering.
func IsOrderAnomaly(observedOrder []string) (bool, string) {
	if MatchesAnyCanonical(observedOrder) {
		return false, ""
	}
	if len(observedOrder) < 8 {
		return true, "fewer than 8 headers and no browser canonical pattern matched"
	}
	return true, "header order does not match any known browser canonical sequence"
}
