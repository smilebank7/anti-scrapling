package headers

import "net/http"

// DetectBrowserForgeQuirk identifies known browserforge library signature anomalies.
// Returns (detected bool, reason string).
func DetectBrowserForgeQuirk(h http.Header) (bool, string) {
	site := h.Get("Sec-Fetch-Site")
	if site == "?0" || site == "?1" {
		return true, "browserforge quirk: Sec-Fetch-Site has boolean-style value '" + site + "' (spec requires: none|same-origin|same-site|cross-site)"
	}
	return false, ""
}
