package tls

import "strings"

type familyInfo struct {
	family       string
	version      string
	library      string
	impersonates string
	deny         bool
}

var ja3Families = map[string]familyInfo{
	// Real browser allowlist from testdata/clienthello and public JA3 corpora.
	"cd08e31494f9531f560d64c695473da9": {family: "chrome", version: "131"},
	"e1d8b04eeb8ef3954ec4f49267a783ef": {family: "chrome", version: "131"},
	"0b935e9b934ada81b2e407784c3ef1b0": {family: "firefox", version: "134"},
	"1ad946d825cc9b4e935a7ade8fbb03b3": {family: "firefox", version: "133"},
	"9c4409ff1b0096116f2dcc9e696e1588": {family: "safari", version: "18"},

	// Scraper libraries that expose non-browser TLS stacks and can be denied at L1.
	"f8bfd03d8fe2b66ec606d235dacb30fa": {family: "python-requests", library: "python-requests", deny: true},
	"29c3e19f41f8747145368dc82464620c": {family: "python-requests", library: "python-requests", deny: true},
	"b32309a26951912be7dba376398abc3b": {family: "python-requests", library: "python-requests", deny: true},
	"786e7ab5b81d05d3931b4871da61da35": {family: "curl", version: "8", library: "curl", deny: true},
	"975b69aeb34b5d47b9684345ca079dec": {family: "curl", version: "8", library: "curl", deny: true},
}

var curlCFFIImpersonationJA3 = map[string]string{
	// These hashes intentionally match real browsers. They are tracked for audit
	// context but are not deny-listed because TLS alone cannot distinguish them.
	"e1d8b04eeb8ef3954ec4f49267a783ef": "chrome131",
	"1ad946d825cc9b4e935a7ade8fbb03b3": "firefox133",
	"9c4409ff1b0096116f2dcc9e696e1588": "safari18_0",
}

var knownBrowserJA4 = map[string]familyInfo{
	"t13d1516h2_dea800f94266_90347b42e38e": {family: "chrome", version: "131"},
	"t13d1515h2_dea800f94266_b7c7eda127ef": {family: "chrome", version: "131"},
	"t13d1715h2_ca21dff6868a_01a254a6f450": {family: "firefox", version: "134"},
	"t13d1714h2_ca21dff6868a_34e8737d688b": {family: "firefox", version: "133"},
	"t13d1714h2_ca21dff6868a_7d784a25af34": {family: "safari", version: "18"},
}

func lookupJA3Family(hash string) (familyInfo, bool) {
	info, ok := ja3Families[strings.ToLower(hash)]
	if !ok {
		return familyInfo{}, false
	}
	if impersonates, ok := curlCFFIImpersonationJA3[strings.ToLower(hash)]; ok {
		info.impersonates = impersonates
	}
	return info, true
}

func lookupDenylistedJA3(hash string) (familyInfo, bool) {
	info, ok := lookupJA3Family(hash)
	if !ok || !info.deny {
		return familyInfo{}, false
	}
	return info, true
}

func lookupKnownJA4(ja4 string) (familyInfo, bool) {
	info, ok := knownBrowserJA4[ja4]
	return info, ok
}

func userAgentFamily(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "python-requests") || strings.Contains(ua, "urllib3"):
		return "python-requests"
	case strings.Contains(ua, "curl"):
		return "curl"
	case strings.Contains(ua, "firefox/"):
		return "firefox"
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "opr/"):
		return "chrome"
	case strings.Contains(ua, "chrome/") || strings.Contains(ua, "chromium/") || strings.Contains(ua, "crios/"):
		return "chrome"
	case strings.Contains(ua, "safari/"):
		return "safari"
	default:
		return ""
	}
}

func isBrowserFamily(family string) bool {
	switch family {
	case "chrome", "firefox", "safari":
		return true
	default:
		return false
	}
}
