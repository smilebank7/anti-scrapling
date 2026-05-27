package headers

import (
	"net/http"
	"regexp"
	"strings"
)

var (
	chromeVersionRE = regexp.MustCompile(`Chrome/(\d+)`)
	brandVersionRE  = regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
)

var chromeBrands = map[string]bool{
	"Google Chrome":  true,
	"Chromium":       true,
	"Microsoft Edge": true,
}

func parseSECCHUA(value string) map[string]string {
	brands := make(map[string]string)
	for _, m := range brandVersionRE.FindAllStringSubmatch(value, -1) {
		brands[m[1]] = m[2]
	}
	return brands
}

func extractChromeVersion(ua string) string {
	m := chromeVersionRE.FindStringSubmatch(ua)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// CheckUACHConsistency verifies sec-ch-ua is consistent with the User-Agent header.
// Returns (mismatch bool, reason string).
func CheckUACHConsistency(h http.Header) (bool, string) {
	ua := h.Get("User-Agent")
	secCHUA := h.Get("Sec-Ch-Ua")

	isChrome := chromeVersionRE.MatchString(ua)
	uaLower := strings.ToLower(ua)

	if secCHUA != "" && !isChrome {
		if strings.Contains(uaLower, "firefox") || strings.Contains(uaLower, "safari") {
			return true, "sec-ch-ua present but User-Agent is Firefox or Safari (these browsers do not send Client Hints)"
		}
	}

	if secCHUA != "" && isChrome {
		brands := parseSECCHUA(secCHUA)
		chromeVer := extractChromeVersion(ua)
		if chromeVer != "" {
			for brand, ver := range brands {
				if chromeBrands[brand] && ver != "" && ver != chromeVer {
					return true, "sec-ch-ua Chrome brand version (" + ver + ") does not match User-Agent Chrome/" + chromeVer
				}
			}
		}
	}

	return false, ""
}
