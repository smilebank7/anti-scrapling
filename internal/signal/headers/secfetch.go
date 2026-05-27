package headers

import "net/http"

var validSecFetchSite = map[string]bool{
	"cross-site":  true,
	"same-origin": true,
	"same-site":   true,
	"none":        true,
}

var validSecFetchMode = map[string]bool{
	"cors":        true,
	"navigate":    true,
	"no-cors":     true,
	"same-origin": true,
	"websocket":   true,
}

var validSecFetchDest = map[string]bool{
	"audio":          true,
	"audioworklet":   true,
	"document":       true,
	"embed":          true,
	"empty":          true,
	"font":           true,
	"frame":          true,
	"iframe":         true,
	"image":          true,
	"manifest":       true,
	"object":         true,
	"paintworklet":   true,
	"report":         true,
	"script":         true,
	"serviceworker":  true,
	"sharedworker":   true,
	"style":          true,
	"track":          true,
	"video":          true,
	"worker":         true,
	"xslt":           true,
}

func headerVal(h http.Header, name string) string {
	return h.Get(name)
}

// ValidateSecFetch checks Sec-Fetch-* headers against W3C Fetch spec valid values and
// cross-header consistency rules.  Returns (invalid bool, reason string).
func ValidateSecFetch(h http.Header) (bool, string) {
	site := headerVal(h, "Sec-Fetch-Site")
	mode := headerVal(h, "Sec-Fetch-Mode")
	dest := headerVal(h, "Sec-Fetch-Dest")
	user := headerVal(h, "Sec-Fetch-User")

	if site == "" && mode == "" && dest == "" && user == "" {
		return false, ""
	}

	if site != "" && !validSecFetchSite[site] {
		return true, "Sec-Fetch-Site value '" + site + "' is not a valid W3C Fetch spec value"
	}
	if mode != "" && !validSecFetchMode[mode] {
		return true, "Sec-Fetch-Mode value '" + mode + "' is not a valid W3C Fetch spec value"
	}
	if dest != "" && !validSecFetchDest[dest] {
		return true, "Sec-Fetch-Dest value '" + dest + "' is not a valid W3C Fetch spec value"
	}
	if user != "" && user != "?1" {
		return true, "Sec-Fetch-User value '" + user + "' is not valid (only '?1' is allowed)"
	}

	if site == "none" && h.Get("Referer") != "" {
		return true, "Sec-Fetch-Site is 'none' but Referer header is present (cross-header inconsistency)"
	}

	return false, ""
}
