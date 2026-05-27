package http2

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const zeroHash = "000000000000"

// JA4HShape is the request metadata used to compute a JA4H fingerprint.
type JA4HShape struct {
	Method      string
	ProtoMajor  int
	ProtoMinor  int
	Header      http.Header
	HeaderOrder []string
	Host        string
}

// ComputeJA4H computes the JA4H_abc fingerprint for an http.Request. The
// headerOrder argument should contain the wire-order header names; when it is
// empty, the request header map is sorted to keep the result deterministic.
func ComputeJA4H(req *http.Request, headerOrder []string) string {
	if req == nil {
		return ""
	}

	shape := JA4HShape{
		Method:      req.Method,
		ProtoMajor:  req.ProtoMajor,
		ProtoMinor:  req.ProtoMinor,
		Header:      req.Header,
		HeaderOrder: headerOrder,
		Host:        req.Host,
	}
	return ComputeJA4HFromShape(shape)
}

// ComputeJA4HFromShape computes the JA4H_abc fingerprint from explicit request
// metadata. JA4H_abc includes the application section, the header-name hash, and
// the cookie-name hash; it intentionally omits the user-specific cookie-value
// section to avoid logging per-user material by default.
func ComputeJA4HFromShape(shape JA4HShape) string {
	if shape.Header == nil {
		shape.Header = http.Header{}
	}

	headerOrder := normalizeHeaderOrder(shape)
	filteredHeaders := make([]string, 0, len(headerOrder))
	for _, name := range headerOrder {
		if ignoredJA4HHeader(name) {
			continue
		}
		filteredHeaders = append(filteredHeaders, name)
	}

	cookieNames, _ := sortedCookies(shape.Header)
	cookieFlag := "n"
	if len(cookieNames) > 0 {
		cookieFlag = "c"
	}

	refererFlag := "n"
	if hasHeader(headerOrder, "referer") || shape.Header.Get("Referer") != "" {
		refererFlag = "r"
	}

	headerCount := len(filteredHeaders)
	if headerCount > 99 {
		headerCount = 99
	}

	sectionA := fmt.Sprintf(
		"%s%s%s%s%02d%s",
		methodCode(shape.Method),
		versionCode(shape.ProtoMajor, shape.ProtoMinor),
		cookieFlag,
		refererFlag,
		headerCount,
		languageCode(shape.Header.Get("Accept-Language")),
	)

	cookieHash := zeroHash
	if len(cookieNames) > 0 {
		cookieHash = shortSHA256(cookieNames)
	}

	return sectionA + "_" + shortSHA256(filteredHeaders) + "_" + cookieHash
}

// ComputeJA4HFull computes the full JA4H a_b_c_d fingerprint, including the
// cookie name/value hash as the d section. Prefer ComputeJA4H for low-cardinality
// detection signals and use this only where per-user correlation is intended.
func ComputeJA4HFull(req *http.Request, headerOrder []string) string {
	if req == nil {
		return ""
	}

	shape := JA4HShape{
		Method:      req.Method,
		ProtoMajor:  req.ProtoMajor,
		ProtoMinor:  req.ProtoMinor,
		Header:      req.Header,
		HeaderOrder: headerOrder,
		Host:        req.Host,
	}
	return ComputeJA4HFullFromShape(shape)
}

// ComputeJA4HFullFromShape computes the full JA4H a_b_c_d fingerprint from
// explicit request metadata.
func ComputeJA4HFullFromShape(shape JA4HShape) string {
	abc := ComputeJA4HFromShape(shape)
	if shape.Header == nil {
		shape.Header = http.Header{}
	}
	_, cookiePairs := sortedCookies(shape.Header)
	if len(cookiePairs) == 0 {
		return abc + "_" + zeroHash
	}
	return abc + "_" + shortSHA256(cookiePairs)
}

func normalizeHeaderOrder(shape JA4HShape) []string {
	if len(shape.HeaderOrder) > 0 {
		out := make([]string, 0, len(shape.HeaderOrder))
		for _, name := range shape.HeaderOrder {
			name = strings.TrimSpace(name)
			if name != "" {
				out = append(out, name)
			}
		}
		return out
	}

	headers := make([]string, 0, len(shape.Header)+1)
	if shape.Host != "" {
		headers = append(headers, "Host")
	}
	for name := range shape.Header {
		headers = append(headers, name)
	}
	sort.Strings(headers)
	return headers
}

func ignoredJA4HHeader(name string) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || strings.HasPrefix(trimmed, ":") {
		return true
	}
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, "cookie") || lower == "referer"
}

func hasHeader(headerOrder []string, target string) bool {
	target = strings.ToLower(target)
	for _, name := range headerOrder {
		if strings.ToLower(strings.TrimSpace(name)) == target {
			return true
		}
	}
	return false
}

func methodCode(method string) string {
	method = strings.ToLower(strings.TrimSpace(method))
	if len(method) >= 2 {
		return method[:2]
	}
	if len(method) == 1 {
		return method + "x"
	}
	return "xx"
}

func versionCode(major, minor int) string {
	switch major {
	case 1:
		if minor == 0 {
			return "10"
		}
		return "11"
	case 2:
		return "20"
	case 3:
		return "30"
	default:
		return "00"
	}
}

func languageCode(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, ";", ",")
	if index := strings.IndexByte(value, ','); index >= 0 {
		value = value[:index]
	}
	value = strings.TrimSpace(value)
	if len(value) > 4 {
		value = value[:4]
	}
	for len(value) < 4 {
		value += "0"
	}
	return value
}

func sortedCookies(header http.Header) ([]string, []string) {
	values := header.Values("Cookie")
	if len(values) == 0 {
		return nil, nil
	}

	type cookiePair struct {
		name string
		pair string
	}

	cookies := make([]cookiePair, 0)
	for _, value := range values {
		for _, part := range strings.Split(value, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name := part
			if index := strings.IndexByte(part, '='); index >= 0 {
				name = strings.TrimSpace(part[:index])
			}
			if name == "" {
				continue
			}
			cookies = append(cookies, cookiePair{name: name, pair: part})
		}
	}

	sort.Slice(cookies, func(i, j int) bool {
		if cookies[i].name == cookies[j].name {
			return cookies[i].pair < cookies[j].pair
		}
		return cookies[i].name < cookies[j].name
	})

	names := make([]string, 0, len(cookies))
	pairs := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		names = append(names, cookie.name)
		pairs = append(pairs, cookie.pair)
	}
	return names, pairs
}

func shortSHA256(values []string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, ",")))
	return fmt.Sprintf("%x", sum)[:12]
}
