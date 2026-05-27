package http2

import (
	"net/http"
	"testing"
)

func TestComputeJA4HCanonicalChromeGET(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = http.Header{
		"Connection":                {"keep-alive"},
		"Sec-Ch-Ua":                 {`"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
		"Sec-Ch-Ua-Mobile":          {"?0"},
		"Sec-Ch-Ua-Platform":        {`"Linux"`},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":            {"none"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-User":            {"?1"},
		"Sec-Fetch-Dest":            {"document"},
		"Accept-Encoding":           {"gzip, deflate, br, zstd"},
		"Accept-Language":           {"en-US,en;q=0.9"},
	}
	headerOrder := []string{
		"Host",
		"Connection",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Accept-Language",
	}

	got := ComputeJA4H(req, headerOrder)
	want := "ge11nn14enus_d9d4fb46dcb1_000000000000"
	if got != want {
		t.Fatalf("JA4H mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestComputeJA4HFullIncludesCookieValues(t *testing.T) {
	shape := JA4HShape{
		Method:     http.MethodPost,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Accept-Language": {"en-US,en;q=0.9"},
			"Cookie":          {"zeta=last; alpha=first"},
			"Referer":         {"https://example.com/"},
		},
		HeaderOrder: []string{"Host", "User-Agent", "Accept-Language", "Cookie", "Referer"},
		Host:        "example.com",
	}

	got := ComputeJA4HFullFromShape(shape)
	want := "po11cr03enus_ea59799162d6_a89f414d94b2_8efa3b39dd3e"
	if got != want {
		t.Fatalf("full JA4H mismatch\n got: %s\nwant: %s", got, want)
	}
}
