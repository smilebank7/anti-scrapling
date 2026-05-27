package headers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckUACHConsistency_ChromeConsistent(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36`)
	h.Add("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	mismatch, _ := CheckUACHConsistency(h)
	assert.False(t, mismatch)
}

func TestCheckUACHConsistency_ChromeVersionMismatch(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", `Mozilla/5.0 Chrome/130.0.0.0`)
	h.Add("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	mismatch, reason := CheckUACHConsistency(h)
	assert.True(t, mismatch)
	assert.Contains(t, reason, "131")
}

func TestCheckUACHConsistency_FirefoxNoClientHints(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0`)
	mismatch, _ := CheckUACHConsistency(h)
	assert.False(t, mismatch)
}

func TestCheckUACHConsistency_SafariNoClientHints(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15`)
	mismatch, _ := CheckUACHConsistency(h)
	assert.False(t, mismatch)
}

func TestCheckUACHConsistency_ClientHintsOnFirefox(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0`)
	h.Add("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131"`)
	mismatch, reason := CheckUACHConsistency(h)
	assert.True(t, mismatch)
	assert.Contains(t, reason, "Firefox")
}

func TestCheckUACHConsistency_ClientHintsOnSafari(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15`)
	h.Add("Sec-Ch-Ua", `"Google Chrome";v="131"`)
	mismatch, reason := CheckUACHConsistency(h)
	assert.True(t, mismatch)
	assert.Contains(t, reason, "Safari")
}
