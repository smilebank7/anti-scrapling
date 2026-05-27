package headers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectBrowserForgeQuirk_BooleanSiteValue(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "?1")
	h.Add("Sec-Fetch-Mode", "navigate")
	quirk, reason := DetectBrowserForgeQuirk(h)
	assert.True(t, quirk)
	assert.Contains(t, reason, "browserforge")
	assert.Contains(t, reason, "?1")
}

func TestDetectBrowserForgeQuirk_BooleanFalseValue(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "?0")
	quirk, reason := DetectBrowserForgeQuirk(h)
	assert.True(t, quirk)
	assert.Contains(t, reason, "?0")
}

func TestDetectBrowserForgeQuirk_ValidSiteNone(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "none")
	h.Add("Sec-Fetch-Mode", "navigate")
	quirk, _ := DetectBrowserForgeQuirk(h)
	assert.False(t, quirk)
}

func TestDetectBrowserForgeQuirk_ValidSiteSameOrigin(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "same-origin")
	quirk, _ := DetectBrowserForgeQuirk(h)
	assert.False(t, quirk)
}

func TestDetectBrowserForgeQuirk_NoSecFetch(t *testing.T) {
	h := make(http.Header)
	h.Add("User-Agent", "curl/8.6.0")
	quirk, _ := DetectBrowserForgeQuirk(h)
	assert.False(t, quirk)
}
