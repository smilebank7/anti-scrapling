package headers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSecFetch_ValidNavigation(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "none")
	h.Add("Sec-Fetch-Mode", "navigate")
	h.Add("Sec-Fetch-User", "?1")
	h.Add("Sec-Fetch-Dest", "document")
	invalid, _ := ValidateSecFetch(h)
	assert.False(t, invalid)
}

func TestValidateSecFetch_NoHeaders(t *testing.T) {
	h := make(http.Header)
	invalid, _ := ValidateSecFetch(h)
	assert.False(t, invalid)
}

func TestValidateSecFetch_InvalidSiteValue(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "unknown-value")
	h.Add("Sec-Fetch-Mode", "navigate")
	invalid, reason := ValidateSecFetch(h)
	assert.True(t, invalid)
	assert.Contains(t, reason, "unknown-value")
}

func TestValidateSecFetch_InvalidModeValue(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "none")
	h.Add("Sec-Fetch-Mode", "invalid-mode")
	invalid, reason := ValidateSecFetch(h)
	assert.True(t, invalid)
	assert.Contains(t, reason, "invalid-mode")
}

func TestValidateSecFetch_InvalidDestValue(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "none")
	h.Add("Sec-Fetch-Mode", "navigate")
	h.Add("Sec-Fetch-Dest", "not-a-dest")
	invalid, reason := ValidateSecFetch(h)
	assert.True(t, invalid)
	assert.Contains(t, reason, "not-a-dest")
}

func TestValidateSecFetch_InvalidUserValue(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "none")
	h.Add("Sec-Fetch-User", "?0")
	invalid, reason := ValidateSecFetch(h)
	assert.True(t, invalid)
	assert.Contains(t, reason, "?0")
}

func TestValidateSecFetch_NoneWithReferer(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "none")
	h.Add("Sec-Fetch-Mode", "navigate")
	h.Add("Referer", "https://www.google.com/")
	invalid, reason := ValidateSecFetch(h)
	assert.True(t, invalid)
	assert.Contains(t, reason, "Referer")
}

func TestValidateSecFetch_SameSiteWithReferer(t *testing.T) {
	h := make(http.Header)
	h.Add("Sec-Fetch-Site", "same-site")
	h.Add("Sec-Fetch-Mode", "navigate")
	h.Add("Referer", "https://sub.example.com/")
	invalid, _ := ValidateSecFetch(h)
	assert.False(t, invalid, "same-site with Referer is legitimate")
}
