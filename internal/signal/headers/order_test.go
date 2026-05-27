package headers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsOrderAnomaly_ChromeCanonical(t *testing.T) {
	order := []string{
		"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"Upgrade-Insecure-Requests", "User-Agent", "Accept",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
		"Accept-Encoding", "Accept-Language",
	}
	anomaly, _ := IsOrderAnomaly(order)
	assert.False(t, anomaly)
}

func TestIsOrderAnomaly_FirefoxCanonical(t *testing.T) {
	order := []string{
		"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
		"Connection", "Upgrade-Insecure-Requests",
		"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
	}
	anomaly, _ := IsOrderAnomaly(order)
	assert.False(t, anomaly)
}

func TestIsOrderAnomaly_SafariCanonical(t *testing.T) {
	order := []string{
		"Host", "Connection", "Accept", "User-Agent", "Accept-Language", "Accept-Encoding",
	}
	anomaly, _ := IsOrderAnomaly(order)
	assert.False(t, anomaly)
}

func TestIsOrderAnomaly_ChromeWithExtraReferer(t *testing.T) {
	order := []string{
		"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"Upgrade-Insecure-Requests", "User-Agent", "Accept",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
		"Referer",
		"Accept-Encoding", "Accept-Language",
	}
	anomaly, _ := IsOrderAnomaly(order)
	assert.False(t, anomaly, "extra Referer should not break Chrome pattern match")
}

func TestIsOrderAnomaly_FewHeaders(t *testing.T) {
	order := []string{"Host", "User-Agent", "Accept"}
	anomaly, reason := IsOrderAnomaly(order)
	assert.True(t, anomaly)
	assert.NotEmpty(t, reason)
}

func TestIsOrderAnomaly_PythonRequests(t *testing.T) {
	order := []string{"Host", "User-Agent", "Accept-Encoding", "Accept", "Connection"}
	anomaly, reason := IsOrderAnomaly(order)
	assert.True(t, anomaly)
	assert.NotEmpty(t, reason)
}

func TestIsOrderAnomaly_UnknownOrder(t *testing.T) {
	order := []string{
		"Accept", "User-Agent", "Host", "X-Custom", "Connection",
		"Accept-Encoding", "Accept-Language", "X-Forwarded-For",
	}
	anomaly, _ := IsOrderAnomaly(order)
	assert.True(t, anomaly)
}
