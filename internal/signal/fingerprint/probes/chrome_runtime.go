package probes

import "github.com/smilebank7/anti-scrapling/internal/types"

// ChromeRuntime scores incorrectly mocked chrome.* extension APIs.
func ChromeRuntime(report types.FingerprintReport) []types.Signal {
	chrome := report.Chrome
	signals := make([]types.Signal, 0, 2)

	if isChromeUA(report.Navigator.UserAgent) && chrome.RuntimeConnectError != "" && !isRealChromeRuntimeConnectError(chrome.RuntimeConnectError) {
		signals = append(signals, newSignal(
			"chrome_runtime_connect_failure",
			40,
			"chrome.runtime.connect failed with a mock-specific error",
			map[string]any{"runtime_connect_error": chrome.RuntimeConnectError},
		))
	}

	if isFirefoxUA(report.Navigator.UserAgent) && chrome.Present {
		signals = append(signals, newSignal(
			"chrome_present_for_firefox",
			60,
			"window.chrome is present for a Firefox user agent",
			map[string]any{"chrome_present": chrome.Present, "user_agent": report.Navigator.UserAgent},
		))
	}

	return signals
}

func isRealChromeRuntimeConnectError(value string) bool {
	return containsFold(value, "Could not establish connection") && !containsFold(value, "TypeError")
}
