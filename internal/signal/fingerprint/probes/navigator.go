package probes

import (
	"strings"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

// Navigator scores navigator.* inconsistencies and known stealth defaults.
func Navigator(report types.FingerprintReport) []types.Signal {
	nav := report.Navigator
	signals := make([]types.Signal, 0, 6)

	uaOS := osFromUA(nav.UserAgent)
	platformOS := osFromPlatform(nav.Platform)
	if uaOS != "" && platformOS != "" && uaOS != platformOS {
		signals = append(signals, newSignal(
			"nav_platform_ua_mismatch",
			50,
			"navigator.platform does not match the operating system in user_agent",
			map[string]any{
				"user_agent":  nav.UserAgent,
				"platform":    nav.Platform,
				"ua_os":       uaOS,
				"platform_os": platformOS,
			},
		))
	}

	if nav.HardwareConcurrency == 4 {
		signals = append(signals, newSignal(
			"nav_hardware_concurrency_trap",
			30,
			"navigator.hardwareConcurrency is exactly the common stealth default of 4",
			map[string]any{"hardware_concurrency": nav.HardwareConcurrency},
		))
	}

	if nav.Webdriver {
		signals = append(signals, newSignal(
			"nav_webdriver_set",
			60,
			"navigator.webdriver is true",
			map[string]any{"webdriver": nav.Webdriver},
		))
	}

	if isChromeUA(nav.UserAgent) && !hasCanonicalChromePlugins(nav.Plugins) {
		signals = append(signals, newSignal(
			"nav_plugins_anomaly",
			20,
			"Chrome plugin list is missing the canonical PDF viewer plugin names",
			map[string]any{"plugins": nav.Plugins},
		))
	}
	if isFirefoxUA(nav.UserAgent) && len(nav.Plugins) > 0 {
		signals = append(signals, newSignal(
			"nav_plugins_anomaly",
			20,
			"Firefox should expose an empty navigator.plugins list",
			map[string]any{"plugins": nav.Plugins},
		))
	}

	if isChromeUA(nav.UserAgent) && nav.Vendor != "Google Inc." {
		signals = append(signals, newSignal(
			"nav_vendor_ua_mismatch",
			25,
			"Chrome user agent must report navigator.vendor as Google Inc.",
			map[string]any{"user_agent": nav.UserAgent, "vendor": nav.Vendor},
		))
	}
	if isFirefoxUA(nav.UserAgent) && nav.Vendor != "" {
		signals = append(signals, newSignal(
			"nav_vendor_ua_mismatch",
			25,
			"Firefox user agent must report an empty navigator.vendor",
			map[string]any{"user_agent": nav.UserAgent, "vendor": nav.Vendor},
		))
	}

	if !isFirefoxUA(nav.UserAgent) && strings.TrimSpace(nav.Oscpu) != "" {
		signals = append(signals, newSignal(
			"nav_oscpu_firefox_only",
			15,
			"navigator.oscpu is Firefox-only but is present for this user agent",
			map[string]any{"user_agent": nav.UserAgent, "oscpu": nav.Oscpu},
		))
	}

	return signals
}

func newSignal(name string, score int, reason string, detail map[string]any) types.Signal {
	return types.Signal{
		Name:   name,
		Score:  score,
		Reason: reason,
		Detail: detail,
	}
}

func isChromeUA(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "firefox/") || strings.Contains(ua, "fxios/") {
		return false
	}
	if strings.Contains(ua, "edg/") || strings.Contains(ua, "opr/") {
		return false
	}
	return strings.Contains(ua, "chrome/") || strings.Contains(ua, "chromium/") || strings.Contains(ua, "crios/")
}

func isFirefoxUA(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	return strings.Contains(ua, "firefox/") || strings.Contains(ua, "fxios/")
}

func isSafariUA(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	return strings.Contains(ua, "safari/") && strings.Contains(ua, "version/") && !isChromeUA(userAgent) && !isFirefoxUA(userAgent)
}

func osFromUA(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "windows nt"):
		return "windows"
	case strings.Contains(ua, "linux") || strings.Contains(ua, "x11"):
		return "linux"
	case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh"):
		return "mac"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "ios"
	default:
		return ""
	}
}

func osFromPlatform(platform string) string {
	value := strings.ToLower(platform)
	switch {
	case strings.Contains(value, "win"):
		return "windows"
	case strings.Contains(value, "linux") || strings.Contains(value, "x11"):
		return "linux"
	case strings.Contains(value, "mac"):
		return "mac"
	case strings.Contains(value, "iphone") || strings.Contains(value, "ipad"):
		return "ios"
	default:
		return ""
	}
}

func hasCanonicalChromePlugins(plugins []string) bool {
	hasPDFViewer := hasExactString(plugins, "PDF Viewer")
	hasChromePDFViewer := hasExactString(plugins, "Chrome PDF Viewer")
	hasChromiumPDFViewer := hasExactString(plugins, "Chromium PDF Viewer")
	hasNativeClient := hasExactString(plugins, "Native Client")

	return hasPDFViewer &&
		(hasChromePDFViewer || hasChromiumPDFViewer) &&
		(hasNativeClient || (hasChromePDFViewer && hasChromiumPDFViewer))
}

func hasExactString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func containsFold(value string, substr string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(substr))
}

func mediaSupportPresent(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "maybe", "probably":
		return true
	default:
		return false
	}
}
