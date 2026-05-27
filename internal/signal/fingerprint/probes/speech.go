package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// Speech scores missing speech synthesis voices on browsers with default voices.
func Speech(report types.FingerprintReport) []types.Signal {
	if !browserBundlesVoices(report.Navigator.UserAgent) {
		return nil
	}
	if report.Speech.VoicesCount != 0 || len(report.Speech.Voices) != 0 {
		return nil
	}

	return []types.Signal{newSignal(
		"speech_voices_empty",
		15,
		"speechSynthesis voice list is empty for a browser/OS that bundles default voices",
		map[string]any{"voices_count": report.Speech.VoicesCount},
	)}
}

func browserBundlesVoices(userAgent string) bool {
	return isChromeUA(userAgent) || isFirefoxUA(userAgent) || isSafariUA(userAgent)
}
