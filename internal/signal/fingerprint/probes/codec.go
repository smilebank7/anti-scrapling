package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// Codecs scores missing rare codec support for modern Chrome and Safari reports.
func Codecs(report types.FingerprintReport) []types.Signal {
	if !isChromeUA(report.Navigator.UserAgent) && !isSafariUA(report.Navigator.UserAgent) {
		return nil
	}

	hevc := report.Codecs.Rare["hevc"]
	av1 := report.Codecs.Rare["av1_p1"]
	if mediaSupportPresent(hevc) && mediaSupportPresent(av1) {
		return nil
	}

	return []types.Signal{newSignal(
		"codec_rare_missing",
		20,
		"modern Chrome/Safari user agent is missing HEVC or AV1 rare codec support",
		map[string]any{"hevc": hevc, "av1_p1": av1},
	)}
}
