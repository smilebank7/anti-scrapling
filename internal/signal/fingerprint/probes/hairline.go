package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// Hairline scores the non-Modernizr sub-pixel rendering trap.
func Hairline(report types.FingerprintReport) []types.Signal {
	if report.Hairline.NonModernizrResult <= 0 {
		return nil
	}

	return []types.Signal{newSignal(
		"hairline_non_modernizr_anomaly",
		20,
		"non-Modernizr hairline probe returned a positive result",
		map[string]any{"non_modernizr_result": report.Hairline.NonModernizrResult},
	)}
}
