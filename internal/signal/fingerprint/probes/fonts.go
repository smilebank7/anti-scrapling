package probes

import "github.com/smilebank7/anti-scrapling/internal/types"

// Fonts scores missing OS-bundled fonts for the claimed platform.
func Fonts(report types.FingerprintReport) []types.Signal {
	if len(report.Fonts.MissingOSBundled) == 0 {
		return nil
	}

	return []types.Signal{newSignal(
		"font_os_bundled_missing",
		25,
		"claimed platform is missing OS-bundled fonts",
		map[string]any{"missing_os_bundled": report.Fonts.MissingOSBundled},
	)}
}
