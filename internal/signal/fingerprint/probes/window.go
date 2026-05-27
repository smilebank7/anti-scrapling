package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// Window scores geometry signatures exposed by stealth patches.
func Window(report types.FingerprintReport) []types.Signal {
	delta := report.Window.OuterHeight - report.Window.InnerHeight
	if delta != 85 {
		return nil
	}

	return []types.Signal{newSignal(
		"window_outer_height_85_trap",
		50,
		"window.outerHeight - window.innerHeight is the playwright-stealth constant 85",
		map[string]any{
			"inner_height": report.Window.InnerHeight,
			"outer_height": report.Window.OuterHeight,
			"delta":        delta,
		},
	)}
}
