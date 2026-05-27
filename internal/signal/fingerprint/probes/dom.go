package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// DOM scores structural probes that expose automation framework patches.
func DOM(report types.FingerprintReport) []types.Signal {
	dom := report.DOM
	signals := make([]types.Signal, 0, 2)

	if dom.IframeContentWindowIdentity {
		signals = append(signals, newSignal(
			"dom_iframe_contentwindow_anomaly",
			40,
			"iframe.contentWindow identity probe matched a stealth patch signature",
			map[string]any{"iframe_content_window_identity": dom.IframeContentWindowIdentity},
		))
	}

	if dom.ClosedShadowRootAccessible {
		signals = append(signals, newSignal(
			"dom_closed_shadow_root_accessible",
			50,
			"closed shadow root was accessible from page JavaScript",
			map[string]any{"closed_shadow_root_accessible": dom.ClosedShadowRootAccessible},
		))
	}

	return signals
}
