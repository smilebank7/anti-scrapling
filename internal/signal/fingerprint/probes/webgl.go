package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// WebGL scores impossible GPU identities and fake extension surfaces.
func WebGL(report types.FingerprintReport) []types.Signal {
	webgl := report.WebGL
	signals := make([]types.Signal, 0, 3)

	if containsFold(webgl.UnmaskedVendor, "Intel") && containsFold(webgl.UnmaskedRenderer, "Apple GPU") {
		signals = append(signals, newSignal(
			"webgl_vendor_renderer_impossible",
			40,
			"WebGL unmasked vendor and renderer describe an impossible GPU combination",
			map[string]any{
				"unmasked_vendor":   webgl.UnmaskedVendor,
				"unmasked_renderer": webgl.UnmaskedRenderer,
			},
		))
	}

	if webgl.UnmaskedVendor == "" || webgl.UnmaskedRenderer == "" {
		signals = append(signals, newSignal(
			"webgl_unmasked_missing",
			20,
			"WEBGL_debug_renderer_info did not expose unmasked vendor and renderer",
			map[string]any{
				"unmasked_vendor":   webgl.UnmaskedVendor,
				"unmasked_renderer": webgl.UnmaskedRenderer,
			},
		))
	}

	if webGLExtensionsAnomalous(webgl.Extensions) {
		signals = append(signals, newSignal(
			"webgl_extensions_anomaly",
			15,
			"WebGL extension surface is too small or matches a fake extension set",
			map[string]any{"extensions": webgl.Extensions, "extension_count": len(webgl.Extensions)},
		))
	}

	return signals
}

func webGLExtensionsAnomalous(extensions []string) bool {
	if len(extensions) < 10 {
		return true
	}

	return len(extensions) <= 12 &&
		hasExactString(extensions, "WEBGL_debug_renderer_info") &&
		!hasExactString(extensions, "OES_texture_float")
}
