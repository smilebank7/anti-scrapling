package probes

import "github.com/smilebank7/anti-scrapling/internal/types"

// ServiceWorker scores service worker registration no-ops.
func ServiceWorker(report types.FingerprintReport) []types.Signal {
	sw := report.ServiceWorker
	if !(sw.Registered && !sw.Controller) && !(sw.Error != "" && containsFold(sw.Error, "no-op")) {
		return nil
	}

	return []types.Signal{newSignal(
		"sw_register_noop",
		45,
		"service worker registration did not produce a controller after wait",
		map[string]any{"registered": sw.Registered, "controller": sw.Controller, "error": sw.Error},
	)}
}
