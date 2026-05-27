package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// Canvas scores seeded canvas noise by checking repeated-render variance.
func Canvas(report types.FingerprintReport) []types.Signal {
	if report.Canvas.Variance < 2 {
		return nil
	}

	return []types.Signal{newSignal(
		"canvas_seeded_noise",
		50,
		"repeated canvas renders produced multiple hashes in the same session",
		map[string]any{"variance": report.Canvas.Variance, "hashes": report.Canvas.Hashes},
	)}
}
