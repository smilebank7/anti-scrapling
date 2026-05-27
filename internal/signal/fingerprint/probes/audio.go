package probes

import "github.com/smilebank7/anti-scrapling/internal/types"

// Audio scores seeded AudioContext noise by checking repeated-render variance.
func Audio(report types.FingerprintReport) []types.Signal {
	if report.Audio.Variance < 2 {
		return nil
	}

	return []types.Signal{newSignal(
		"audio_seeded_noise",
		40,
		"repeated AudioContext renders produced multiple hashes in the same session",
		map[string]any{"variance": report.Audio.Variance, "hashes": report.Audio.Hashes},
	)}
}
