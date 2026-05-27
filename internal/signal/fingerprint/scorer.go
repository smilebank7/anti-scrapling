package fingerprint

import (
	"github.com/anti-scrapling/anti-scrapling/internal/signal/fingerprint/probes"
	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

type probeFamily func(types.FingerprintReport) []types.Signal

var probeFamilies = []probeFamily{
	probes.Navigator,
	probes.WebGL,
	probes.Canvas,
	probes.Audio,
	probes.Codecs,
	probes.Fonts,
	probes.Window,
	probes.ChromeRuntime,
	probes.Permissions,
	probes.WebRTC,
	probes.DOM,
	probes.Runtime,
	probes.Speech,
	probes.ServiceWorker,
	probes.Hairline,
}

// Score turns a browser fingerprint report into risk-bearing signals.
//
// TODO(fingerprint): threat-model probes L3.5, L3.8, L3.9, L4.18, L5.1,
// L5.2, L5.3, and population-level L5.4 need request/session telemetry that is
// not present in types.FingerprintReport. Do not invent fields here; wire those
// probes in when the telemetry schema exists.
func Score(report types.FingerprintReport) ([]types.Signal, error) {
	signals := make([]types.Signal, 0)

	for _, family := range probeFamilies {
		signals = append(signals, family(report)...)
	}

	return signals, nil
}
