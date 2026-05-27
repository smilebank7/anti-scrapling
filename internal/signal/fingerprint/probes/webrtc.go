package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// WebRTC scores missing local ICE candidates from the STUN probe.
func WebRTC(report types.FingerprintReport) []types.Signal {
	if len(report.WebRTC.LocalIPs) > 0 {
		return nil
	}

	return []types.Signal{newSignal(
		"webrtc_no_local_ips",
		15,
		"WebRTC STUN probe did not expose any local IP candidates",
		map[string]any{"public_ip": report.WebRTC.PublicIP},
	)}
}
