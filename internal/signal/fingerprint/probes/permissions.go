package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// Permissions scores inconsistent Permissions API spoofing.
func Permissions(report types.FingerprintReport) []types.Signal {
	permissions := report.Permissions
	if permissions.NotificationsState != "granted" {
		return nil
	}

	if permissions.MidiState != "denied" && permissions.MidiState != "prompt" {
		return nil
	}

	return []types.Signal{newSignal(
		"permissions_midi_inconsistent",
		35,
		"notifications permission is granted while midi remains denied or prompt",
		map[string]any{
			"notifications_state": permissions.NotificationsState,
			"midi_state":          permissions.MidiState,
		},
	)}
}
