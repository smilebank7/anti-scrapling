package behavior

import "github.com/anti-scrapling/anti-scrapling/internal/types"

const (
	jitterThreshold  = 0.05
	minMoveCountBot  = 10
)

func checkMouseJitter(b *types.BehaviorBeacon) *types.Signal {
	if b.Mouse.JitterIndex < jitterThreshold && b.Mouse.MoveCount > minMoveCountBot {
		return &types.Signal{
			Name:   "behavior_smooth_path",
			Score:  30,
			Reason: "mouse jitter index below human floor with significant move count — synthetic Bezier path",
			Detail: map[string]any{
				"jitter_index": b.Mouse.JitterIndex,
				"move_count":   b.Mouse.MoveCount,
			},
		}
	}
	return nil
}
