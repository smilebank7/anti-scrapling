package behavior

import "github.com/smilebank7/anti-scrapling/internal/types"

const (
	turnstileMin = 100
	turnstileMax = 200
)

func checkClickTiming(b *types.BehaviorBeacon) *types.Signal {
	intervals := b.Mouse.ClickIntervalsMs
	if len(intervals) == 0 {
		return nil
	}

	for _, iv := range intervals {
		if iv < turnstileMin || iv > turnstileMax {
			return nil
		}
	}

	return &types.Signal{
		Name:   "behavior_turnstile_clicker",
		Score:  60,
		Reason: "all click intervals within Scrapling randint(100,200) band — Turnstile auto-solver (L5.3)",
		Detail: map[string]any{
			"intervals": intervals,
		},
	}
}
