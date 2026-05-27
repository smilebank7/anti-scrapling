package behavior

import "github.com/smilebank7/anti-scrapling/internal/types"

func checkVisibility(b *types.BehaviorBeacon) *types.Signal {
	hidden := b.Visibility.HiddenMs
	visible := b.Visibility.VisibleMs
	if hidden == 0 {
		return nil
	}
	if hidden > visible*5 {
		return &types.Signal{
			Name:   "behavior_hidden_dominant",
			Score:  20,
			Reason: "hidden time dominates visible time — headless or non-interactive session",
			Detail: map[string]any{
				"hidden_ms":  hidden,
				"visible_ms": visible,
			},
		}
	}
	return nil
}
