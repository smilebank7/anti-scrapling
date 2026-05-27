package behavior

import "github.com/anti-scrapling/anti-scrapling/internal/types"

func checkResourceBlock(b *types.BehaviorBeacon) *types.Signal {
	rf := b.ResourceFetches
	if rf.CSS == 0 && rf.Font == 0 && rf.Image == 0 {
		return &types.Signal{
			Name:   "behavior_resource_block",
			Score:  40,
			Reason: "zero CSS/font/image fetches — Scrapling resource-type blocking (L5.1)",
		}
	}
	return nil
}
