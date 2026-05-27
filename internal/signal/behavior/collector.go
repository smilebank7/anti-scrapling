package behavior

import (
	"io"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

type Collector struct{}

func (c *Collector) Name() string { return "behavior" }

func (c *Collector) Collect(ctx types.RequestContext) ([]types.Signal, error) {
	body, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		return nil, err
	}

	beacon, err := Ingest(body)
	if err != nil {
		return nil, err
	}

	return Score(beacon), nil
}

func Score(b *types.BehaviorBeacon) []types.Signal {
	checkers := []func(*types.BehaviorBeacon) *types.Signal{
		checkResourceBlock,
		checkMouseJitter,
		checkClickTiming,
		checkVisibility,
	}

	var signals []types.Signal
	for _, check := range checkers {
		if s := check(b); s != nil {
			signals = append(signals, *s)
		}
	}
	return signals
}
