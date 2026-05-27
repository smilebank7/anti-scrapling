// Package behavior implements behavioral telemetry ingest and bot-signal scoring.
package behavior

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/types"
)

type rawBeacon struct {
	SessionID       string       `json:"session_id"`
	PageURL         string       `json:"page_url"`
	PageVisible     bool         `json:"page_visible"`
	VisitDurationMs int          `json:"visit_duration_ms"`
	Scroll          rawScroll    `json:"scroll"`
	Mouse           rawMouse     `json:"mouse"`
	Clicks          []rawClick   `json:"clicks"`
	KeyEvents       int          `json:"key_events"`
	ResourceReqs    rawResources `json:"resource_requests"`
	Attention       rawAttention `json:"attention"`
}

type rawScroll struct {
	Events     int `json:"events"`
	MaxDepthPx int `json:"max_depth_px"`
}

type rawMouse struct {
	MoveEvents   int     `json:"move_events"`
	ClickEvents  int     `json:"click_events"`
	JitterMeanPx float64 `json:"jitter_mean_px"`
}

type rawClick struct {
	X              int    `json:"x"`
	Y              int    `json:"y"`
	TimestampMs    int    `json:"timestamp_ms"`
	TargetTag      string `json:"target_tag"`
	DelaySincePrev int    `json:"delay_since_prev_ms"`
}

type rawResources struct {
	CSS     int `json:"css"`
	Fonts   int `json:"fonts"`
	Images  int `json:"images"`
	Scripts int `json:"scripts"`
	Beacons int `json:"beacons"`
}

type rawAttention struct {
	FocusEvents       int `json:"focus_events"`
	BlurEvents        int `json:"blur_events"`
	VisibilityChanges int `json:"visibility_changes"`
	HiddenDurationMs  int `json:"hidden_duration_ms"`
}

// Ingest parses the wire-format beacon JSON and returns a types.BehaviorBeacon.
// Returns an error if the payload is empty or session_id is absent.
func Ingest(data []byte) (*types.BehaviorBeacon, error) {
	if len(data) == 0 {
		return nil, errors.New("behavior/ingest: empty payload")
	}

	var raw rawBeacon
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	if raw.SessionID == "" {
		return nil, errors.New("behavior/ingest: missing session_id")
	}

	intervals := make([]int, 0, len(raw.Clicks))
	for _, c := range raw.Clicks {
		intervals = append(intervals, c.DelaySincePrev)
	}

	visibleMs := raw.VisitDurationMs - raw.Attention.HiddenDurationMs
	if visibleMs < 0 {
		visibleMs = 0
	}

	return &types.BehaviorBeacon{
		SessionID: raw.SessionID,
		Timestamp: time.Now().UnixMilli(),
		Mouse: types.MouseMetrics{
			MoveCount:        raw.Mouse.MoveEvents,
			JitterIndex:      raw.Mouse.JitterMeanPx,
			Clicks:           raw.Mouse.ClickEvents,
			ClickIntervalsMs: intervals,
		},
		Scroll: types.ScrollMetrics{
			Events: raw.Scroll.Events,
			MaxY:   raw.Scroll.MaxDepthPx,
		},
		Visibility: types.VisibilityMetrics{
			HiddenMs:  raw.Attention.HiddenDurationMs,
			VisibleMs: visibleMs,
		},
		ResourceFetches: types.ResourceMetrics{
			CSS:    raw.ResourceReqs.CSS,
			Image:  raw.ResourceReqs.Images,
			Font:   raw.ResourceReqs.Fonts,
			Script: raw.ResourceReqs.Scripts,
		},
	}, nil
}
