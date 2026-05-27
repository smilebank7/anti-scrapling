package types

// BehaviorBeacon is the telemetry payload POSTed by the in-page behavior collector.
type BehaviorBeacon struct {
	SessionID       string            `json:"session_id"`
	Timestamp       int64             `json:"timestamp"`
	Mouse           MouseMetrics      `json:"mouse"`
	Scroll          ScrollMetrics     `json:"scroll"`
	Visibility      VisibilityMetrics `json:"visibility"`
	ResourceFetches ResourceMetrics   `json:"resource_fetches"`
}

// MouseMetrics aggregates pointer movement and click statistics for the session.
type MouseMetrics struct {
	MoveCount        int     `json:"move_count"`
	PathLength       float64 `json:"path_length"` // pixels
	AvgVelocity      float64 `json:"avg_velocity"`
	JitterIndex      float64 `json:"jitter_index"` // std-dev of velocity changes
	Clicks           int     `json:"clicks"`
	ClickIntervalsMs []int   `json:"click_intervals_ms"` // for uniform-distribution test
}

// ScrollMetrics tracks scroll event count and maximum depth.
type ScrollMetrics struct {
	Events int `json:"events"`
	MaxY   int `json:"max_y"`
}

// VisibilityMetrics records how long the page was visible vs hidden.
type VisibilityMetrics struct {
	HiddenMs  int `json:"hidden_ms"`
	VisibleMs int `json:"visible_ms"`
}

// ResourceMetrics counts sub-resource fetches by type, used to verify realistic page load.
type ResourceMetrics struct {
	CSS    int `json:"css"`
	Image  int `json:"image"`
	Font   int `json:"font"`
	Script int `json:"script"`
	XHR    int `json:"xhr"`
}
