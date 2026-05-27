package headers

import (
	"net/url"
	"strings"
	"sync"
)

type ipWindow struct {
	mu         sync.Mutex
	buf        []bool
	pos        int
	filled     bool
	windowSize int
	threshold  float64
}

func newIPWindow(windowSize int, threshold float64) *ipWindow {
	return &ipWindow{
		buf:        make([]bool, windowSize),
		windowSize: windowSize,
		threshold:  threshold,
	}
}

func (w *ipWindow) observe(isGoogle bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf[w.pos] = isGoogle
	w.pos++
	if w.pos >= w.windowSize {
		w.pos = 0
		w.filled = true
	}

	n := w.windowSize
	if !w.filled {
		n = w.pos
	}

	if n < 5 {
		return false
	}

	count := 0
	for i := 0; i < n; i++ {
		if w.buf[i] {
			count++
		}
	}
	return float64(count)/float64(n) > w.threshold
}

// RefererTracker tracks the per-IP Google-referer ratio using a sliding ring buffer.
type RefererTracker struct {
	mu         sync.RWMutex
	windows    map[string]*ipWindow
	windowSize int
	threshold  float64
}

// NewRefererTracker creates a tracker with the given sliding window size and alert threshold.
func NewRefererTracker(windowSize int, threshold float64) *RefererTracker {
	return &RefererTracker{
		windows:    make(map[string]*ipWindow),
		windowSize: windowSize,
		threshold:  threshold,
	}
}

// Observe records a request from ip with the given Referer value.
// Returns true when the Google-referer fraction exceeds the threshold.
func (t *RefererTracker) Observe(ip, referer string) bool {
	t.mu.RLock()
	w, ok := t.windows[ip]
	t.mu.RUnlock()

	if !ok {
		t.mu.Lock()
		w, ok = t.windows[ip]
		if !ok {
			w = newIPWindow(t.windowSize, t.threshold)
			t.windows[ip] = w
		}
		t.mu.Unlock()
	}

	return w.observe(isGoogleReferer(referer))
}

func isGoogleReferer(referer string) bool {
	if referer == "" {
		return false
	}
	u, err := url.Parse(referer)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Host)
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	// Padding with dots ensures "google" is matched as a whole domain label,
	// not as a suffix of another word (e.g. "notgoogle.com" → ".notgoogle.com." has no ".google.").
	return strings.Contains("."+host+".", ".google.")
}
