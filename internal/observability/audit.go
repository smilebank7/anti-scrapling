package observability

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/types"
)

// AuditEntry is a single recorded decision event stored in the ring buffer.
type AuditEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	RequestID string         `json:"request_id"`
	IP        string         `json:"ip"`
	URL       string         `json:"url"`
	Verdict   types.Verdict  `json:"verdict"`
	Score     int            `json:"score"`
	Signals   []types.Signal `json:"signals"`
	Reasons   []string       `json:"reasons"`
}

// Audit is a thread-safe fixed-size ring buffer of recent AuditEntry records.
type Audit struct {
	mu    sync.RWMutex
	buf   []AuditEntry
	size  int
	head  int
	count int
}

// NewAudit returns an Audit with a ring buffer of the given size (defaults to 10000 when ≤ 0).
func NewAudit(size int) *Audit {
	if size <= 0 {
		size = 10000
	}
	return &Audit{
		buf:  make([]AuditEntry, size),
		size: size,
	}
}

// Record stores entry in the ring buffer, evicting the oldest entry on overflow.
func (a *Audit) Record(entry AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.buf[a.head] = entry
	a.head = (a.head + 1) % a.size
	if a.count < a.size {
		a.count++
	}
}

// Since returns all entries with Timestamp ≥ t in insertion order (oldest first).
func (a *Audit) Since(t time.Time) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.count == 0 {
		return nil
	}

	start := 0
	if a.count == a.size {
		start = a.head
	}

	var out []AuditEntry
	for i := 0; i < a.count; i++ {
		e := a.buf[(start+i)%a.size]
		if !e.Timestamp.Before(t) {
			out = append(out, e)
		}
	}
	return out
}

// HTTPHandler returns a handler that serves audit entries as JSON.
// The optional query param `since` (RFC3339) narrows results; defaults to 24 h ago.
func (a *Audit) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cutoff := time.Now().Add(-24 * time.Hour)
		if s := r.URL.Query().Get("since"); s != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
				cutoff = parsed
			} else if parsed, err := time.Parse(time.RFC3339, s); err == nil {
				cutoff = parsed
			}
		}

		entries := a.Since(cutoff)
		if entries == nil {
			entries = []AuditEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	})
}
