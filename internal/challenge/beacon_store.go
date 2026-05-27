package challenge

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/signal/behavior"
	"github.com/smilebank7/anti-scrapling/internal/types"
)

const (
	beaconMaxPerKey = 100
	beaconMaxAge    = 5 * time.Minute
)

type beaconEntry struct {
	beacon   types.BehaviorBeacon
	storedAt time.Time
}

// BeaconStore is a sliding-window in-memory store with dual indexes:
// bySession (keyed by BehaviorBeacon.SessionID) for challenge-time scoring,
// and byIP (keyed by RemoteAddr) for pipeline-time scoring.
// Both windows retain at most beaconMaxPerKey entries and entries older than
// beaconMaxAge are pruned on every write.
type BeaconStore struct {
	mu        sync.Mutex
	bySession map[string][]beaconEntry
	byIP      map[string][]beaconEntry
}

func NewBeaconStore() *BeaconStore {
	return &BeaconStore{
		bySession: make(map[string][]beaconEntry),
		byIP:      make(map[string][]beaconEntry),
	}
}

// Ingest implements BeaconIngestor, storing by SessionID only.
func (s *BeaconStore) Ingest(beacon types.BehaviorBeacon) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpired()
	s.push(s.bySession, beacon.SessionID, beacon)
	return nil
}

// IngestFromRequest stores by session_id AND by the request's RemoteIP
// so the pipeline behavior collector can retrieve beacons without a session_id.
func (s *BeaconStore) IngestFromRequest(r *http.Request, beacon types.BehaviorBeacon) error {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpired()
	s.push(s.bySession, beacon.SessionID, beacon)
	s.push(s.byIP, ip, beacon)
	return nil
}

func (s *BeaconStore) GetBySession(sessionID string) *types.BehaviorBeacon {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.bySession[sessionID]
	if len(entries) == 0 {
		return nil
	}
	b := entries[len(entries)-1].beacon
	return &b
}

func (s *BeaconStore) GetByIP(ip string) *types.BehaviorBeacon {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.byIP[ip]
	if len(entries) == 0 {
		return nil
	}
	b := entries[len(entries)-1].beacon
	return &b
}

func (s *BeaconStore) ScoreSession(sessionID string) []types.Signal {
	b := s.GetBySession(sessionID)
	if b == nil {
		return nil
	}
	return behavior.Score(b)
}

func (s *BeaconStore) push(m map[string][]beaconEntry, key string, beacon types.BehaviorBeacon) {
	entries := append(m[key], beaconEntry{beacon: beacon, storedAt: time.Now()})
	if len(entries) > beaconMaxPerKey {
		entries = entries[len(entries)-beaconMaxPerKey:]
	}
	m[key] = entries
}

func (s *BeaconStore) pruneExpired() {
	cutoff := time.Now().Add(-beaconMaxAge)
	pruneBeaconMap(s.bySession, cutoff)
	pruneBeaconMap(s.byIP, cutoff)
}

func pruneBeaconMap(m map[string][]beaconEntry, cutoff time.Time) {
	for key, entries := range m {
		kept := entries[:0]
		for _, e := range entries {
			if e.storedAt.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(m, key)
		} else {
			m[key] = kept
		}
	}
}

// StoreBehaviorCollector implements types.SignalCollector using a BeaconStore.
// It looks up beacons by RemoteIP; returns nil signals when none exist.
type StoreBehaviorCollector struct {
	store *BeaconStore
}

func NewStoreBehaviorCollector(store *BeaconStore) *StoreBehaviorCollector {
	return &StoreBehaviorCollector{store: store}
}

func (c *StoreBehaviorCollector) Name() string { return "behavior" }

func (c *StoreBehaviorCollector) Collect(ctx types.RequestContext) ([]types.Signal, error) {
	b := c.store.GetByIP(ctx.RemoteIP)
	if b == nil {
		return nil, nil
	}
	return behavior.Score(b), nil
}
