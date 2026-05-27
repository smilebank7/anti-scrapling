package cache

import (
	"context"
	"time"
)

// Cache is the pluggable cache interface used throughout anti-scrapling.
type Cache interface {
	// Get retrieves a value by key. Returns (value, true, nil) on hit,
	// (nil, false, nil) on miss, and (nil, false, err) on error.
	Get(ctx context.Context, key string) ([]byte, bool, error)

	// Set stores a value with the given TTL. A zero TTL means no expiry.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a key. It is not an error if the key does not exist.
	Delete(ctx context.Context, key string) error

	// Close releases any resources held by the cache.
	Close() error
}
