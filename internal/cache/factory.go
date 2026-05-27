package cache

import (
	"fmt"

	"github.com/smilebank7/anti-scrapling/internal/types"
)

// New constructs a Cache from cfg. Returns a memory cache when cfg is nil or
// cfg.Backend is empty or "memory". Returns a Redis cache when cfg.Backend is
// "redis". Any other backend value is an error.
func New(cfg *types.CacheConfig) (Cache, error) {
	if cfg == nil || cfg.Backend == "" || cfg.Backend == "memory" {
		return NewMemory(0), nil
	}

	switch cfg.Backend {
	case "redis":
		url, err := redisURL(cfg)
		if err != nil {
			return nil, err
		}
		c, err := NewRedis(url)
		if err != nil {
			return nil, fmt.Errorf("cache: redis init: %w", err)
		}
		return c, nil
	default:
		return nil, fmt.Errorf("cache: unknown backend %q", cfg.Backend)
	}
}

func redisURL(cfg *types.CacheConfig) (string, error) {
	if cfg.Redis == nil {
		return "", fmt.Errorf("cache: redis backend requires redis.addr")
	}
	if cfg.Redis.Addr == "" {
		return "", fmt.Errorf("cache: redis.addr must not be empty")
	}
	db := cfg.Redis.DB
	return fmt.Sprintf("redis://%s/%d", cfg.Redis.Addr, db), nil
}
