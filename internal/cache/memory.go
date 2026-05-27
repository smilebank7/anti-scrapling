package cache

import (
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultMemorySize = 10_000

type entry struct {
	value     []byte
	expiresAt time.Time
}

type memoryCache struct {
	lru *lru.Cache[string, entry]
}

// NewMemory returns an in-memory LRU cache with per-entry TTL support.
// size <= 0 uses defaultMemorySize.
func NewMemory(size int) Cache {
	if size <= 0 {
		size = defaultMemorySize
	}
	c, _ := lru.New[string, entry](size)
	return &memoryCache{lru: c}
}

func (m *memoryCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	e, ok := m.lru.Get(key)
	if !ok {
		return nil, false, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		m.lru.Remove(key)
		return nil, false, nil
	}
	return e.value, true, nil
}

func (m *memoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.lru.Add(key, entry{value: value, expiresAt: exp})
	return nil
}

func (m *memoryCache) Delete(_ context.Context, key string) error {
	m.lru.Remove(key)
	return nil
}

func (m *memoryCache) Close() error {
	m.lru.Purge()
	return nil
}
