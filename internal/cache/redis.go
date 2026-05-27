package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type redisCache struct {
	client *redis.Client
}

// NewRedis returns a Cache backed by Redis. url must be a valid redis:// URL.
func NewRedis(url string) (Cache, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	c := redis.NewClient(opts)
	return &redisCache{client: c}, nil
}

func (r *redisCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	val, err := r.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}

func (r *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *redisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *redisCache) Close() error {
	return r.client.Close()
}
