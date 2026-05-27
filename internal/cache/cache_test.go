package cache

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemory_SetGet(t *testing.T) {
	c := NewMemory(0)
	defer c.Close()

	ctx := context.Background()
	require.NoError(t, c.Set(ctx, "k", []byte("v"), time.Minute))

	val, ok, err := c.Get(ctx, "k")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []byte("v"), val)
}

func TestMemory_Miss(t *testing.T) {
	c := NewMemory(0)
	defer c.Close()

	_, ok, err := c.Get(context.Background(), "missing")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMemory_Delete(t *testing.T) {
	c := NewMemory(0)
	defer c.Close()

	ctx := context.Background()
	require.NoError(t, c.Set(ctx, "k", []byte("v"), time.Minute))
	require.NoError(t, c.Delete(ctx, "k"))

	_, ok, err := c.Get(ctx, "k")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMemory_DeleteMissing(t *testing.T) {
	c := NewMemory(0)
	defer c.Close()

	assert.NoError(t, c.Delete(context.Background(), "nonexistent"))
}

func TestMemory_Expire(t *testing.T) {
	c := NewMemory(0)
	defer c.Close()

	ctx := context.Background()
	require.NoError(t, c.Set(ctx, "k", []byte("v"), 50*time.Millisecond))

	time.Sleep(120 * time.Millisecond)

	_, ok, err := c.Get(ctx, "k")
	require.NoError(t, err)
	assert.False(t, ok, "entry should have expired")
}

func TestMemory_LRUEviction(t *testing.T) {
	const size = 3
	c := NewMemory(size)
	defer c.Close()

	ctx := context.Background()
	for i := 0; i < size; i++ {
		require.NoError(t, c.Set(ctx, fmt.Sprintf("k%d", i), []byte("v"), time.Minute))
	}

	require.NoError(t, c.Set(ctx, "overflow", []byte("v"), time.Minute))

	_, ok, err := c.Get(ctx, "k0")
	require.NoError(t, err)
	assert.False(t, ok, "k0 should have been evicted as LRU entry")
}

func TestRedis_SkipIfNoURL(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}

	c, err := NewRedis(url)
	if err != nil {
		t.Skipf("redis connection failed: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	if pingErr := c.(*redisCache).client.Ping(ctx).Err(); pingErr != nil {
		t.Skipf("redis unreachable: %v", pingErr)
	}

	require.NoError(t, c.Set(ctx, "rk", []byte("rv"), time.Minute))

	val, ok, err := c.Get(ctx, "rk")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []byte("rv"), val)

	require.NoError(t, c.Delete(ctx, "rk"))

	_, ok, err = c.Get(ctx, "rk")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRedis_ExpireSkipIfNoURL(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}

	c, err := NewRedis(url)
	if err != nil {
		t.Skipf("redis connection failed: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	if pingErr := c.(*redisCache).client.Ping(ctx).Err(); pingErr != nil {
		t.Skipf("redis unreachable: %v", pingErr)
	}

	require.NoError(t, c.Set(ctx, "expkey", []byte("val"), 100*time.Millisecond))
	time.Sleep(200 * time.Millisecond)

	_, ok, err := c.Get(ctx, "expkey")
	require.NoError(t, err)
	assert.False(t, ok, "entry should have expired in redis")
}
