package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCache(t *testing.T) {
	c, err := NewCache(128)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestCache_GetOrCompute_AWS(t *testing.T) {
	c, err := NewCache(128)
	require.NoError(t, err)

	entry := c.GetOrCompute(net.ParseIP("54.1.2.3"))
	assert.Equal(t, uint(16509), entry.ASN.ASN)
	assert.Equal(t, CategoryDatacenter, entry.Category)
	assert.False(t, entry.IsTor)
}

func TestCache_GetOrCompute_TorExit(t *testing.T) {
	c, err := NewCache(128)
	require.NoError(t, err)

	entry := c.GetOrCompute(net.ParseIP("185.220.101.19"))
	assert.True(t, entry.IsTor)
}

func TestCache_HitReturnsSameEntry(t *testing.T) {
	c, err := NewCache(128)
	require.NoError(t, err)

	ip := net.ParseIP("35.200.0.1")
	e1 := c.GetOrCompute(ip)
	e2 := c.GetOrCompute(ip)
	assert.Equal(t, e1, e2)
}

func TestNewCache_DefaultSize(t *testing.T) {
	c, err := NewCache(0)
	require.NoError(t, err)
	assert.NotNil(t, c)
}
