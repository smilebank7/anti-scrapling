package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupASN_AWS(t *testing.T) {
	ip := net.ParseIP("54.1.2.3")
	require.NotNil(t, ip)
	result, err := LookupASN(ip)
	require.NoError(t, err)
	assert.Equal(t, uint(16509), result.ASN)
	assert.Contains(t, result.Org, "Amazon")
}

func TestLookupASN_GCP(t *testing.T) {
	ip := net.ParseIP("35.200.0.1")
	require.NotNil(t, ip)
	result, err := LookupASN(ip)
	require.NoError(t, err)
	assert.Equal(t, uint(15169), result.ASN)
	assert.Contains(t, result.Org, "Google")
}

func TestLookupASN_Azure(t *testing.T) {
	ip := net.ParseIP("20.40.0.1")
	require.NotNil(t, ip)
	result, err := LookupASN(ip)
	require.NoError(t, err)
	assert.Equal(t, uint(8075), result.ASN)
	assert.Contains(t, result.Org, "Microsoft")
}

func TestLookupASN_Hetzner(t *testing.T) {
	ip := net.ParseIP("88.99.1.1")
	require.NotNil(t, ip)
	result, err := LookupASN(ip)
	require.NoError(t, err)
	assert.Equal(t, uint(24940), result.ASN)
	assert.Contains(t, result.Org, "Hetzner")
}

func TestLookupASN_Unknown(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	require.NotNil(t, ip)
	result, err := LookupASN(ip)
	require.NoError(t, err)
	assert.Equal(t, uint(0), result.ASN)
}

func TestLookupASN_NilIP(t *testing.T) {
	_, err := LookupASN(nil)
	assert.Error(t, err)
}
