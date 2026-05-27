package ip

import (
	"context"
	"net/http"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCollector(t *testing.T) *Collector {
	t.Helper()
	c, err := New(256)
	require.NoError(t, err)
	return c
}

func makeCtx(remoteIP string) types.RequestContext {
	return types.RequestContext{
		Ctx:      context.Background(),
		Request:  &http.Request{},
		RemoteIP: remoteIP,
	}
}

func signalByName(signals []types.Signal, name string) (types.Signal, bool) {
	for _, s := range signals {
		if s.Name == name {
			return s, true
		}
	}
	return types.Signal{}, false
}

func TestCollector_Name(t *testing.T) {
	assert.Equal(t, "ip", newTestCollector(t).Name())
}

func TestCollector_DatacenterIP_AWS(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx("54.1.2.3"))
	require.NoError(t, err)
	s, ok := signalByName(signals, "datacenter_ip")
	require.True(t, ok, "expected datacenter_ip signal")
	assert.Equal(t, 30, s.Score)
}

func TestCollector_DatacenterIP_GCP(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx("35.200.0.1"))
	require.NoError(t, err)
	_, ok := signalByName(signals, "datacenter_ip")
	assert.True(t, ok)
}

func TestCollector_DatacenterIP_Hetzner(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx("88.99.1.1"))
	require.NoError(t, err)
	_, ok := signalByName(signals, "datacenter_ip")
	assert.True(t, ok)
}

func TestCollector_TorExit(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx("185.220.101.19"))
	require.NoError(t, err)

	s, ok := signalByName(signals, "tor_exit")
	require.True(t, ok, "expected tor_exit signal")
	assert.Equal(t, 50, s.Score)
}

func TestCollector_PrivateIP_NoSignals(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx("192.168.1.1"))
	require.NoError(t, err)
	assert.Empty(t, signals)
}

func TestCollector_Loopback_NoSignals(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx("127.0.0.1"))
	require.NoError(t, err)
	assert.Empty(t, signals)
}

func TestCollector_EmptyAddr_NoSignals(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx(""))
	require.NoError(t, err)
	assert.Empty(t, signals)
}

func TestCollector_AddrWithPort(t *testing.T) {
	signals, err := newTestCollector(t).Collect(makeCtx("54.1.2.3:12345"))
	require.NoError(t, err)
	_, ok := signalByName(signals, "datacenter_ip")
	assert.True(t, ok)
}

func TestCollector_ImplementsSignalCollector(t *testing.T) {
	var _ types.SignalCollector = newTestCollector(t)
}
