package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTorExit_KnownExit(t *testing.T) {
	assert.True(t, IsTorExit(net.ParseIP("185.220.101.19")))
	assert.True(t, IsTorExit(net.ParseIP("185.220.101.20")))
	assert.True(t, IsTorExit(net.ParseIP("45.142.212.100")))
}

func TestIsTorExit_NotExit(t *testing.T) {
	assert.False(t, IsTorExit(net.ParseIP("1.2.3.4")))
	assert.False(t, IsTorExit(net.ParseIP("8.8.8.8")))
}

func TestIsTorExit_Nil(t *testing.T) {
	assert.False(t, IsTorExit(nil))
}

func TestIsTorExit_Private(t *testing.T) {
	assert.False(t, IsTorExit(net.ParseIP("192.168.1.1")))
}

func TestTorExitCount_NonZero(t *testing.T) {
	assert.Greater(t, TorExitCount(), 0)
}
