package uasc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReviseLifetime(t *testing.T) {
	require.Equal(t, uint32(3600000), reviseLifetime(0))
	require.Equal(t, uint32(3600000), reviseLifetime(10*3600000))
	require.Equal(t, uint32(1000), reviseLifetime(10))
	require.Equal(t, uint32(30000), reviseLifetime(30000))
}

func TestTokenExpiresAfterLifetimePlusQuarter(t *testing.T) {
	now := time.Now()
	inst := &channelInstance{createdAt: now, revisedLifetime: 4 * time.Second}
	require.False(t, tokenExpired(inst, now.Add(4*time.Second)))
	require.False(t, tokenExpired(inst, now.Add(5*time.Second)))
	require.True(t, tokenExpired(inst, now.Add(5*time.Second+time.Millisecond)))
}
