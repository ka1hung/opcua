package uasc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func chunkOf(n int) *MessageChunk { return &MessageChunk{Data: make([]byte, n)} }

func TestChunkBufferLimitsChunksPerRequest(t *testing.T) {
	b := newChunkBuffer()
	for i := 0; i < 3; i++ {
		require.NoError(t, b.add(1, chunkOf(10), 3, 0))
	}
	require.Error(t, b.add(1, chunkOf(10), 3, 0))
	require.Equal(t, 0, b.len(), "an oversized request is dropped")
	require.Equal(t, 0, b.total)
}

// The size of a request is checked while it is buffered, not only after
// all chunks have arrived and been merged.
func TestChunkBufferLimitsBytesPerRequest(t *testing.T) {
	b := newChunkBuffer()
	require.NoError(t, b.add(1, chunkOf(600), 0, 1000))
	require.Error(t, b.add(1, chunkOf(600), 0, 1000))
	require.Equal(t, 0, b.len())
	require.Equal(t, 0, b.total)
}

// A peer cannot open unboundedly many partial requests (§10.1 T10).
func TestChunkBufferLimitsPendingRequests(t *testing.T) {
	b := newChunkBuffer()
	for id := uint32(0); id < maxPendingRequests; id++ {
		require.NoError(t, b.add(id, chunkOf(1), 0, 0))
	}
	require.Error(t, b.add(maxPendingRequests, chunkOf(1), 0, 0))
	// A request that is already pending may still grow.
	require.NoError(t, b.add(0, chunkOf(1), 0, 0))
}

func TestChunkBufferTakeReturnsInOrderAndFrees(t *testing.T) {
	b := newChunkBuffer()
	c1, c2 := chunkOf(1), chunkOf(2)
	require.NoError(t, b.add(7, c1, 0, 0))
	require.NoError(t, b.add(7, c2, 0, 0))
	require.Equal(t, []*MessageChunk{c1, c2}, b.take(7))
	require.Equal(t, 0, b.len())
	require.Equal(t, 0, b.total)
	require.Nil(t, b.take(7))
}
