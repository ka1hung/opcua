package uasc

import (
	"github.com/ka1hung/opcua/errors"
)

// maxPendingRequests bounds how many requests may have intermediate chunks
// buffered at once on one channel. Requests are normally sent whole or one
// at a time; the bound only stops a peer from opening many partial
// requests to exhaust memory (§10.1 T10).
const maxPendingRequests = 64

// chunkBuffer holds the intermediate ('C') chunks of requests that are not
// complete yet, bounded per request by chunk count and size, and across
// requests by count and total size. It is not safe for concurrent use; the
// SecureChannel guards it with chunksMu.
type chunkBuffer struct {
	m     map[uint32][]*MessageChunk
	size  map[uint32]int
	total int
}

func newChunkBuffer() *chunkBuffer {
	return &chunkBuffer{
		m:    make(map[uint32][]*MessageChunk),
		size: make(map[uint32]int),
	}
}

// add buffers an intermediate chunk of reqID. It rejects the chunk, and
// drops everything buffered for reqID, when that would exceed
// maxChunkCount chunks or maxMessageSize bytes for the request, or
// maxPendingRequests requests or maxPendingRequests*maxMessageSize bytes
// in total. A limit of 0 means no limit for that value.
func (b *chunkBuffer) add(reqID uint32, c *MessageChunk, maxChunkCount, maxMessageSize uint32) error {
	_, pending := b.m[reqID]
	if !pending && len(b.m) >= maxPendingRequests {
		return errors.Errorf("too many partial requests: %d", len(b.m))
	}

	n := len(c.Data)
	if count := len(b.m[reqID]) + 1; maxChunkCount > 0 && uint32(count) > maxChunkCount {
		b.drop(reqID)
		return errors.Errorf("too many chunks: %d > %d", count, maxChunkCount)
	}
	if maxMessageSize > 0 {
		if size := b.size[reqID] + n; size > int(maxMessageSize) {
			b.drop(reqID)
			return errors.Errorf("message too large: %d > %d", size, maxMessageSize)
		}
		if limit := maxPendingRequests * int(maxMessageSize); b.total+n > limit {
			b.drop(reqID)
			return errors.Errorf("too much buffered: %d > %d bytes", b.total+n, limit)
		}
	}

	b.m[reqID] = append(b.m[reqID], c)
	b.size[reqID] += n
	b.total += n
	return nil
}

// take removes and returns the chunks buffered for reqID.
func (b *chunkBuffer) take(reqID uint32) []*MessageChunk {
	all := b.m[reqID]
	b.drop(reqID)
	return all
}

// drop discards the chunks buffered for reqID.
func (b *chunkBuffer) drop(reqID uint32) {
	b.total -= b.size[reqID]
	delete(b.m, reqID)
	delete(b.size, reqID)
}

// len reports how many requests have chunks buffered.
func (b *chunkBuffer) len() int { return len(b.m) }
