package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// browseTypes browses the references of BaseDataType, a response of
// several tens of kilobytes.
func browseTypes(t *testing.T, c *opcua.Client) (*ua.BrowseResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodes := make([]*ua.BrowseDescription, 0, 100)
	for i := 0; i < 100; i++ {
		nodes = append(nodes, &ua.BrowseDescription{
			NodeID: ua.NewNumericNodeID(0, id.BaseDataType), BrowseDirection: ua.BrowseDirectionBoth,
			IncludeSubtypes: true, ResultMask: 0x3f,
		})
	}
	return c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: nodes})
}

// A client with the smallest buffers the standard allows gets large
// responses in chunks it can take (§10.1 T8, §10.4 matrix A).
func TestSmallBufferClientGetsChunkedResponse(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := opcua.NewClient(f.ep, opcua.AutoReconnect(false),
		opcua.ReceiveBufferSize(8192), opcua.SendBufferSize(8192))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	defer c.Close(context.Background())

	resp, err := browseTypes(t, c)
	require.NoError(t, err)
	require.Len(t, resp.Results, 100)
	require.GreaterOrEqual(t, len(resp.Results[0].References), 15)
}

// A response larger than the client's MaxMessageSize is answered with
// Bad_ResponseTooLarge instead of a message the client cannot take.
func TestResponseOverClientLimitIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := opcua.NewClient(f.ep, opcua.AutoReconnect(false), opcua.MaxMessageSize(16384))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	defer c.Close(context.Background())

	_, err = browseTypes(t, c)
	require.ErrorIs(t, err, ua.StatusBadResponseTooLarge)

	// The channel is still usable.
	require.Equal(t, ua.StatusOK, read(t, c, f.id("Temp")).Status)
}
