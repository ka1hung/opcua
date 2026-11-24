package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

// A panic in a service handler fails that one request with
// BadInternalError; the server keeps serving the same client (§10.1 T4).
func TestHandlerPanicFailsOnlyThatRequest(t *testing.T) {
	ep := startNoneServerWith(t, func(s *server.Server) {
		s.RegisterHandler(id.RegisterNodesRequest_Encoding_DefaultBinary,
			func(context.Context, *server.Request) (ua.Response, error) {
				panic("boom")
			})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := opcua.NewClient(ep, opcua.SecurityMode(ua.MessageSecurityModeNone))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	err = c.Send(ctx, &ua.RegisterNodesRequest{NodesToRegister: []*ua.NodeID{ua.NewNumericNodeID(0, 1)}}, func(ua.Response) error { return nil })
	require.ErrorIs(t, err, ua.StatusBadInternalError)

	// The server is still alive and serves the next request.
	_, err = c.Node(ua.NewNumericNodeID(0, id.Server_ServerStatus_State)).Value(ctx)
	require.NoError(t, err)
}
