package server_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

// startNoneServer starts a server with SecurityPolicy None on a free
// loopback port and returns its endpoint URL.
func startNoneServer(t *testing.T, opts ...server.Option) string {
	t.Helper()
	return startNoneServerWith(t, nil, opts...)
}

// startNoneServerWith is startNoneServer with a hook that runs on the
// server before Start, e.g. to register a handler.
func startNoneServerWith(t *testing.T, setup func(*server.Server), opts ...server.Option) string {
	t.Helper()
	port := freePort(t)

	opts = append([]server.Option{
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EndPoint("127.0.0.1", port),
	}, opts...)
	srv := server.New(opts...)
	if setup != nil {
		setup(srv)
	}
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return endpointURL(port)
}

// freePort returns a TCP port on 127.0.0.1 that was free a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func endpointURL(port int) string { return fmt.Sprintf("opc.tcp://127.0.0.1:%d", port) }

// connectNone connects a None/Anonymous client within the given time.
func connectNone(t *testing.T, endpoint string, within time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	c, err := opcua.NewClient(endpoint, opcua.SecurityMode(ua.MessageSecurityModeNone))
	if err != nil {
		return err
	}
	if err := c.Connect(ctx); err != nil {
		return err
	}
	return c.Close(context.Background())
}

func tcpAddr(endpoint string) string { return endpoint[len("opc.tcp://"):] }

// A connection that never sends Hello must not stop other clients from
// connecting (§10.1 T5).
func TestIdleConnectionDoesNotBlockOthers(t *testing.T) {
	ep := startNoneServer(t)

	idle, err := net.Dial("tcp", tcpAddr(ep))
	require.NoError(t, err)
	t.Cleanup(func() { idle.Close() })
	time.Sleep(50 * time.Millisecond) // let the server accept it

	require.NoError(t, connectNone(t, ep, 3*time.Second))
}

// A client that resets its connection before Hello must not stop the
// server from accepting new connections (§10.1 T5).
func TestResetBeforeHelloKeepsAccepting(t *testing.T) {
	ep := startNoneServer(t)

	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", tcpAddr(ep))
		require.NoError(t, err)
		require.NoError(t, c.(*net.TCPConn).SetLinger(0)) // close sends RST
		require.NoError(t, c.Close())
	}
	time.Sleep(100 * time.Millisecond)

	require.NoError(t, connectNone(t, ep, 3*time.Second))
}

// Garbage instead of Hello is rejected without affecting other clients.
func TestGarbageBeforeHelloKeepsAccepting(t *testing.T) {
	ep := startNoneServer(t)

	c, err := net.Dial("tcp", tcpAddr(ep))
	require.NoError(t, err)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	_, _ = c.Read(buf) // the server answers with ERR or closes
	c.Close()

	require.NoError(t, connectNone(t, ep, 3*time.Second))
}
