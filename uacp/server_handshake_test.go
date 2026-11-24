package uacp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/ua"
)

// listenLocal starts a Listener on a free loopback port.
func listenLocal(t *testing.T) *Listener {
	t.Helper()
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	return ln
}

// A client that connects and never sends Hello must not hold the server
// handshake forever: ServerHandshake gives up at its context deadline.
func TestServerHandshakeGivesUpAtDeadline(t *testing.T) {
	ln := listenLocal(t)

	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() })

	c, err := ln.AcceptConn()
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.ServerHandshake(ctx, ln.Endpoint()) }()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("ServerHandshake did not return after its context deadline")
	}
}

// Accept applies DefaultHelloTimeout, so a silent client cannot block it.
func TestAcceptGivesUpOnSilentClient(t *testing.T) {
	old := DefaultHelloTimeout
	DefaultHelloTimeout = 200 * time.Millisecond
	t.Cleanup(func() { DefaultHelloTimeout = old })

	ln := listenLocal(t)
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() })

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept(context.Background())
		if c != nil {
			c.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Accept blocked on a client that never sent Hello")
	}
}

// A server never acts on a ReverseHello: RHE is sent by a server to a
// client (OPC 10000-6 §7.1.2.6). Acting on it would make the server dial
// an address chosen by the peer.
func TestServerHandshakeRejectsReverseHello(t *testing.T) {
	ln := listenLocal(t)

	// A listener the server must never connect to.
	trap, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { trap.Close() })
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := trap.Accept(); err == nil {
			c.Close()
			dialed <- struct{}{}
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() })

	client := &Conn{TCPConn: raw.(*net.TCPConn), id: nextid(), ack: DefaultClientACK}
	rhe := &ReverseHello{ServerURI: trap.Addr().String(), EndpointURL: ln.Endpoint()}
	require.NoError(t, client.Send("RHEF", rhe))

	c, err := ln.AcceptConn()
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.Error(t, c.ServerHandshake(ctx, ln.Endpoint()))

	// The client is told why.
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = client.Receive()
	var uerr *Error
	require.ErrorAs(t, err, &uerr)
	require.Equal(t, uint32(ua.StatusBadTCPMessageTypeInvalid), uerr.ErrorCode)

	select {
	case <-dialed:
		t.Fatal("server dialed the address named in a ReverseHello")
	case <-time.After(200 * time.Millisecond):
	}
}
