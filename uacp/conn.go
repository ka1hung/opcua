// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uacp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ka1hung/opcua/debug"
	"github.com/ka1hung/opcua/errors"
	"github.com/ka1hung/opcua/ua"
)

const (
	KB = 1024
	MB = 1024 * KB

	DefaultReceiveBufSize = 0xffff
	DefaultSendBufSize    = 0xffff
	DefaultMaxChunkCount  = 512
	DefaultMaxMessageSize = 2 * MB
)

var (
	// DefaultClientACK is the ACK handshake message sent to the server
	// for client connections.
	DefaultClientACK = &Acknowledge{
		ReceiveBufSize: DefaultReceiveBufSize,
		SendBufSize:    DefaultSendBufSize,
		MaxChunkCount:  0, // use what the server wants
		MaxMessageSize: 0, // use what the server wants
	}

	// DefaultServerACK is the ACK handshake message sent to the client
	// for server connections.
	DefaultServerACK = &Acknowledge{
		ReceiveBufSize: DefaultReceiveBufSize,
		SendBufSize:    DefaultSendBufSize,
		MaxChunkCount:  DefaultMaxChunkCount,
		MaxMessageSize: DefaultMaxMessageSize,
	}
)

// connid stores the current connection id. updated with atomic.AddUint32
var connid uint32

// nextid returns the next connection id
func nextid() uint32 {
	return atomic.AddUint32(&connid, 1)
}

// Dialer establishes a connection to an endpoint.
type Dialer struct {
	// Dialer establishes the TCP connection. Defaults to net.Dialer.
	Dialer *net.Dialer

	// ClientACK defines the connection parameters requested by the client.
	// Defaults to DefaultClientACK.
	ClientACK *Acknowledge
}

func (d *Dialer) Dial(ctx context.Context, endpoint string) (*Conn, error) {
	debug.Printf("uacp: connecting to %s", endpoint)

	// Dial the host as written, not one address resolved up front: for a
	// name, net.Dialer tries every address it resolves to, in order, so a
	// name whose first address does not answer (localhost resolving to an
	// IPv6 ::1 the server does not listen on) still reaches the server on
	// the next one.
	_, raddr, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	dl := d.Dialer
	if dl == nil {
		dl = &net.Dialer{}
	}

	c, err := dl.DialContext(ctx, "tcp", raddr.Host)
	if err != nil {
		return nil, err
	}

	conn, err := NewConn(c.(*net.TCPConn), d.ClientACK)
	if err != nil {
		c.Close()
		return nil, err
	}

	debug.Printf("uacp %d: start HEL/ACK handshake", conn.id)
	if err := conn.Handshake(ctx, endpoint); err != nil {
		debug.Printf("uacp %d: HEL/ACK handshake failed: %s", conn.id, err)
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial uses the default dialer to establish a connection to the endpoint
func Dial(ctx context.Context, endpoint string) (*Conn, error) {
	d := &Dialer{}
	return d.Dial(ctx, endpoint)
}

// Listener is a OPC UA Connection Protocol network listener.
type Listener struct {
	l        *net.TCPListener
	ack      *Acknowledge
	endpoint string
}

// Listen acts like net.Listen for OPC UA Connection Protocol networks.
//
// Currently the endpoint can only be specified in "opc.tcp://<addr[:port]>/path" format.
//
// If the IP field of laddr is nil or an unspecified IP address, Listen listens
// on all available unicast and anycast IP addresses of the local system.
// If the Port field of laddr is 0, a port number is automatically chosen.
func Listen(ctx context.Context, endpoint string, ack *Acknowledge) (*Listener, error) {
	if ack == nil {
		ack = DefaultServerACK
	}
	_, laddr, err := ResolveEndpoint(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", laddr.Host)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l:        l.(*net.TCPListener),
		ack:      ack,
		endpoint: endpoint,
	}, nil
}

// DefaultHelloTimeout bounds how long Accept waits for a client's Hello.
var DefaultHelloTimeout = 10 * time.Second

// Accept accepts the next incoming connection and runs the server side of
// the HEL/ACK handshake, bounded by ctx and by DefaultHelloTimeout.
//
// Accept handles one connection at a time. A server that must not let one
// slow client delay the next should call AcceptConn and run ServerHandshake
// on its own goroutine instead.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	conn, err := l.AcceptConn()
	if err != nil {
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, DefaultHelloTimeout)
	defer cancel()
	if err := conn.ServerHandshake(hctx, l.endpoint); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// AcceptConn accepts the next incoming TCP connection without running the
// handshake. The caller must call ServerHandshake before using the
// connection, and must close it if the handshake fails.
func (l *Listener) AcceptConn() (*Conn, error) {
	c, err := l.l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return &Conn{TCPConn: c, id: nextid(), ack: l.ack}, nil
}

// ServerHandshake waits for the client's Hello and answers it, bounded by
// ctx: by its deadline, and by its cancellation. It does not close the
// connection on failure.
func (c *Conn) ServerHandshake(ctx context.Context, endpoint string) error {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() {
		// A deadline in the past unblocks the pending read or write.
		_ = c.SetDeadline(time.Unix(1, 0))
	})
	err := c.srvhandshake(endpoint)
	if !stop() {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	// Clear the handshake deadline for the secure channel that follows.
	return c.SetDeadline(time.Time{})
}

// Close closes the Listener.
func (l *Listener) Close() error {
	return l.l.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}

// Endpoint returns the listener's EndpointURL.
func (l *Listener) Endpoint() string {
	return l.endpoint
}

type Conn struct {
	*net.TCPConn
	id  uint32
	ack *Acknowledge

	// peerMaxMessageSize and peerMaxChunkCount are the limits the client
	// announced in its Hello, for a server connection; 0 means no limit.
	peerMaxMessageSize uint32
	peerMaxChunkCount  uint32

	closeOnce sync.Once
}

func NewConn(c *net.TCPConn, ack *Acknowledge) (*Conn, error) {
	if c == nil {
		return nil, fmt.Errorf("no connection")
	}
	if ack == nil {
		ack = DefaultClientACK
	}
	return &Conn{TCPConn: c, id: nextid(), ack: ack}, nil
}

func (c *Conn) ID() uint32 {
	return c.id
}

func (c *Conn) ReceiveBufSize() uint32 {
	return c.ack.ReceiveBufSize
}

func (c *Conn) SendBufSize() uint32 {
	return c.ack.SendBufSize
}

func (c *Conn) MaxMessageSize() uint32 {
	return c.ack.MaxMessageSize
}

func (c *Conn) MaxChunkCount() uint32 {
	return c.ack.MaxChunkCount
}

// PeerMaxMessageSize is the largest message the client of a server
// connection accepts; 0 means no limit or a client connection.
func (c *Conn) PeerMaxMessageSize() uint32 { return c.peerMaxMessageSize }

// PeerMaxChunkCount is the most chunks per message the client of a server
// connection accepts; 0 means no limit or a client connection.
func (c *Conn) PeerMaxChunkCount() uint32 { return c.peerMaxChunkCount }

// minHelloBufSize is the smallest buffer size a Hello may announce
// (OPC 10000-6 §7.1.2.3).
const minHelloBufSize = 8192

func (c *Conn) Close() (err error) {
	err = io.EOF
	c.closeOnce.Do(func() { err = c.close() })
	return err
}

func (c *Conn) close() error {
	debug.Printf("uacp %d: close", c.id)
	return c.TCPConn.Close()
}

// Handshake sends Hello and waits for Acknowledge, bounded by ctx: by its
// deadline, and by its cancellation. The reconnect monitor dials with a
// ctx that is cancelled on Client.Close but has no deadline; a server that
// accepts the TCP connection and never answers Hello would otherwise hold
// the read — and the monitor goroutine and its socket — past Close.
func (c *Conn) Handshake(ctx context.Context, endpoint string) error {
	stop := context.AfterFunc(ctx, func() {
		// A deadline in the past unblocks the pending read or write.
		_ = c.SetDeadline(time.Unix(1, 0))
	})
	err := c.handshake(ctx, endpoint)
	if !stop() {
		// ctx ended during the exchange. Whatever it returned, the
		// connection's deadline is now in the past: report why.
		return ctx.Err()
	}
	return err
}

func (c *Conn) handshake(ctx context.Context, endpoint string) error {
	hel := &Hello{
		Version:        c.ack.Version,
		ReceiveBufSize: c.ack.ReceiveBufSize,
		SendBufSize:    c.ack.SendBufSize,
		MaxMessageSize: c.ack.MaxMessageSize,
		MaxChunkCount:  c.ack.MaxChunkCount,
		EndpointURL:    endpoint,
	}

	// set a deadline if there is one
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}

	if err := c.Send("HELF", hel); err != nil {
		return err
	}

	b, err := c.Receive()
	if err != nil {
		return err
	}

	// clear the deadline
	c.SetDeadline(time.Time{})

	msgtyp := string(b[:4])
	switch msgtyp {
	case "ACKF":
		ack := new(Acknowledge)
		if _, err := ack.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ACK failed: %s", err)
		}
		if ack.Version != 0 {
			return errors.Errorf("uacp: invalid version %d", ack.Version)
		}
		if ack.MaxChunkCount == 0 {
			ack.MaxChunkCount = DefaultMaxChunkCount
			debug.Printf("uacp %d: server has no chunk limit. Using %d", c.id, ack.MaxChunkCount)
		}
		if ack.MaxMessageSize == 0 {
			ack.MaxMessageSize = DefaultMaxMessageSize
			debug.Printf("uacp %d: server has no message size limit. Using %d", c.id, ack.MaxMessageSize)
		}
		c.ack = ack
		debug.Printf("uacp %d: recv %#v", c.id, ack)
		return nil

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ERR failed: %s", err)
		}
		debug.Printf("uacp %d: recv %#v", c.id, errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return errors.Errorf("invalid handshake packet %q", msgtyp)
	}
}

func (c *Conn) srvhandshake(endpoint string) error {
	b, err := c.Receive()
	if err != nil {
		c.SendError(ua.StatusBadTCPInternalError)
		return err
	}

	// HEL or RHE?
	msgtyp := string(b[:4])
	msg := b[hdrlen:]
	switch msgtyp {
	case "HELF":
		hel := new(Hello)
		if _, err := hel.Decode(msg); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		// The EndpointUrl is not checked: a client may reach the server by
		// any of its addresses.
		if hel.ReceiveBufSize < minHelloBufSize || hel.SendBufSize < minHelloBufSize {
			c.SendError(ua.StatusBadTCPInternalError)
			return errors.Errorf("uacp: buffer sizes %d/%d below %d", hel.ReceiveBufSize, hel.SendBufSize, minHelloBufSize)
		}
		// Negotiate (OPC 10000-6 §7.1.2.4): never receive chunks larger
		// than the client sends, never send chunks larger than it receives.
		ack := *c.ack
		ack.Version = 0
		ack.ReceiveBufSize = min(ack.ReceiveBufSize, hel.SendBufSize)
		ack.SendBufSize = min(ack.SendBufSize, hel.ReceiveBufSize)
		c.peerMaxMessageSize = hel.MaxMessageSize
		c.peerMaxChunkCount = hel.MaxChunkCount
		if err := c.Send("ACKF", &ack); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		c.ack = &ack
		debug.Printf("uacp %d: recv %#v", c.id, hel)
		return nil

	case "RHEF":
		// A ReverseHello is sent by a server to a client
		// (OPC 10000-6 §7.1.2.6); a server never acts on one. The
		// upstream code dialed the peer-chosen ServerURI here.
		c.SendError(ua.StatusBadTCPMessageTypeInvalid)
		return errors.Errorf("uacp: unexpected ReverseHello from client")

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ERR failed: %s", err)
		}
		debug.Printf("uacp %d: recv %#v", c.id, errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return errors.Errorf("invalid handshake packet %q", msgtyp)
	}
}

// hdrlen is the size of the uacp header
const hdrlen = 8

// Receive reads a full UACP message from the underlying connection.
// The size of b must be at least ReceiveBufSize. Otherwise,
// the function returns an error.
func (c *Conn) Receive() ([]byte, error) {
	// TODO(kung-foo): allow user-specified buffer
	// TODO(kung-foo): sync.Pool
	b := make([]byte, c.ack.ReceiveBufSize)

	if _, err := io.ReadFull(c, b[:hdrlen]); err != nil {
		// todo(fs): do not wrap this error since it hides io.EOF
		// todo(fs): use golang.org/x/xerrors
		return nil, err
	}

	var h Header
	if _, err := h.Decode(b[:hdrlen]); err != nil {
		return nil, errors.Errorf("uacp: header decode failed: %s", err)
	}

	if h.MessageSize > c.ack.ReceiveBufSize {
		return nil, errors.Errorf("uacp: message too large: %d > %d bytes. MsgType=%s, ChunkType=%c", h.MessageSize, c.ack.ReceiveBufSize, h.MessageType, h.ChunkType)
	}
	if h.MessageSize < hdrlen {
		return nil, errors.Errorf("uacp: message too small: %d bytes. MsgType=%s, ChunkType=%c.", h.MessageSize, h.MessageType, h.ChunkType)
	}

	if _, err := io.ReadFull(c, b[hdrlen:h.MessageSize]); err != nil {
		// todo(fs): do not wrap this error since it hides io.EOF
		// todo(fs): use golang.org/x/xerrors
		return nil, err
	}

	debug.Printf("uacp %d: recv %s%c with %d bytes", c.id, h.MessageType, h.ChunkType, h.MessageSize)

	if h.MessageType == "ERR" {
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:h.MessageSize]); err != nil {
			return nil, errors.Errorf("uacp: failed to decode ERRF message: %s", err)
		}
		return nil, errf
	}
	return b[:h.MessageSize], nil
}

func (c *Conn) Send(typ string, msg interface{}) error {
	if len(typ) != 4 {
		return errors.Errorf("invalid msg type: %s", typ)
	}

	body, err := ua.Encode(msg)
	if err != nil {
		return errors.Errorf("encode msg failed: %s", err)
	}

	h := Header{
		MessageType: typ[:3],
		ChunkType:   typ[3],
		MessageSize: uint32(len(body) + hdrlen),
	}

	if h.MessageSize > c.ack.SendBufSize {
		return errors.Errorf("send packet too large: %d > %d bytes", h.MessageSize, c.ack.SendBufSize)
	}

	hdr, err := h.Encode()
	if err != nil {
		return errors.Errorf("encode hdr failed: %s", err)
	}

	b := append(hdr, body...)
	if _, err := c.Write(b); err != nil {
		return errors.Errorf("write failed: %s", err)
	}
	debug.Printf("uacp %d: sent %s with %d bytes", c.id, typ, len(b))

	return nil
}

func (c *Conn) SendError(code ua.StatusCode) {
	// we swallow the error to silence complaints from the linter
	// since sending an error will close the connection and we
	// want to bubble a different error up.
	_ = c.Send("ERRF", &Error{ErrorCode: uint32(code)})
}
