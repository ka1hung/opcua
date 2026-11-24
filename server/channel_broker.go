package server

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"runtime/debug"
	"sync"
	"time"

	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uacp"
	"github.com/ka1hung/opcua/uasc"
)

// channelBroker owns the secure channels of the server.
type channelBroker struct {
	srv *Server

	mu              sync.Mutex
	channels        map[uint32]*uasc.SecureChannel
	conns           map[uint32]*uacp.Conn
	secureChannelID uint32
	secureTokenID   uint32
	open            int // connections admitted, including those in handshake

	// allowedSecurity reports whether a client may open a channel with a
	// security policy and mode. Set by Server.Start.
	allowedSecurity func(policyURI string, mode ua.MessageSecurityMode) bool

	// verifyPeer validates a client certificate when a channel is opened;
	// nil accepts any. Set by Server.Start.
	verifyPeer func(chainDER []byte) error
}

func newChannelBroker(srv *Server) *channelBroker {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return &channelBroker{
		srv:             srv,
		channels:        make(map[uint32]*uasc.SecureChannel),
		conns:           make(map[uint32]*uacp.Conn),
		secureChannelID: uint32(rng.Int31()),
		secureTokenID:   uint32(rng.Int31()),
	}
}

// admit counts a new connection; it reports false when MaxConnections are
// open.
func (c *channelBroker) admit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open >= c.srv.cfg.limits.MaxConnections {
		return false
	}
	c.open++
	return true
}

func (c *channelBroker) release() {
	c.mu.Lock()
	c.open--
	c.mu.Unlock()
}

func (c *channelBroker) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.channels)
}

// serve runs a secure channel on conn until the channel or ctx ends.
// Requests are handled concurrently, at most RequestsPerChannel at a time;
// responses may go out in another order, as OPC UA allows.
func (c *channelBroker) serve(ctx context.Context, conn *uacp.Conn, localCert []byte, localKey *rsa.PrivateKey) {
	cfg := defaultChannelConfig()
	cfg.Certificate = localCert
	cfg.LocalKey = localKey
	cfg.AllowedSecurity = c.allowedSecurity
	if cfg.AllowedSecurity == nil {
		cfg.AllowedSecurity = func(string, ua.MessageSecurityMode) bool { return false }
	}
	cfg.VerifyPeerCertificate = c.verifyPeer

	c.mu.Lock()
	c.secureChannelID++
	c.secureTokenID++
	channelID, tokenID := c.secureChannelID, c.secureTokenID
	c.mu.Unlock()
	sequenceNumber := uint32(mrand.Int31n(1023) + 1)

	sc, err := uasc.NewServerSecureChannel("", conn, cfg, make(chan error, 1), channelID, sequenceNumber, tokenID)
	if err != nil {
		c.srv.logError("creating secure channel: %s", err)
		conn.Close()
		return
	}

	c.mu.Lock()
	c.channels[channelID] = sc
	c.conns[channelID] = conn
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	sem := make(chan struct{}, c.srv.cfg.limits.RequestsPerChannel)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		c.mu.Lock()
		delete(c.channels, channelID)
		delete(c.conns, channelID)
		c.mu.Unlock()
		_ = conn.Close()
		c.srv.sessions.channelClosed(channelID)
		c.srv.logDebug("secure channel %d closed", channelID)
	}()

	for ctx.Err() == nil {
		msg := receiveSafe(ctx, sc)
		switch {
		case msg.Err == io.EOF:
			return
		case msg.Aborted():
			continue
		case msg.Err != nil:
			c.srv.logDebug("secure channel %d: %s", channelID, msg.Err)
			// Tell the client why before closing (OPC 10000-6 §7.1.3).
			conn.SendError(errorStatus(msg.Err))
			return
		}
		req := msg.Request()
		if req == nil {
			// OpenSecureChannel is answered inside uasc.
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(reqID uint32, req ua.Request) {
			defer func() { <-sem; wg.Done() }()
			c.srv.handleService(ctx, sc, reqID, req)
		}(msg.RequestID, req)
	}
}

// errorStatus picks the status code sent in an ERR message for err: the
// status code err carries, if any, and Bad_TcpInternalError otherwise.
func errorStatus(err error) ua.StatusCode {
	var sc ua.StatusCode
	if errors.As(err, &sc) {
		return sc
	}
	return ua.StatusBadTCPInternalError
}

// receiveSafe reads the next message from sc. A panic while reading or
// decoding a chunk - which holds bytes from the peer - ends this one
// channel with an error instead of the whole process.
func receiveSafe(ctx context.Context, sc *uasc.SecureChannel) (msg *uasc.MessageBody) {
	defer func() {
		if r := recover(); r != nil {
			msg = &uasc.MessageBody{Err: fmt.Errorf("panic while reading secure channel: %v\n%s", r, debug.Stack())}
		}
	}()
	return sc.Receive(ctx)
}

// Close closes all connections.
func (c *channelBroker) Close() error {
	c.mu.Lock()
	conns := make([]*uacp.Conn, 0, len(c.conns))
	for _, conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return nil
}
