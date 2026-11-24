// Package server implements an OPC UA server.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ka1hung/opcua/schema"
	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uacp"
	"github.com/ka1hung/opcua/uapolicy"
	"github.com/ka1hung/opcua/uasc"
)

// Server is an OPC UA server.
type Server struct {
	cfg        *serverConfig
	listenAddr string

	space    *AddressSpace
	sessions *sessionManager
	subs     *subscriptionManager
	handlers map[uint16]Handler

	mu        sync.Mutex
	state     ua.ServerState
	startTime time.Time
	endpoints []*ua.EndpointDescription
	l         *uacp.Listener
	cb        *channelBroker
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	writeMu sync.RWMutex
	onWrite WriteFunc
	history HistoryReader

	eventSinks eventSinkSet
	alarms     alarmManager
}

// New returns a server. Call Start to serve. It loads the standard
// address space (namespace 0); the server's own namespace 1 is its
// ApplicationUri.
func New(opts ...Option) *Server {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	s := &Server{
		cfg:      cfg,
		space:    newAddressSpace(),
		handlers: make(map[uint16]Handler),
		state:    ua.ServerStateSuspended,
	}
	s.sessions = newSessionManager(s)
	s.subs = newSubscriptionManager(s)
	s.cb = newChannelBroker(s)

	if err := s.space.importNodeSet(schema.OpcUaNodeSet2); err != nil {
		// The embedded NodeSet is fixed at build time; a failure here is a
		// build defect, not a runtime condition.
		panic(err)
	}
	appURI := cfg.applicationURI
	if appURI == "" {
		appURI = "urn:opcua:server"
		cfg.applicationURI = appURI
	}
	s.space.namespaceIndex(appURI) // ns=1
	s.initServerObject()
	s.initAlarms()
	s.initHandlers()
	return s
}

// ListenAddress makes the server listen on addr (host:port, e.g.
// "0.0.0.0:4840") instead of the host and port of the first endpoint.
func ListenAddress(addr string) Option {
	return func(s *serverConfig) { s.listenAddr = addr }
}

// Space returns the server's address space.
func (s *Server) Space() *AddressSpace { return s.space }

// Endpoints returns the endpoint descriptions the server offers.
func (s *Server) Endpoints() []*ua.EndpointDescription {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*ua.EndpointDescription(nil), s.endpoints...)
}

// URLs returns the endpoint URLs.
func (s *Server) URLs() []string { return append([]string(nil), s.cfg.endpoints...) }

// Addr returns the address the server listens on, after Start.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		return nil
	}
	return s.l.Addr()
}

// Start starts listening and serving. It returns when the server listens.
func (s *Server) Start(ctx context.Context) error {
	if len(s.cfg.endpoints) == 0 {
		return fmt.Errorf("cannot start server: no endpoints defined")
	}
	if len(s.cfg.enabledSec) == 0 {
		return fmt.Errorf("cannot start server: no security policy enabled; call EnableSecurity")
	}
	if len(s.cfg.enabledAuth) == 0 {
		return fmt.Errorf("cannot start server: no user authentication enabled; call EnableAuthMode")
	}
	if s.securedPolicyEnabled() && (s.cfg.privateKey == nil || len(s.cfg.certificate) == 0) {
		return fmt.Errorf("cannot start server: secured policies need Certificate and PrivateKey")
	}
	if s.cfg.trustStore == nil && s.securedPolicyEnabled() {
		s.logWarn("no trust store configured: every client certificate is accepted; use server.TrustStore")
	}

	listen := s.cfg.endpoints[0]
	if s.cfg.listenAddr != "" {
		listen = "opc.tcp://" + s.cfg.listenAddr
	}
	l, err := uacp.Listen(ctx, listen, nil)
	if err != nil {
		return err
	}
	s.initEndpoints()

	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.l = l
	s.cancel = cancel
	s.state = ua.ServerStateRunning
	s.startTime = time.Now()
	s.mu.Unlock()

	s.cb.allowedSecurity = s.channelAllowed
	if ts := s.cfg.trustStore; ts != nil {
		s.cb.verifyPeer = func(chain []byte) error { return ts.Validate(chain, "") }
	}

	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.sessions.run() }()
	go func() { defer s.wg.Done(); s.acceptAndRegister(ctx, l) }()
	s.logInfo("listening on %s, endpoints %v", l.Addr(), s.cfg.endpoints)
	return nil
}

// Close stops the server: it stops listening, closes all sessions and
// secure channels, and waits for its goroutines.
func (s *Server) Close() error {
	s.mu.Lock()
	s.state = ua.ServerStateShutdown
	l, cancel := s.l, s.cancel
	s.mu.Unlock()
	if l != nil {
		l.Close()
	}
	if cancel != nil {
		cancel()
	}
	s.sessions.stop()
	s.subs.stop()
	err := s.cb.Close()
	s.wg.Wait()
	return err
}

func (s *Server) serverState() ua.ServerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Server) logf(level string, format string, args ...any) {
	l := s.cfg.logger
	if l == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	switch level {
	case "debug":
		l.Debug(msg)
	case "info":
		l.Info(msg)
	case "warn":
		l.Warn(msg)
	default:
		l.Error(msg)
	}
}

func (s *Server) logDebug(format string, args ...any) { s.logf("debug", format, args...) }
func (s *Server) logInfo(format string, args ...any)  { s.logf("info", format, args...) }
func (s *Server) logWarn(format string, args ...any)  { s.logf("warn", format, args...) }
func (s *Server) logError(format string, args ...any) { s.logf("error", format, args...) }

// securityEnabled reports whether the security policy and mode pair was
// enabled with EnableSecurity.
func (s *Server) securityEnabled(policyURI string, mode ua.MessageSecurityMode) bool {
	for _, sec := range s.cfg.enabledSec {
		if sec.secPolicy == policyURI && sec.secMode == mode {
			return true
		}
	}
	return false
}

// securedPolicyEnabled reports whether any policy other than None is enabled.
func (s *Server) securedPolicyEnabled() bool {
	for _, sec := range s.cfg.enabledSec {
		if sec.secPolicy != ua.SecurityPolicyURINone {
			return true
		}
	}
	return false
}

// channelAllowed reports whether a client may open a secure channel with
// the policy and mode. A None channel is always allowed so that clients
// can call the discovery services (OPC 10000-4 §5.4.1); when None is not
// enabled, handleService limits such a channel to those services.
func (s *Server) channelAllowed(policyURI string, mode ua.MessageSecurityMode) bool {
	if policyURI == ua.SecurityPolicyURINone && mode == ua.MessageSecurityModeNone {
		return true
	}
	return s.securityEnabled(policyURI, mode)
}

// discoveryOnly reports whether requests on sc are limited to the
// discovery services: the channel uses the None policy, which was not
// enabled for sessions.
func (s *Server) discoveryOnly(sc *uasc.SecureChannel) bool {
	return sc.SecurityPolicyURI() == ua.SecurityPolicyURINone &&
		!s.securityEnabled(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
}

// acceptAndRegister accepts TCP connections and hands each one to its own
// goroutine for the HEL/ACK handshake, so a client that is slow to send
// Hello, or never sends it, cannot delay other clients. An accept error
// ends the loop only when the listener is closed or ctx is done; any
// other error (a client resetting its connection, a transient resource
// limit) is logged and retried with a short backoff.
func (s *Server) acceptAndRegister(ctx context.Context, l *uacp.Listener) {
	const maxBackoff = time.Second
	var backoff time.Duration
	for {
		c, err := l.AcceptConn()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			s.logWarn("accept: %s; retrying in %v", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		if !s.cb.admit() {
			s.logWarn("refusing connection from %s: %d connections open", c.RemoteAddr(), s.cfg.limits.MaxConnections)
			c.SendError(ua.StatusBadTCPNotEnoughResources)
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.cb.release()
			s.handshakeAndRegister(ctx, l, c)
		}()
	}
}

// handshakeAndRegister runs the server side of the HEL/ACK handshake,
// bounded by the server's Hello timeout, then serves the connection.
func (s *Server) handshakeAndRegister(ctx context.Context, l *uacp.Listener, c *uacp.Conn) {
	hctx, cancel := context.WithTimeout(ctx, s.cfg.helloTimeout)
	err := c.ServerHandshake(hctx, l.Endpoint())
	cancel()
	if err != nil {
		c.Close()
		s.logDebug("handshake with %s failed: %s", c.RemoteAddr(), err)
		return
	}
	s.logDebug("connection from %s", c.RemoteAddr())
	s.cb.serve(ctx, c, s.cfg.certificate, s.cfg.privateKey)
}

// initEndpoints builds the endpoint descriptions from the enabled security
// policies and user token types.
func (s *Server) initEndpoints() {
	var endpoints []*ua.EndpointDescription
	for _, sec := range s.cfg.enabledSec {
		for _, u := range s.cfg.endpoints {
			ep := &ua.EndpointDescription{
				EndpointURL:         u,
				SecurityLevel:       uapolicy.SecurityLevel(sec.secPolicy, sec.secMode),
				Server:              s.applicationDescription(),
				ServerCertificate:   s.cfg.certificate,
				SecurityMode:        sec.secMode,
				SecurityPolicyURI:   sec.secPolicy,
				TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
				UserIdentityTokens:  s.userTokenPolicies(sec.secPolicy),
			}
			endpoints = append(endpoints, ep)
		}
	}
	s.mu.Lock()
	s.endpoints = endpoints
	s.mu.Unlock()
}

func (s *Server) applicationDescription() *ua.ApplicationDescription {
	return &ua.ApplicationDescription{
		ApplicationURI:  s.cfg.applicationURI,
		ProductURI:      s.cfg.productURI,
		ApplicationName: ua.NewLocalizedText(s.cfg.applicationName),
		ApplicationType: ua.ApplicationTypeServer,
		DiscoveryURLs:   s.URLs(),
	}
}

// tokenPolicyNone is used for user tokens on a None endpoint: the token is
// encrypted (UserName) or signed (X509) with the server certificate under
// this policy, so that a password never crosses the network in clear.
const tokenPolicyNone = ua.SecurityPolicyURIBasic256Sha256

// userTokenPolicies lists the user token policies of an endpoint with the
// given channel security policy.
func (s *Server) userTokenPolicies(channelPolicy string) []*ua.UserTokenPolicy {
	var out []*ua.UserTokenPolicy
	haveCert := len(s.cfg.certificate) > 0 && s.cfg.privateKey != nil
	for _, t := range s.cfg.enabledAuth {
		p := &ua.UserTokenPolicy{TokenType: t}
		switch t {
		case ua.UserTokenTypeAnonymous:
			p.PolicyID = "anonymous"
		case ua.UserTokenTypeUserName, ua.UserTokenTypeCertificate:
			base := strings.ToLower(strings.TrimPrefix(t.String(), "UserTokenType"))
			if channelPolicy == ua.SecurityPolicyURINone {
				if !haveCert {
					continue
				}
				p.PolicyID = base + "_" + strings.ToLower(strings.TrimPrefix(tokenPolicyNone, "http://opcfoundation.org/UA/SecurityPolicy#"))
				p.SecurityPolicyURI = tokenPolicyNone
			} else {
				p.PolicyID = base
			}
		default:
			continue
		}
		out = append(out, p)
	}
	return out
}

// tokenPolicy finds the user token policy with the id among the endpoint
// policies for the channel's security policy.
func (s *Server) tokenPolicy(channelPolicy, policyID string) *ua.UserTokenPolicy {
	for _, p := range s.userTokenPolicies(channelPolicy) {
		if p.PolicyID == policyID {
			return p
		}
	}
	return nil
}
