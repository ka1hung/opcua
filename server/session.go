package server

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uasc"
)

// Identity is the user of a session, as established by ActivateSession.
type Identity struct {
	// TokenType is how the user authenticated.
	TokenType ua.UserTokenType
	// UserName is set for UserName tokens.
	UserName string
	// Certificate is set for X509 tokens.
	Certificate *x509.Certificate
	// Roles are free-form role names the application assigns.
	Roles []string
	// Data is for the application.
	Data any
}

// Anonymous reports whether the identity is the anonymous user.
func (id *Identity) Anonymous() bool {
	return id == nil || id.TokenType == ua.UserTokenTypeAnonymous
}

func (id *Identity) sameUser(o *Identity) bool {
	if id.Anonymous() || o.Anonymous() {
		return id.Anonymous() && o.Anonymous()
	}
	if id.TokenType != o.TokenType {
		return false
	}
	switch id.TokenType {
	case ua.UserTokenTypeUserName:
		return id.UserName == o.UserName
	case ua.UserTokenTypeCertificate:
		return id.Certificate != nil && o.Certificate != nil && id.Certificate.Equal(o.Certificate)
	}
	return false
}

var anonymous = &Identity{TokenType: ua.UserTokenTypeAnonymous}

// Session is a client session.
type Session struct {
	srv *Server

	id        *ua.NodeID
	authToken *ua.NodeID
	name      string
	timeout   time.Duration
	clientURI string
	// clientCert is the leaf certificate of the channel the session was
	// created on; a session may move only to a channel with the same one.
	clientCert []byte

	mu           sync.Mutex
	channelID    uint32
	sc           *uasc.SecureChannel
	activated    bool
	identity     *Identity
	serverNonce  []byte
	lastActivity time.Time
	closed       bool

	browseCPs  map[string]*browseCP
	historyCPs map[string]*historyCP

	pub publishQueue
}

// ID returns the session's NodeId.
func (s *Session) ID() *ua.NodeID { return s.id }

// Identity returns the session's user.
func (s *Session) Identity() *Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity == nil {
		return anonymous
	}
	return s.identity
}

func (s *Session) touch() {
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()
}

func (s *Session) channel() *uasc.SecureChannel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sc
}

type sessionManager struct {
	srv *Server

	mu       sync.Mutex
	byToken  map[string]*Session
	byID     map[string]*Session
	closeCh  chan struct{}
	stopOnce sync.Once
}

func newSessionManager(srv *Server) *sessionManager {
	return &sessionManager{
		srv:     srv,
		byToken: make(map[string]*Session),
		byID:    make(map[string]*Session),
		closeCh: make(chan struct{}),
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return b
}

// create adds a session, or returns Bad_TooManySessions.
func (m *sessionManager) create(sc *uasc.SecureChannel, name string, timeout time.Duration) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byToken) >= m.srv.cfg.limits.MaxSessions {
		return nil, ua.StatusBadTooManySessions
	}
	s := &Session{
		srv: m.srv,
		// Session ids are public; authentication tokens are secrets and
		// come from crypto/rand (OPC 10000-4 §5.6.2).
		id:           ua.NewGUIDNodeID(1, newGUID()),
		authToken:    ua.NewByteStringNodeID(0, randomBytes(32)),
		name:         name,
		timeout:      timeout,
		clientCert:   leafOf(sc.RemoteCertificate()),
		channelID:    sc.SecureChannelID(),
		sc:           sc,
		lastActivity: time.Now(),
		browseCPs:    make(map[string]*browseCP),
		historyCPs:   make(map[string]*historyCP),
	}
	s.pub.init(m.srv.cfg.limits.MaxPublishRequestsPerSession)
	m.byToken[tokenKey(s.authToken)] = s
	m.byID[s.id.String()] = s
	return s, nil
}

func newGUID() string {
	b := randomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func leafOf(chain []byte) []byte {
	if len(chain) == 0 {
		return nil
	}
	cs, err := x509.ParseCertificates(chain)
	if err != nil || len(cs) == 0 {
		return nil
	}
	return cs[0].Raw
}

func tokenKey(id *ua.NodeID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func (m *sessionManager) byAuthToken(tok *ua.NodeID) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byToken[tokenKey(tok)]
}

func (m *sessionManager) list() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.byToken))
	for _, s := range m.byToken {
		out = append(out, s)
	}
	return out
}

func (m *sessionManager) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byToken)
}

// close removes a session and, if deleteSubs, its subscriptions. A
// session's subscriptions are otherwise kept until their lifetime ends so
// that another session can transfer them.
func (m *sessionManager) close(s *Session, deleteSubs bool) {
	m.mu.Lock()
	delete(m.byToken, tokenKey(s.authToken))
	delete(m.byID, s.id.String())
	m.mu.Unlock()

	s.mu.Lock()
	already := s.closed
	s.closed = true
	s.mu.Unlock()
	if already {
		return
	}
	s.pub.closeAll(ua.StatusBadSessionClosed)
	if deleteSubs {
		m.srv.subs.deleteSession(s)
	} else {
		m.srv.subs.orphan(s)
	}
}

// run closes sessions whose timeout passed without a request
// (OPC 10000-4 §5.6.2: RevisedSessionTimeout).
func (m *sessionManager) run() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.closeCh:
			return
		case now := <-t.C:
			for _, s := range m.list() {
				s.mu.Lock()
				idle := now.Sub(s.lastActivity)
				s.mu.Unlock()
				if idle > s.timeout {
					m.srv.logInfo("session %s timed out after %v", s.id, s.timeout)
					m.close(s, true)
					continue
				}
				s.pub.expire(now)
			}
		}
	}
}

func (m *sessionManager) stop() {
	m.stopOnce.Do(func() { close(m.closeCh) })
	for _, s := range m.list() {
		m.close(s, true)
	}
}

// channelClosed is called when a secure channel ends. Its sessions stay
// until they time out, so that a client can reconnect and reactivate them.
func (m *sessionManager) channelClosed(channelID uint32) {
	for _, s := range m.list() {
		s.mu.Lock()
		if s.channelID == channelID {
			s.sc = nil
		}
		s.mu.Unlock()
	}
}
