package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uapolicy"
	"github.com/ka1hung/opcua/uasc"
)

const sessionNonceLength = 32

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.2
func (s *Server) findServers(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.FindServersRequest)
	servers := []*ua.ApplicationDescription{s.applicationDescription()}
	if len(req.ServerURIs) > 0 {
		match := false
		for _, u := range req.ServerURIs {
			if u == s.cfg.applicationURI {
				match = true
			}
		}
		if !match {
			servers = nil
		}
	}
	return &ua.FindServersResponse{ResponseHeader: okHeader(req), Servers: servers}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.4
func (s *Server) getEndpoints(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.GetEndpointsRequest)
	return &ua.GetEndpointsResponse{
		ResponseHeader: okHeader(req),
		Endpoints:      s.endpointsFor(req.EndpointURL),
	}, nil
}

// endpointsFor returns the endpoints whose URL matches u, ignoring case
// and a trailing slash. When none match - a client reached the server by
// an address that is not in its endpoint list, such as an IP while the
// server is configured with its host name - the endpoints are returned
// with their host replaced by the one the client used (port and path
// kept). A client that follows the returned URL then connects the same
// way it reached the server, without needing a DNS name it cannot resolve.
func (s *Server) endpointsFor(u string) []*ua.EndpointDescription {
	all := s.Endpoints()
	norm := func(x string) string { return strings.TrimSuffix(strings.ToLower(x), "/") }
	var out []*ua.EndpointDescription
	for _, ep := range all {
		if norm(ep.EndpointURL) == norm(u) {
			out = append(out, ep)
		}
	}
	if len(out) > 0 {
		return out
	}
	req, err := url.Parse(u)
	if err != nil || req.Hostname() == "" {
		return all
	}
	seen := map[string]bool{}
	for _, ep := range all {
		a, err := url.Parse(ep.EndpointURL)
		if err != nil {
			out = append(out, ep)
			continue
		}
		port := a.Port()
		if port == "" {
			port = req.Port()
		}
		a.Host = req.Hostname()
		if port != "" {
			a.Host = net.JoinHostPort(req.Hostname(), port)
		}
		k := a.String() + "|" + ep.SecurityPolicyURI + "|" + ep.SecurityMode.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		c := *ep
		c.EndpointURL = a.String()
		out = append(out, &c)
	}
	return out
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.2
func (s *Server) createSession(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.CreateSessionRequest)
	if err := s.checkClient(r.SC, req); err != nil {
		return nil, err
	}

	timeout := time.Duration(req.RequestedSessionTimeout * float64(time.Millisecond))
	switch lim := s.cfg.limits; {
	case timeout <= 0:
		timeout = 60 * time.Second
	case timeout < lim.MinSessionTimeout:
		timeout = lim.MinSessionTimeout
	case timeout > lim.MaxSessionTimeout:
		timeout = lim.MaxSessionTimeout
	}

	sess, err := s.sessions.create(r.SC, req.SessionName, timeout)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(sessionNonceLength)
	sess.mu.Lock()
	if req.ClientDescription != nil {
		sess.clientURI = req.ClientDescription.ApplicationURI
		if req.ClientDescription.ApplicationName != nil {
			sess.clientName = req.ClientDescription.ApplicationName.Text
		}
	}
	sess.serverNonce = nonce
	sess.mu.Unlock()

	sig, alg, err := r.SC.NewSessionSignature(req.ClientCertificate, req.ClientNonce)
	if err != nil {
		s.sessions.close(sess, true)
		return nil, ua.StatusBadSecurityChecksFailed
	}

	return &ua.CreateSessionResponse{
		ResponseHeader:        okHeader(req),
		SessionID:             sess.id,
		AuthenticationToken:   sess.authToken,
		RevisedSessionTimeout: float64(timeout / time.Millisecond),
		ServerNonce:           nonce,
		ServerCertificate:     s.cfg.certificate,
		ServerEndpoints:       s.endpointsFor(req.EndpointURL),
		ServerSignature:       &ua.SignatureData{Signature: sig, Algorithm: alg},
	}, nil
}

// checkClient applies the checks of OPC 10000-4 §5.6.2 to a secured
// CreateSession request: the client certificate is the one the secure
// channel was opened with, it names the client's ApplicationUri and it is
// trusted, and the client nonce is long enough.
func (s *Server) checkClient(sc *uasc.SecureChannel, req *ua.CreateSessionRequest) error {
	if sc.SecurityPolicyURI() == ua.SecurityPolicyURINone {
		return nil
	}
	if len(req.ClientNonce) < sessionNonceLength {
		return ua.StatusBadNonceInvalid
	}
	if !bytes.Equal(leafOf(req.ClientCertificate), leafOf(sc.RemoteCertificate())) || leafOf(req.ClientCertificate) == nil {
		return ua.StatusBadSecurityChecksFailed
	}
	if ts := s.cfg.trustStore; ts != nil {
		appURI := ""
		if req.ClientDescription != nil {
			appURI = req.ClientDescription.ApplicationURI
		}
		if err := ts.Validate(req.ClientCertificate, appURI); err != nil {
			return err
		}
	}
	return nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.3
func (s *Server) activateSession(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.ActivateSessionRequest)
	sess := r.Session
	sc := r.SC

	sess.mu.Lock()
	closed, channelID, nonce := sess.closed, sess.channelID, sess.serverNonce
	sess.mu.Unlock()
	if closed {
		return nil, ua.StatusBadSessionClosed
	}

	// A session may move to another channel only if that channel belongs
	// to the same client application.
	if channelID != sc.SecureChannelID() && !bytes.Equal(leafOf(sc.RemoteCertificate()), sess.clientCert) {
		return nil, ua.StatusBadSecurityChecksFailed
	}

	if sc.SecurityPolicyURI() != ua.SecurityPolicyURINone {
		var sig []byte
		if req.ClientSignature != nil {
			sig = req.ClientSignature.Signature
		}
		if err := sc.VerifySessionSignature(sess.clientCert, nonce, sig); err != nil {
			return nil, ua.StatusBadApplicationSignatureInvalid
		}
	}

	who, err := s.authenticate(ctx, sc, nonce, req.UserIdentityToken, req.UserTokenSignature)
	if err != nil {
		s.logInfo("session %s: user rejected: %s", sess.id, err)
		return nil, err
	}

	newNonce := randomBytes(sessionNonceLength)
	sess.mu.Lock()
	sess.activated = true
	sess.identity = who
	sess.channelID = sc.SecureChannelID()
	sess.sc = sc
	sess.serverNonce = newNonce
	sess.mu.Unlock()
	s.subs.sessionChannelChanged(sess)

	return &ua.ActivateSessionResponse{
		ResponseHeader: okHeader(req),
		ServerNonce:    newNonce,
	}, nil
}

// authenticate checks a user identity token (OPC 10000-4 §5.6.3, §7.40).
func (s *Server) authenticate(ctx context.Context, sc *uasc.SecureChannel, serverNonce []byte, tok *ua.ExtensionObject, tokSig *ua.SignatureData) (*Identity, error) {
	if tok == nil || tok.Value == nil {
		// A null token means anonymous.
		tok = ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyID: "anonymous"})
	}
	channelPolicy := sc.SecurityPolicyURI()

	switch t := tok.Value.(type) {
	case *ua.AnonymousIdentityToken:
		p := s.tokenPolicy(channelPolicy, t.PolicyID)
		if p == nil || p.TokenType != ua.UserTokenTypeAnonymous {
			// Some clients send an empty policy id for anonymous.
			if p = s.tokenPolicy(channelPolicy, "anonymous"); p == nil {
				return nil, ua.StatusBadIdentityTokenInvalid
			}
		}
		return anonymous, nil

	case *ua.UserNameIdentityToken:
		p := s.tokenPolicy(channelPolicy, t.PolicyID)
		if p == nil || p.TokenType != ua.UserTokenTypeUserName {
			return nil, ua.StatusBadIdentityTokenInvalid
		}
		if s.cfg.authUser == nil {
			return nil, ua.StatusBadIdentityTokenRejected
		}
		policy := p.SecurityPolicyURI
		if policy == "" {
			policy = channelPolicy
		}
		password, err := s.decryptPassword(policy, t, serverNonce)
		if err != nil {
			return nil, err
		}
		who, err := s.cfg.authUser(ctx, t.UserName, password)
		if err != nil {
			return nil, userError(err)
		}
		if who == nil {
			who = &Identity{}
		}
		who.TokenType = ua.UserTokenTypeUserName
		who.UserName = t.UserName
		return who, nil

	case *ua.X509IdentityToken:
		p := s.tokenPolicy(channelPolicy, t.PolicyID)
		if p == nil || p.TokenType != ua.UserTokenTypeCertificate {
			return nil, ua.StatusBadIdentityTokenInvalid
		}
		if s.cfg.authCert == nil {
			return nil, ua.StatusBadIdentityTokenRejected
		}
		cert, err := x509.ParseCertificate(t.CertificateData)
		if err != nil {
			return nil, ua.StatusBadIdentityTokenInvalid
		}
		store := s.cfg.userTrustStore
		if store == nil {
			store = s.cfg.trustStore
		}
		if store != nil {
			if err := store.Validate(t.CertificateData, ""); err != nil {
				s.logInfo("user certificate %s rejected: %s", cert.Subject, err)
				return nil, ua.StatusBadIdentityTokenRejected
			}
		}
		policy := p.SecurityPolicyURI
		if policy == "" {
			policy = channelPolicy
		}
		if policy == ua.SecurityPolicyURINone || tokSig == nil {
			return nil, ua.StatusBadUserSignatureInvalid
		}
		key, err := uapolicy.PublicKey(t.CertificateData)
		if err != nil {
			return nil, ua.StatusBadIdentityTokenInvalid
		}
		enc, err := uapolicy.Asymmetric(policy, nil, key)
		if err != nil {
			return nil, ua.StatusBadUserSignatureInvalid
		}
		signed := append(append([]byte(nil), s.cfg.certificate...), serverNonce...)
		if err := enc.VerifySignature(signed, tokSig.Signature); err != nil {
			return nil, ua.StatusBadUserSignatureInvalid
		}
		who, err := s.cfg.authCert(ctx, cert)
		if err != nil {
			return nil, userError(err)
		}
		if who == nil {
			who = &Identity{}
		}
		who.TokenType = ua.UserTokenTypeCertificate
		who.Certificate = cert
		return who, nil
	}
	return nil, ua.StatusBadIdentityTokenInvalid
}

func userError(err error) error {
	if sc, ok := err.(ua.StatusCode); ok {
		return sc
	}
	return ua.StatusBadUserAccessDenied
}

// decryptPassword returns the password of a UserName token. Under a
// security policy the token holds, encrypted with the server's key, a
// 4-byte length, the password and the server nonce of the session
// (OPC 10000-4 §7.40.3); the nonce must be the current one, so that a
// recorded token cannot be replayed.
func (s *Server) decryptPassword(policy string, t *ua.UserNameIdentityToken, serverNonce []byte) (string, error) {
	if policy == ua.SecurityPolicyURINone {
		if t.EncryptionAlgorithm != "" {
			return "", ua.StatusBadIdentityTokenInvalid
		}
		return string(t.Password), nil
	}
	enc, err := uapolicy.Asymmetric(policy, s.cfg.privateKey, nil)
	if err != nil {
		return "", ua.StatusBadIdentityTokenInvalid
	}
	if t.EncryptionAlgorithm != enc.EncryptionURI() {
		return "", ua.StatusBadIdentityTokenInvalid
	}
	plain, err := enc.Decrypt(t.Password)
	if err != nil || len(plain) < 4 {
		return "", ua.StatusBadIdentityTokenInvalid
	}
	n := int(binary.LittleEndian.Uint32(plain))
	if n < len(serverNonce) || n > len(plain)-4 {
		return "", ua.StatusBadIdentityTokenInvalid
	}
	secret := plain[4 : 4+n]
	pw, nonce := secret[:n-len(serverNonce)], secret[n-len(serverNonce):]
	if !bytes.Equal(nonce, serverNonce) {
		return "", ua.StatusBadIdentityTokenInvalid
	}
	return string(pw), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.4
func (s *Server) closeSession(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.CloseSessionRequest)
	s.sessions.close(r.Session, req.DeleteSubscriptions)
	return &ua.CloseSessionResponse{ResponseHeader: okHeader(req)}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.5
func (s *Server) cancelRequest(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.CancelRequest)
	return &ua.CancelResponse{ResponseHeader: okHeader(req)}, nil
}
