package uasc

import (
	"bytes"
	"crypto/x509"
	"time"

	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uapolicy"
)

// Server-side security token handling (OPC 10000-4 §5.5.2, OPC 10000-6
// §6.7.4). Every OpenSecureChannel request - Issue or Renew - gets a fresh
// instance with a new TokenId. The server keeps using the current token
// to send until the client first uses the new one, accepts each token
// until its lifetime (plus 25 %) has passed, and closes the channel when
// the newest token expires without being renewed.

const (
	minTokenLifetime = time.Second
	maxTokenLifetime = time.Hour
)

// serverTokens is the token state of a server channel.
type serverTokens struct {
	lastTokenID uint32
	pending     *channelInstance // issued, not yet used by the client
	expiry      *time.Timer
	opnChannel  uint32 // SecureChannelId in the header of the OPN being handled
}

func (s *SecureChannel) isServer() bool { return s.serverChannelID != 0 }

// serverOpening checks an OPN chunk on a server channel and returns a new
// instance, set up with the asymmetric algorithm, to decrypt and answer it.
func (s *SecureChannel) serverOpening(m *MessageChunk) (*channelInstance, error) {
	h := m.AsymmetricSecurityHeader
	if allow := s.cfg.AllowedSecurity; allow != nil && !policyAllowed(allow, h.SecurityPolicyURI) {
		return nil, ua.StatusBadSecurityPolicyRejected
	}

	s.instancesMu.Lock()
	open := s.activeInstance != nil
	s.instancesMu.Unlock()
	s.tokens.opnChannel = m.SecureChannelID

	if open {
		// A renewal keeps the channel's policy and client certificate.
		if m.SecureChannelID != s.serverChannelID {
			return nil, ua.StatusBadSecureChannelIDInvalid
		}
		if h.SecurityPolicyURI != s.cfg.SecurityPolicyURI {
			return nil, ua.StatusBadSecurityPolicyRejected
		}
		if h.SecurityPolicyURI != ua.SecurityPolicyURINone && !sameLeafCert(h.SenderCertificate, s.cfg.RemoteCertificate) {
			return nil, ua.StatusBadSecurityChecksFailed
		}
	} else {
		s.cfg.SecurityPolicyURI = h.SecurityPolicyURI
		if h.SecurityPolicyURI != ua.SecurityPolicyURINone {
			s.cfg.RemoteCertificate = h.SenderCertificate
			s.cfg.Thumbprint = uapolicy.Thumbprint(h.SenderCertificate)
			if verify := s.cfg.VerifyPeerCertificate; verify != nil {
				if err := verify(h.SenderCertificate); err != nil {
					return nil, err
				}
			}
		}
	}

	inst := newChannelInstance(s)
	inst.secureChannelID = s.serverChannelID
	if h.SecurityPolicyURI == ua.SecurityPolicyURINone {
		algo, err := uapolicy.Asymmetric(ua.SecurityPolicyURINone, nil, nil)
		if err != nil {
			return nil, err
		}
		inst.algo = algo
		s.openingInstance = inst
		return inst, nil
	}

	// The client encrypted the request for this server's certificate.
	if len(h.ReceiverCertificateThumbprint) > 0 && len(s.cfg.Certificate) > 0 &&
		!bytes.Equal(h.ReceiverCertificateThumbprint, uapolicy.Thumbprint(s.cfg.Certificate)) {
		return nil, ua.StatusBadCertificateInvalid
	}
	remoteKey, err := uapolicy.PublicKey(h.SenderCertificate)
	if err != nil {
		return nil, ua.StatusBadCertificateInvalid
	}
	algo, err := uapolicy.Asymmetric(h.SecurityPolicyURI, s.cfg.LocalKey, remoteKey)
	if err != nil {
		return nil, err
	}
	inst.algo = algo
	s.openingInstance = inst
	return inst, nil
}

func sameLeafCert(a, b []byte) bool {
	ca, err := x509.ParseCertificates(a)
	if err != nil || len(ca) == 0 {
		return false
	}
	cb, err := x509.ParseCertificates(b)
	if err != nil || len(cb) == 0 {
		return false
	}
	return bytes.Equal(ca[0].Raw, cb[0].Raw)
}

// reviseLifetime bounds a requested token lifetime in milliseconds.
func reviseLifetime(ms uint32) uint32 {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case ms == 0 || d > maxTokenLifetime:
		d = maxTokenLifetime
	case d < minTokenLifetime:
		d = minTokenLifetime
	}
	return uint32(d / time.Millisecond)
}

// checkServerOPN applies the request checks that need the decoded
// OpenSecureChannel request. It reports whether the request renews a
// token.
func (s *SecureChannel) checkServerOPN(req *ua.OpenSecureChannelRequest, inst *channelInstance) (renew bool, err error) {
	s.instancesMu.Lock()
	open := s.activeInstance != nil
	s.instancesMu.Unlock()

	switch req.RequestType {
	case ua.SecurityTokenRequestTypeIssue:
		if open {
			return false, ua.StatusBadRequestTypeInvalid
		}
	case ua.SecurityTokenRequestTypeRenew:
		if !open {
			return false, ua.StatusBadRequestTypeInvalid
		}
		if req.SecurityMode != s.cfg.SecurityMode {
			return false, ua.StatusBadSecurityModeRejected
		}
		renew = true
	default:
		return false, ua.StatusBadRequestTypeInvalid
	}
	if s.cfg.SecurityPolicyURI != ua.SecurityPolicyURINone && len(req.ClientNonce) != inst.algo.NonceLength() {
		return false, ua.StatusBadNonceInvalid
	}
	return renew, nil
}

// activateServerToken records a token after its OpenSecureChannel
// response was sent.
func (s *SecureChannel) activateServerToken(inst *channelInstance, renew bool) {
	now := s.timeNow()
	inst.createdAt = now
	inst.state = channelActive

	s.instancesMu.Lock()
	list := s.instances[inst.secureChannelID]
	// Drop tokens that expired; keep the active one.
	kept := list[:0]
	for _, old := range list {
		if old == s.activeInstance || !tokenExpired(old, now) {
			kept = append(kept, old)
		}
	}
	s.instances[inst.secureChannelID] = append(kept, inst)
	if renew {
		s.tokens.pending = inst
	} else {
		s.activeInstance = inst
	}
	s.instancesMu.Unlock()

	// Close the channel if this token expires without a renewal.
	grace := inst.revisedLifetime + inst.revisedLifetime/4
	if s.tokens.expiry != nil {
		s.tokens.expiry.Stop()
	}
	s.tokens.expiry = time.AfterFunc(grace, func() {
		s.instancesMu.Lock()
		list := s.instances[inst.secureChannelID]
		newest := len(list) > 0 && list[len(list)-1] == inst
		s.instancesMu.Unlock()
		if newest {
			_ = s.c.Close()
		}
	})
}

func tokenExpired(inst *channelInstance, now time.Time) bool {
	if inst.revisedLifetime == 0 {
		return false
	}
	return now.After(inst.createdAt.Add(inst.revisedLifetime + inst.revisedLifetime/4))
}

// serverInstanceFor returns the instance of the token a MSG or CLO chunk
// names.
func (s *SecureChannel) serverInstanceFor(m *MessageChunk) (*channelInstance, error) {
	if m.SymmetricSecurityHeader == nil {
		return nil, ua.StatusBadDecodingError
	}
	if m.SecureChannelID != s.serverChannelID {
		return nil, ua.StatusBadSecureChannelIDInvalid
	}
	tokenID := m.SymmetricSecurityHeader.TokenID
	now := s.timeNow()

	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	for _, inst := range s.instances[s.serverChannelID] {
		if inst.securityTokenID != tokenID {
			continue
		}
		if tokenExpired(inst, now) {
			return nil, ua.StatusBadSecureChannelTokenUnknown
		}
		return inst, nil
	}
	return nil, ua.StatusBadSecureChannelTokenUnknown
}

// tokenUsed is called after a chunk secured with inst was verified: the
// first verified message under a renewed token makes it the one the
// server sends with.
func (s *SecureChannel) tokenUsed(inst *channelInstance) {
	s.instancesMu.Lock()
	if inst == s.tokens.pending {
		s.activeInstance = inst
		s.tokens.pending = nil
	}
	s.instancesMu.Unlock()
}
