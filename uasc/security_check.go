package uasc

import "github.com/ka1hung/opcua/ua"

// policyAllowed reports whether allow permits policyURI with any mode.
func policyAllowed(allow func(string, ua.MessageSecurityMode) bool, policyURI string) bool {
	for _, mode := range []ua.MessageSecurityMode{
		ua.MessageSecurityModeNone,
		ua.MessageSecurityModeSign,
		ua.MessageSecurityModeSignAndEncrypt,
	} {
		if allow(policyURI, mode) {
			return true
		}
	}
	return false
}

// validSecurityPair reports whether mode can be used with policyURI at all:
// the None policy only with mode None, every other policy only with Sign
// or SignAndEncrypt (OPC 10000-4 §7.36, OPC 10000-6 §6.7.4).
func validSecurityPair(policyURI string, mode ua.MessageSecurityMode) bool {
	if policyURI == ua.SecurityPolicyURINone {
		return mode == ua.MessageSecurityModeNone
	}
	return mode == ua.MessageSecurityModeSign || mode == ua.MessageSecurityModeSignAndEncrypt
}

// SecurityPolicyURI returns the security policy the channel was opened with.
func (s *SecureChannel) SecurityPolicyURI() string {
	return s.cfg.SecurityPolicyURI
}

// RemoteCertificate returns the peer's certificate (DER, possibly followed
// by its chain) the channel was opened with, or nil under the None policy.
func (s *SecureChannel) RemoteCertificate() []byte {
	return s.cfg.RemoteCertificate
}

// SecureChannelID returns the id a server channel assigned to itself, or 0
// for a client channel.
func (s *SecureChannel) SecureChannelID() uint32 {
	return s.serverChannelID
}
