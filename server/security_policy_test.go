package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uacp"
	"github.com/ka1hung/opcua/uapolicy"
	"github.com/ka1hung/opcua/uasc"
)

// testCert returns a self-signed RSA certificate for an OPC UA application.
func testCert(t *testing.T, appURI string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	u, err := url.Parse(appURI)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: appURI},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der, key
}

// connectWith opens a secure channel and session with the given policy and
// mode and reports the error, if any.
func connectWith(t *testing.T, ep string, serverCert []byte, policy string, mode ua.MessageSecurityMode) error {
	t.Helper()
	cert, key := testCert(t, "urn:test:client")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := opcua.NewClient(ep,
		opcua.SecurityPolicy(policy),
		opcua.SecurityMode(mode),
		opcua.Certificate(cert),
		opcua.PrivateKey(key),
		opcua.RemoteCertificate(serverCert),
		opcua.AutoReconnect(false),
	)
	if err != nil {
		return err
	}
	err = c.Connect(ctx)
	_ = c.Close(context.Background())
	return err
}

// The server accepts only the security policy and mode pairs it was
// configured with; a client cannot pick another one, in particular not
// None (§10.1 T1).
func TestServerRejectsSecurityItDoesNotOffer(t *testing.T) {
	cert, key := testCert(t, "urn:test:server")
	ep := startSecuredServer(t, cert, key,
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))

	require.NoError(t, connectWith(t, ep, cert, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		"the offered pair must work")

	for _, tc := range []struct {
		policy string
		mode   ua.MessageSecurityMode
		want   ua.StatusCode
	}{
		{ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, ua.StatusBadSecurityModeRejected},
		{ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.MessageSecurityModeSignAndEncrypt, ua.StatusBadSecurityPolicyRejected},
	} {
		// The client's own error names the reason, not just EOF.
		require.ErrorIs(t, connectWith(t, ep, cert, tc.policy, tc.mode), tc.want, "%s %s must be rejected", tc.policy, tc.mode)
		// The server says why in an ERR message before closing.
		require.ErrorIs(t, openChannel(t, ep, cert, tc.policy, tc.mode), tc.want, "%s %s", tc.policy, tc.mode)
	}
}

// openChannel opens only a secure channel, with the uasc client, and
// returns the error the server reported for it: the ERR message the
// server sent, if one arrived, or the error from Open.
func openChannel(t *testing.T, ep string, serverCert []byte, policy string, mode ua.MessageSecurityMode) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := uacp.Dial(ctx, ep)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	cfg := &uasc.Config{
		SecurityPolicyURI: policy,
		SecurityMode:      mode,
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    3 * time.Second,
	}
	if policy != ua.SecurityPolicyURINone {
		cert, key := testCert(t, "urn:test:client")
		cfg.Certificate = cert
		cfg.LocalKey = key
		cfg.RemoteCertificate = serverCert
		cfg.Thumbprint = uapolicy.Thumbprint(serverCert)
	}
	errch := make(chan error, 4)
	sc, err := uasc.NewSecureChannel(ep, conn, cfg, errch)
	require.NoError(t, err)
	openErr := sc.Open(ctx)
	select {
	case err := <-errch:
		return err
	case <-time.After(time.Second):
		return openErr
	}
}

// A None channel to a server that offers only secure endpoints may be used
// for discovery (OPC 10000-4 §5.4.1) but not for a session (§10.1 T1).
func TestNoneChannelIsDiscoveryOnly(t *testing.T) {
	cert, key := testCert(t, "urn:test:server")
	ep := startSecuredServer(t, cert, key,
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, ep)
	require.NoError(t, err, "discovery over None must work")
	require.NotEmpty(t, eps)
	for _, e := range eps {
		require.NotEqual(t, ua.SecurityPolicyURINone, e.SecurityPolicyURI, "None is not offered for sessions")
	}

	err = connectWith(t, ep, cert, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
	require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected, "a session over None must be refused")
}

// startSecuredServer starts a server with the given certificate and
// security options on a free loopback port.
func startSecuredServer(t *testing.T, cert []byte, key *rsa.PrivateKey, opts ...server.Option) string {
	t.Helper()
	port := freePort(t)
	opts = append([]server.Option{
		server.Certificate(cert),
		server.PrivateKey(key),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EndPoint("127.0.0.1", port),
	}, opts...)
	srv := server.New(opts...)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return endpointURL(port)
}

// A server that offers only None does not open an encrypted channel with a
// policy it never offered.
func TestNoneOnlyServerRejectsOtherPolicies(t *testing.T) {
	cert, key := testCert(t, "urn:test:server")
	ep := startSecuredServer(t, cert, key,
		server.EnableSecurity("None", ua.MessageSecurityModeNone))

	require.NoError(t, openChannelOK(t, ep, cert, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone))
	require.ErrorIs(t,
		openChannel(t, ep, cert, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		ua.StatusBadSecurityPolicyRejected)
}

// openChannelOK is openChannel for a pair that must succeed: it reports
// only the error from Open.
func openChannelOK(t *testing.T, ep string, serverCert []byte, policy string, mode ua.MessageSecurityMode) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := uacp.Dial(ctx, ep)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	sc, err := uasc.NewSecureChannel(ep, conn, &uasc.Config{
		SecurityPolicyURI: policy,
		SecurityMode:      mode,
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    3 * time.Second,
	}, make(chan error, 4))
	require.NoError(t, err)
	return sc.Open(ctx)
}
