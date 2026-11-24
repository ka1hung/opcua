package server_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/certs"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uacp"
	"github.com/ka1hung/opcua/uapolicy"
	"github.com/ka1hung/opcua/uasc"
)

// connectAs connects a client with the given certificate, key and
// ApplicationURI over Basic256Sha256/SignAndEncrypt.
func connectAs(t *testing.T, ep string, serverCert, cert []byte, key *rsa.PrivateKey, appURI string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := opcua.NewClient(ep,
		opcua.SecurityPolicy(ua.SecurityPolicyURIBasic256Sha256),
		opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
		opcua.Certificate(cert),
		opcua.PrivateKey(key),
		opcua.RemoteCertificate(serverCert),
		opcua.ApplicationURI(appURI),
		opcua.AutoReconnect(false),
	)
	if err != nil {
		return err
	}
	err = c.Connect(ctx)
	_ = c.Close(context.Background())
	return err
}

// openChannelAs opens only a secure channel with the given client
// certificate and returns the error the server reported.
func openChannelAs(t *testing.T, ep string, serverCert, cert []byte, key *rsa.PrivateKey) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := uacp.Dial(ctx, ep)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	errch := make(chan error, 4)
	sc, err := uasc.NewSecureChannel(ep, conn, &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		Certificate:       cert,
		LocalKey:          key,
		RemoteCertificate: serverCert,
		Thumbprint:        uapolicy.Thumbprint(serverCert),
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    3 * time.Second,
	}, errch)
	require.NoError(t, err)
	openErr := sc.Open(ctx)
	select {
	case err := <-errch:
		return err
	case <-time.After(time.Second):
		return openErr
	}
}

// With a trust store, an unknown client certificate is refused when the
// channel is opened and saved for an operator to trust (§10.1 T2).
func TestTrustStoreRejectsUnknownClient(t *testing.T) {
	store, err := certs.Open(t.TempDir(), certs.Options{})
	require.NoError(t, err)
	srvCert, srvKey := testCert(t, "urn:test:server")
	ep := startSecuredServer(t, srvCert, srvKey,
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.TrustStore(store))

	cliCert, cliKey := testCert(t, "urn:test:client")
	require.ErrorIs(t, openChannelAs(t, ep, srvCert, cliCert, cliKey), ua.StatusBadCertificateUntrusted)
	require.Error(t, connectAs(t, ep, srvCert, cliCert, cliKey, "urn:test:client"))

	rejected, err := store.Rejected()
	require.NoError(t, err)
	require.Len(t, rejected, 1)

	// The operator trusts it; the client connects without a server restart.
	require.NoError(t, store.Trust(rejected[0]))
	require.NoError(t, connectAs(t, ep, srvCert, cliCert, cliKey, "urn:test:client"))
}

// The client's ApplicationUri must be the one in its certificate
// (OPC 10000-4 §5.6.2).
func TestCreateSessionChecksApplicationURI(t *testing.T) {
	store, err := certs.Open(t.TempDir(), certs.Options{})
	require.NoError(t, err)
	srvCert, srvKey := testCert(t, "urn:test:server")
	ep := startSecuredServer(t, srvCert, srvKey,
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.TrustStore(store))

	cliCert, cliKey := testCert(t, "urn:test:client")
	c, err := x509.ParseCertificate(cliCert)
	require.NoError(t, err)
	require.NoError(t, store.Trust(c))

	require.NoError(t, connectAs(t, ep, srvCert, cliCert, cliKey, "urn:test:client"))
	require.ErrorIs(t, connectAs(t, ep, srvCert, cliCert, cliKey, "urn:test:someone-else"),
		ua.StatusBadCertificateURIInvalid)
}
