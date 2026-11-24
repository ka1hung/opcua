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
	"github.com/ka1hung/opcua/certs"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

func testCertBits(t *testing.T, appURI string, bits int) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	u, _ := url.Parse(appURI)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: appURI},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der, key
}

// Every policy and mode works with 2048- and 4096-bit keys on either side;
// keys over 2048 bits use the ExtraPaddingSize byte (§10.1 T15, §10.4
// matrix B).
func TestPoliciesWithKeySizes(t *testing.T) {
	if testing.Short() {
		t.Skip("generates 4096-bit keys")
	}
	policies := []string{"Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"}
	for _, sizes := range [][2]int{{2048, 2048}, {2048, 4096}, {4096, 2048}, {4096, 4096}} {
		srvCert, srvKey := testCertBits(t, "urn:test:server", sizes[0])
		cliCert, cliKey := testCertBits(t, "urn:test:client", sizes[1])
		opts := []server.Option{server.Certificate(srvCert), server.PrivateKey(srvKey),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous), server.EndPoint("127.0.0.1", freePort(t))}
		for _, p := range policies {
			opts = append(opts,
				server.EnableSecurity(p, ua.MessageSecurityModeSign),
				server.EnableSecurity(p, ua.MessageSecurityModeSignAndEncrypt))
		}
		srv := server.New(opts...)
		require.NoError(t, srv.Start(context.Background()))
		ep := srv.URLs()[0]
		for _, p := range policies {
			if (p == "Basic128Rsa15" || p == "Basic256") && (sizes[0] > 2048 || sizes[1] > 2048) {
				// These policies allow keys of 1024 to 2048 bits only.
				continue
			}
			for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				c, err := opcua.NewClient(ep, opcua.AutoReconnect(false),
					opcua.SecurityPolicy(p), opcua.SecurityMode(mode),
					opcua.Certificate(cliCert), opcua.PrivateKey(cliKey), opcua.RemoteCertificate(srvCert),
					opcua.ApplicationURI("urn:test:client"))
				require.NoError(t, err)
				err = c.Connect(ctx)
				require.NoError(t, err, "server %d client %d %s %s", sizes[0], sizes[1], p, mode)
				_, err = c.NamespaceArray(ctx)
				require.NoError(t, err)
				_ = c.Close(context.Background())
				cancel()
			}
		}
		_ = srv.Close()
	}
}

// A user can log in with an X509 certificate the user trust store trusts
// (§10.4 matrix E).
func TestX509UserLogin(t *testing.T) {
	users, err := certs.Open(t.TempDir(), certs.Options{})
	require.NoError(t, err)
	userCert, userKey := testCert(t, "urn:test:user")
	uc, err := x509.ParseCertificate(userCert)
	require.NoError(t, err)

	f := newFixture(t,
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.UserTrustStore(users),
		server.CertificateAuthenticator(func(ctx context.Context, c *x509.Certificate) (*server.Identity, error) {
			return &server.Identity{Roles: []string{"admin"}}, nil
		}))

	login := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		eps, err := opcua.GetEndpoints(ctx, f.ep)
		require.NoError(t, err)
		var ep *ua.EndpointDescription
		for _, e := range eps {
			if e.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 {
				ep = e
			}
		}
		cliCert, cliKey := testCert(t, "urn:test:client")
		c, err := opcua.NewClient(ep.EndpointURL, opcua.AutoReconnect(false),
			opcua.Certificate(cliCert), opcua.PrivateKey(cliKey), opcua.ApplicationURI("urn:test:client"),
			opcua.AuthCertificate(userCert), opcua.AuthPrivateKey(userKey),
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeCertificate))
		require.NoError(t, err)
		err = c.Connect(ctx)
		if err == nil {
			_ = c.Close(context.Background())
		}
		return err
	}

	require.ErrorIs(t, login(), ua.StatusBadIdentityTokenRejected, "an untrusted user certificate")
	require.NoError(t, users.Trust(uc))
	require.NoError(t, login())
}
