package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/ua"
)

type issued struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

var serial int64

// issue creates a certificate signed by parent, or self-signed when parent
// is nil.
func issue(t *testing.T, parent *issued, cn string, ca bool, mod func(*x509.Certificate)) *issued {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial++
	u, _ := url.Parse("urn:test:" + cn)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
	}
	if ca {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if mod != nil {
		mod(tmpl)
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &issued{c, key}
}

func put(t *testing.T, dir string, c *x509.Certificate) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, Thumbprint(c)+".der"), c.Raw, 0o644))
}

func openStore(t *testing.T, opts Options) *Store {
	t.Helper()
	s, err := Open(t.TempDir(), opts)
	require.NoError(t, err)
	return s
}

func TestUntrustedSelfSignedIsRejectedAndSaved(t *testing.T) {
	s := openStore(t, Options{})
	app := issue(t, nil, "app", false, nil)

	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateUntrusted)

	rej, err := s.Rejected()
	require.NoError(t, err)
	require.Len(t, rej, 1)
	require.Equal(t, app.cert.Raw, rej[0].Raw)

	// The operator moves it to trusted; it is accepted without a restart.
	require.NoError(t, s.Trust(rej[0]))
	require.NoError(t, s.Validate(app.cert.Raw, ""))
	rej, _ = s.Rejected()
	require.Empty(t, rej)
}

func TestTrustedSelfSignedIsAccepted(t *testing.T) {
	s := openStore(t, Options{})
	app := issue(t, nil, "app", false, nil)
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Validate(app.cert.Raw, ""))
}

func TestFileAddedByOperatorIsNoticed(t *testing.T) {
	s := openStore(t, Options{})
	app := issue(t, nil, "app", false, nil)
	require.Error(t, s.Validate(app.cert.Raw, ""))

	// Some file systems keep directory mtimes in whole seconds.
	time.Sleep(1100 * time.Millisecond)
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Validate(app.cert.Raw, ""))
}

func TestCertificateIssuedByTrustedCAIsAccepted(t *testing.T) {
	s := openStore(t, Options{})
	ca := issue(t, nil, "ca", true, nil)
	app := issue(t, ca, "app", false, nil)
	put(t, s.trustedCerts(), ca.cert)

	require.NoError(t, s.Validate(app.cert.Raw, ""))
}

func TestCAInIssuersOnlyDoesNotMakeTrusted(t *testing.T) {
	s := openStore(t, Options{})
	ca := issue(t, nil, "ca", true, nil)
	app := issue(t, ca, "app", false, nil)
	put(t, s.issuerCerts(), ca.cert)

	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateUntrusted)

	// Trusting the application certificate itself is enough; the issuer
	// is used to build its chain.
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Reload())
	require.NoError(t, s.Validate(app.cert.Raw, ""))
}

func TestUnknownIssuerIsChainIncomplete(t *testing.T) {
	s := openStore(t, Options{})
	ca := issue(t, nil, "ca", true, nil)
	app := issue(t, ca, "app", false, nil)
	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateChainIncomplete)
}

func TestChainSentByPeerIsUsed(t *testing.T) {
	s := openStore(t, Options{})
	root := issue(t, nil, "root", true, nil)
	inter := issue(t, root, "inter", true, nil)
	app := issue(t, inter, "app", false, nil)
	put(t, s.trustedCerts(), root.cert)

	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateChainIncomplete)
	chain := append(append([]byte{}, app.cert.Raw...), inter.cert.Raw...)
	require.NoError(t, s.Validate(chain, ""))
}

func TestExpiredAndNotYetValid(t *testing.T) {
	s := openStore(t, Options{})
	expired := issue(t, nil, "old", false, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	future := issue(t, nil, "new", false, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(24 * time.Hour)
		c.NotAfter = time.Now().Add(48 * time.Hour)
	})
	put(t, s.trustedCerts(), expired.cert)
	put(t, s.trustedCerts(), future.cert)
	require.NoError(t, s.Reload())

	require.ErrorIs(t, s.Validate(expired.cert.Raw, ""), ua.StatusBadCertificateTimeInvalid)
	require.ErrorIs(t, s.Validate(future.cert.Raw, ""), ua.StatusBadCertificateTimeInvalid)

	// A device whose clock is off by up to two days can be tolerated.
	lenient := openStore(t, Options{ClockSkew: 48 * time.Hour})
	put(t, lenient.trustedCerts(), future.cert)
	require.NoError(t, lenient.Reload())
	require.NoError(t, lenient.Validate(future.cert.Raw, ""))
}

func TestApplicationURIMustMatch(t *testing.T) {
	s := openStore(t, Options{})
	app := issue(t, nil, "app", false, nil)
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Reload())

	require.NoError(t, s.Validate(app.cert.Raw, "urn:test:app"))
	require.ErrorIs(t, s.Validate(app.cert.Raw, "urn:test:other"), ua.StatusBadCertificateURIInvalid)
}

func TestKeyUsageWithoutSignatureIsRejected(t *testing.T) {
	s := openStore(t, Options{})
	app := issue(t, nil, "app", false, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageKeyEncipherment
	})
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Reload())
	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateUseNotAllowed)
}

func TestRevokedCertificate(t *testing.T) {
	s := openStore(t, Options{})
	ca := issue(t, nil, "ca", true, nil)
	good := issue(t, ca, "good", false, nil)
	bad := issue(t, ca, "bad", false, nil)
	put(t, s.trustedCerts(), ca.cert)

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: bad.cert.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)},
		},
	}, ca.cert, ca.key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(s.trustedCRL(), "ca.crl"), crl, 0o644))
	require.NoError(t, s.Reload())

	require.NoError(t, s.Validate(good.cert.Raw, ""))
	require.ErrorIs(t, s.Validate(bad.cert.Raw, ""), ua.StatusBadCertificateRevoked)
}

func TestRequireCRL(t *testing.T) {
	s := openStore(t, Options{RequireCRL: true})
	ca := issue(t, nil, "ca", true, nil)
	app := issue(t, ca, "app", false, nil)
	put(t, s.trustedCerts(), ca.cert)
	require.NoError(t, s.Reload())
	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateRevocationUnknown)
}

func TestAutoTrust(t *testing.T) {
	s := openStore(t, Options{AutoTrust: true})
	app := issue(t, nil, "app", false, nil)
	require.NoError(t, s.Validate(app.cert.Raw, ""))
	trusted, err := readCertDir(s.trustedCerts())
	require.NoError(t, err)
	require.Len(t, trusted, 1)
}

func TestRejectedDirectoryIsBounded(t *testing.T) {
	s := openStore(t, Options{MaxRejected: 3})
	for i := 0; i < 6; i++ {
		app := issue(t, nil, "app", false, nil)
		require.Error(t, s.Validate(app.cert.Raw, ""))
	}
	rej, err := s.Rejected()
	require.NoError(t, err)
	require.Len(t, rej, 3)
}

func TestGarbageIsInvalid(t *testing.T) {
	s := openStore(t, Options{})
	require.ErrorIs(t, s.Validate([]byte("not a certificate"), ""), ua.StatusBadCertificateInvalid)
	require.ErrorIs(t, s.Validate(nil, ""), ua.StatusBadCertificateInvalid)
}

func TestSelfSignedFitsSpecAndValidates(t *testing.T) {
	spec := Spec{ApplicationURI: "urn:host:app", Hosts: []string{"192.168.1.10", "plc.local"}}
	der, key, err := NewSelfSigned(spec)
	require.NoError(t, err)
	require.NotNil(t, key)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.NoError(t, Matches(c, spec, time.Now()))
	require.Error(t, Matches(c, Spec{ApplicationURI: "urn:host:app", Hosts: []string{"10.0.0.1"}}, time.Now()))

	s := openStore(t, Options{})
	put(t, s.trustedCerts(), c)
	require.NoError(t, s.Reload())
	require.NoError(t, s.Validate(der, "urn:host:app"))
}

func TestLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "own", "cert.der"), filepath.Join(dir, "own", "key.pem")
	spec := Spec{ApplicationURI: "urn:host:app", Hosts: []string{"10.0.0.1"}}

	der1, _, created, warn, err := LoadOrCreate(cf, kf, spec, true)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, warn)

	der2, _, created, _, err := LoadOrCreate(cf, kf, spec, true)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, der1, der2)

	// The address changed: keep the certificate but warn, or regenerate.
	moved := Spec{ApplicationURI: "urn:host:app", Hosts: []string{"10.0.0.2"}}
	der3, _, created, warn, err := LoadOrCreate(cf, kf, moved, false)
	require.NoError(t, err)
	require.False(t, created)
	require.Error(t, warn)
	require.Equal(t, der1, der3)

	der4, _, created, warn, err := LoadOrCreate(cf, kf, moved, true)
	require.NoError(t, err)
	require.True(t, created)
	require.Error(t, warn)
	require.NotEqual(t, der1, der4)
}

// Directories an operator removed are recreated.
func TestRemovedDirectoriesAreRecreated(t *testing.T) {
	s := openStore(t, Options{})
	require.NoError(t, os.RemoveAll(filepath.Join(s.Dir(), "rejected")))
	require.NoError(t, os.RemoveAll(filepath.Join(s.Dir(), "trusted")))
	app := issue(t, nil, "app", false, nil)
	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateUntrusted)
	rej, err := s.Rejected()
	require.NoError(t, err)
	require.Len(t, rej, 1)
}
