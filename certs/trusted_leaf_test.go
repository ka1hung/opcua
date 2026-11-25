package certs

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/ua"
)

// A CA-issued certificate that is trusted by itself is still checked
// against its issuer's CRL (GHSA-m7qw-w8q9-w5hf).
func TestTrustedCAIssuedLeafIsCheckedForRevocation(t *testing.T) {
	for _, caDir := range []string{"issuers", "trusted"} {
		t.Run(caDir, func(t *testing.T) {
			s := openStore(t, Options{})
			ca := issue(t, nil, "ca", true, nil)
			good := issue(t, ca, "good", false, nil)
			bad := issue(t, ca, "bad", false, nil)
			if caDir == "issuers" {
				put(t, s.issuerCerts(), ca.cert)
			} else {
				put(t, s.trustedCerts(), ca.cert)
			}
			put(t, s.trustedCerts(), good.cert)
			put(t, s.trustedCerts(), bad.cert)

			crl, err := x509CreateCRL(ca, bad)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(s.issuerCRL(), "ca.crl"), crl, 0o644))
			require.NoError(t, s.Reload())

			require.NoError(t, s.Validate(good.cert.Raw, ""))
			require.ErrorIs(t, s.Validate(bad.cert.Raw, ""), ua.StatusBadCertificateRevoked)
		})
	}
}

func TestTrustedCAIssuedLeafRequireCRL(t *testing.T) {
	s := openStore(t, Options{RequireCRL: true})
	ca := issue(t, nil, "ca", true, nil)
	app := issue(t, ca, "app", false, nil)
	put(t, s.issuerCerts(), ca.cert)
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Reload())
	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateRevocationUnknown)
}

// Without its issuer in the store, a trusted CA-issued certificate is
// accepted unless RequireCRL asks for its revocation status.
func TestTrustedCAIssuedLeafWithoutIssuer(t *testing.T) {
	ca := issue(t, nil, "ca", true, nil)
	app := issue(t, ca, "app", false, nil)

	s := openStore(t, Options{})
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Reload())
	require.NoError(t, s.Validate(app.cert.Raw, ""))

	s = openStore(t, Options{RequireCRL: true})
	put(t, s.trustedCerts(), app.cert)
	require.NoError(t, s.Reload())
	require.ErrorIs(t, s.Validate(app.cert.Raw, ""), ua.StatusBadCertificateRevocationUnknown)
}

func x509CreateCRL(ca, revoked *issued) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revoked.cert.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)},
		},
	}, ca.cert, ca.key)
}
