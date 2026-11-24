package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Spec describes an application instance certificate.
type Spec struct {
	// ApplicationURI goes into the subjectAltName as a URI; it must equal
	// the application's ApplicationUri (OPC 10000-6 §6.2.2).
	ApplicationURI string
	// Hosts are host names and IP addresses the application is reached at;
	// they go into the subjectAltName as DNS names and IP addresses.
	Hosts []string
	// CommonName defaults to the first host or the ApplicationURI.
	CommonName   string
	Organization string
	// Validity defaults to 10 years.
	Validity time.Duration
	// KeyBits defaults to 2048.
	KeyBits int
}

// NewSelfSigned creates a self-signed application instance certificate and
// its RSA key. It returns the certificate as DER.
func NewSelfSigned(spec Spec) ([]byte, *rsa.PrivateKey, error) {
	if spec.ApplicationURI == "" {
		return nil, nil, errors.New("certs: ApplicationURI is required")
	}
	u, err := url.Parse(spec.ApplicationURI)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: invalid ApplicationURI: %w", err)
	}
	bits := spec.KeyBits
	if bits == 0 {
		bits = 2048
	}
	validity := spec.Validity
	if validity == 0 {
		validity = 10 * 365 * 24 * time.Hour
	}
	cn := spec.CommonName
	if cn == "" {
		cn = spec.ApplicationURI
		if len(spec.Hosts) > 0 {
			cn = spec.Hosts[0]
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: nonEmpty(spec.Organization),
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(validity),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
	}
	for _, h := range spec.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// Matches reports what about cert does not fit spec: a missing
// ApplicationURI or host, or an expiry within the next 30 days. It
// returns nil when the certificate fits.
func Matches(cert *x509.Certificate, spec Spec, now time.Time) error {
	if !hasURI(cert, spec.ApplicationURI) {
		return fmt.Errorf("certificate does not name ApplicationURI %s", spec.ApplicationURI)
	}
	for _, h := range spec.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			if !hasIP(cert, ip) {
				return fmt.Errorf("certificate does not name address %s", h)
			}
		} else if h != "" && !hasDNS(cert, h) {
			return fmt.Errorf("certificate does not name host %s", h)
		}
	}
	if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		return fmt.Errorf("certificate expires %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func hasIP(c *x509.Certificate, ip net.IP) bool {
	for _, a := range c.IPAddresses {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

func hasDNS(c *x509.Certificate, h string) bool {
	for _, d := range c.DNSNames {
		if d == h {
			return true
		}
	}
	return false
}

// LoadOrCreate loads the certificate (DER or PEM) and RSA key (PEM, PKCS#1
// or PKCS#8) from certFile and keyFile. When neither file exists it
// creates a self-signed certificate from spec and writes both files. When
// the files exist but the certificate does not fit spec (see Matches) and
// regenerate is true, it replaces them with a new self-signed certificate;
// with regenerate false it keeps them and returns the mismatch as warn.
func LoadOrCreate(certFile, keyFile string, spec Spec, regenerate bool) (certDER []byte, key *rsa.PrivateKey, created bool, warn error, err error) {
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		return create(certFile, keyFile, spec)
	}

	certDER, key, err = Load(certFile, keyFile)
	if err != nil {
		return nil, nil, false, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, false, nil, err
	}
	if mismatch := Matches(cert, spec, time.Now()); mismatch != nil {
		if !regenerate {
			return certDER, key, false, mismatch, nil
		}
		certDER, key, _, _, err = create(certFile, keyFile, spec)
		return certDER, key, true, mismatch, err
	}
	return certDER, key, false, nil, nil
}

func create(certFile, keyFile string, spec Spec) ([]byte, *rsa.PrivateKey, bool, error, error) {
	der, key, err := NewSelfSigned(spec)
	if err != nil {
		return nil, nil, false, nil, err
	}
	for _, f := range []string{certFile, keyFile} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return nil, nil, false, nil, err
		}
	}
	if err := os.WriteFile(certFile, der, 0o644); err != nil {
		return nil, nil, false, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return nil, nil, false, nil, err
	}
	return der, key, true, nil, nil
}

// Load reads a certificate (DER or PEM) and an RSA private key (PEM,
// PKCS#1 or PKCS#8).
func Load(certFile, keyFile string) ([]byte, *rsa.PrivateKey, error) {
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	certs := parseCerts(cb)
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("certs: no certificate in %s", certFile)
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(kb)
	if blk == nil {
		return nil, nil, fmt.Errorf("certs: no PEM key in %s", keyFile)
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return certs[0].Raw, k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: parse key %s: %w", keyFile, err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("certs: key in %s is %T, not RSA", keyFile, k)
	}
	return certs[0].Raw, rk, nil
}
