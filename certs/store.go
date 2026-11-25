// Package certs holds the certificate trust store of an OPC UA application
// and helpers to create application instance certificates.
//
// The store uses the directory layout of OPC 10000-12 §F.1, which UaExpert
// and the OPC Foundation stacks also use:
//
//	<dir>/trusted/certs   trusted certificates (application or CA)
//	<dir>/trusted/crl     CRLs of trusted CAs
//	<dir>/issuers/certs   CA certificates used only to build chains
//	<dir>/issuers/crl     CRLs of those CAs
//	<dir>/rejected/certs  certificates that were rejected, for an operator
//	                      to review and move to trusted/certs
//
// Certificates are read as DER (.der, .cer) or PEM (.pem, .crt). The store
// notices files added or removed by an operator without a restart.
package certs

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ka1hung/opcua/ua"
)

// DefaultMaxRejected is the default number of certificates kept in the
// rejected directory; the oldest are deleted beyond it.
const DefaultMaxRejected = 100

// Options configures a Store.
type Options struct {
	// AutoTrust adds every certificate that is not trusted to
	// trusted/certs and accepts it. Use only to commission a system.
	AutoTrust bool

	// RequireCRL rejects a certificate issued by a CA that has no CRL in
	// the store with Bad_CertificateRevocationUnknown. By default a missing
	// CRL is accepted, since many plants do not run a CA.
	RequireCRL bool

	// ClockSkew widens the validity period of every certificate by this
	// much in both directions, for devices whose clock may be off.
	ClockSkew time.Duration

	// MaxRejected bounds the files in rejected/certs. 0 means
	// DefaultMaxRejected; a negative value disables saving rejected
	// certificates.
	MaxRejected int

	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// Store is a certificate trust store backed by a directory.
type Store struct {
	dir  string
	opts Options

	mu       sync.Mutex
	loadedAt map[string]time.Time // directory -> mtime at last load
	trusted  []*x509.Certificate
	issuers  []*x509.Certificate
	crls     []*x509.RevocationList
}

// Open opens the store in dir, creating its directories if needed.
func Open(dir string, opts Options) (*Store, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxRejected == 0 {
		opts.MaxRejected = DefaultMaxRejected
	}
	s := &Store{dir: dir, opts: opts}
	for _, d := range s.dirs() {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) trustedCerts() string  { return filepath.Join(s.dir, "trusted", "certs") }
func (s *Store) trustedCRL() string    { return filepath.Join(s.dir, "trusted", "crl") }
func (s *Store) issuerCerts() string   { return filepath.Join(s.dir, "issuers", "certs") }
func (s *Store) issuerCRL() string     { return filepath.Join(s.dir, "issuers", "crl") }
func (s *Store) rejectedCerts() string { return filepath.Join(s.dir, "rejected", "certs") }

func (s *Store) dirs() []string {
	return []string{s.trustedCerts(), s.trustedCRL(), s.issuerCerts(), s.issuerCRL(), s.rejectedCerts()}
}

// refresh reloads the store when an operator changed one of its
// directories since the last load. Called with s.mu held.
func (s *Store) refresh() error {
	for _, d := range []string{s.trustedCerts(), s.trustedCRL(), s.issuerCerts(), s.issuerCRL()} {
		fi, err := os.Stat(d)
		if os.IsNotExist(err) {
			// An operator removed a directory: recreate the layout.
			for _, d := range s.dirs() {
				if err := os.MkdirAll(d, 0o755); err != nil {
					return err
				}
			}
			return s.reload()
		}
		if err != nil {
			return err
		}
		if !fi.ModTime().Equal(s.loadedAt[d]) {
			return s.reload()
		}
	}
	return nil
}

// reload reads all trusted and issuer certificates and CRLs.
func (s *Store) reload() error {
	loadedAt := map[string]time.Time{}
	stamp := func(d string) {
		if fi, err := os.Stat(d); err == nil {
			loadedAt[d] = fi.ModTime()
		}
	}
	for _, d := range []string{s.trustedCerts(), s.trustedCRL(), s.issuerCerts(), s.issuerCRL()} {
		stamp(d)
	}
	trusted, err := readCertDir(s.trustedCerts())
	if err != nil {
		return err
	}
	issuers, err := readCertDir(s.issuerCerts())
	if err != nil {
		return err
	}
	var crls []*x509.RevocationList
	for _, d := range []string{s.trustedCRL(), s.issuerCRL()} {
		l, err := readCRLDir(d)
		if err != nil {
			return err
		}
		crls = append(crls, l...)
	}
	s.trusted, s.issuers, s.crls, s.loadedAt = trusted, issuers, crls, loadedAt
	return nil
}

// Validate checks a peer's application instance certificate, given as
// DER, optionally followed by the DER of its issuer chain, as OPC UA
// sends it. If applicationURI is not empty, the certificate must name it
// in its subjectAltName. It returns nil or a ua.StatusCode error that says
// why the certificate is not accepted (OPC 10000-4 §6.1.3).
//
// A certificate that is not trusted is saved to rejected/certs - unless
// AutoTrust is set, in which case it is saved to trusted/certs and
// accepted.
func (s *Store) Validate(chainDER []byte, applicationURI string) error {
	chain, err := x509.ParseCertificates(chainDER)
	if err != nil || len(chain) == 0 {
		return ua.StatusBadCertificateInvalid
	}
	leaf := chain[0]

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return ua.StatusBadCertificateInvalid
	}

	if applicationURI != "" && !hasURI(leaf, applicationURI) {
		return ua.StatusBadCertificateURIInvalid
	}
	if err := s.checkTime(leaf); err != nil {
		return err
	}
	if err := checkUse(leaf); err != nil {
		return err
	}

	path, status := s.buildPath(leaf, chain[1:])
	if status == ua.StatusBadCertificateUntrusted && s.opts.AutoTrust {
		if err := s.save(s.trustedCerts(), leaf); err != nil {
			return ua.StatusBadCertificateUntrusted
		}
		if err := s.reload(); err != nil {
			return ua.StatusBadCertificateUntrusted
		}
		path, status = s.buildPath(leaf, chain[1:])
	}
	if status != ua.StatusOK {
		if status == ua.StatusBadCertificateUntrusted {
			s.reject(leaf)
		}
		return status
	}

	// A trusted CA-issued certificate whose issuer chain does not reach a
	// root in the store is the path by itself; its revocation is still
	// looked up at its issuer, if the store or the peer has it.
	if len(path) == 1 && !isSelfSigned(leaf) {
		issuer := s.issuerOf(leaf, chain[1:])
		if issuer == nil {
			if s.opts.RequireCRL {
				return ua.StatusBadCertificateRevocationUnknown
			}
			return nil
		}
		return s.checkRevoked(leaf, issuer)
	}

	// The issuers above the leaf must be valid, usable CAs and not revoked.
	for i, c := range path {
		if i > 0 {
			if err := s.checkTime(c); err != nil {
				return ua.StatusBadCertificateIssuerTimeInvalid
			}
			if !c.IsCA || (c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0) {
				return ua.StatusBadCertificateIssuerUseNotAllowed
			}
		}
		if i+1 < len(path) {
			if err := s.checkRevoked(c, path[i+1]); err != nil {
				if i == 0 {
					return err
				}
				return issuerStatus(err)
			}
		}
	}
	return nil
}

// buildPath finds the path from leaf to a trust anchor and checks that
// some certificate on it is trusted. It returns the path, leaf first.
func (s *Store) buildPath(leaf *x509.Certificate, sent []*x509.Certificate) ([]*x509.Certificate, ua.StatusCode) {
	if s.isTrusted(leaf) && isSelfSigned(leaf) {
		return []*x509.Certificate{leaf}, ua.StatusOK
	}

	roots := x509.NewCertPool()
	inter := x509.NewCertPool()
	for _, c := range append(append([]*x509.Certificate{}, s.trusted...), s.issuers...) {
		if isSelfSigned(c) {
			roots.AddCert(c)
		} else {
			inter.AddCert(c)
		}
	}
	for _, c := range sent {
		inter.AddCert(c)
	}
	// A trusted certificate that is not self-signed is trusted by itself,
	// but it is not added to the roots: crypto/x509 would then return the
	// chain [leaf] alone, and its issuers would not be checked nor its
	// revocation looked up. The chain is built to the issuer the store
	// knows; without one, the leaf alone is the path (see Validate).

	// Validity periods are checked by Validate, with ClockSkew; build the
	// chain at a time the leaf is valid so that x509 checks only the path.
	at := s.opts.Now()
	if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore
	} else if at.After(leaf.NotAfter) {
		at = leaf.NotAfter
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) {
			if s.isTrusted(leaf) {
				return []*x509.Certificate{leaf}, ua.StatusOK
			}
			if isSelfSigned(leaf) {
				return nil, ua.StatusBadCertificateUntrusted
			}
			return nil, ua.StatusBadCertificateChainIncomplete
		}
		var inv x509.CertificateInvalidError
		if errors.As(err, &inv) && inv.Reason == x509.Expired {
			return nil, ua.StatusBadCertificateIssuerTimeInvalid
		}
		return nil, ua.StatusBadCertificateInvalid
	}
	for _, chain := range chains {
		for _, c := range chain {
			if s.isTrusted(c) {
				return chain, ua.StatusOK
			}
		}
	}
	return nil, ua.StatusBadCertificateUntrusted
}

// issuerOf finds the certificate that signed c among the store's
// certificates and those the peer sent.
func (s *Store) issuerOf(c *x509.Certificate, sent []*x509.Certificate) *x509.Certificate {
	for _, list := range [][]*x509.Certificate{s.issuers, s.trusted, sent} {
		for _, i := range list {
			if !bytes.Equal(i.Raw, c.Raw) && c.CheckSignatureFrom(i) == nil {
				return i
			}
		}
	}
	return nil
}

func (s *Store) isTrusted(c *x509.Certificate) bool {
	for _, t := range s.trusted {
		if bytes.Equal(t.Raw, c.Raw) {
			return true
		}
	}
	return false
}

func (s *Store) checkTime(c *x509.Certificate) error {
	now := s.opts.Now()
	if now.Before(c.NotBefore.Add(-s.opts.ClockSkew)) || now.After(c.NotAfter.Add(s.opts.ClockSkew)) {
		return ua.StatusBadCertificateTimeInvalid
	}
	return nil
}

// checkRevoked checks c against the CRL of its issuer.
func (s *Store) checkRevoked(c, issuer *x509.Certificate) error {
	var found bool
	for _, crl := range s.crls {
		if crl.CheckSignatureFrom(issuer) != nil {
			continue
		}
		found = true
		for _, r := range crl.RevokedCertificateEntries {
			if r.SerialNumber.Cmp(c.SerialNumber) == 0 {
				return ua.StatusBadCertificateRevoked
			}
		}
	}
	if !found && s.opts.RequireCRL {
		return ua.StatusBadCertificateRevocationUnknown
	}
	return nil
}

func issuerStatus(err error) error {
	switch err {
	case ua.StatusBadCertificateRevoked:
		return ua.StatusBadCertificateIssuerRevoked
	case ua.StatusBadCertificateRevocationUnknown:
		return ua.StatusBadCertificateIssuerRevocationUnknown
	}
	return err
}

// checkUse checks that an application instance certificate may be used
// for signing (OPC 10000-6 §6.2.2).
func checkUse(c *x509.Certificate) error {
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ua.StatusBadCertificateUseNotAllowed
	}
	return nil
}

func hasURI(c *x509.Certificate, uri string) bool {
	for _, u := range c.URIs {
		if u.String() == uri {
			return true
		}
	}
	return false
}

// isSelfSigned reports whether c is signed by its own key. Application
// instance certificates are often self-signed without being CAs, so this
// checks the signature directly rather than with CheckSignatureFrom, which
// requires the signer to be a CA.
func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// Thumbprint returns the hex SHA-1 thumbprint used as a file name.
func Thumbprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func (s *Store) save(dir string, c *x509.Certificate) error {
	// An operator may have removed the directory.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := filepath.Join(dir, certFileName(c))
	return os.WriteFile(name, c.Raw, 0o644)
}

func certFileName(c *x509.Certificate) string {
	cn := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, c.Subject.CommonName)
	if len(cn) > 40 {
		cn = cn[:40]
	}
	return fmt.Sprintf("%s [%s].der", cn, Thumbprint(c))
}

// reject saves c to rejected/certs, keeping at most MaxRejected files.
func (s *Store) reject(c *x509.Certificate) {
	if s.opts.MaxRejected < 0 {
		return
	}
	dir := s.rejectedCerts()
	_ = s.save(dir, c)

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= s.opts.MaxRejected {
		return
	}
	type file struct {
		name string
		mod  time.Time
	}
	var files []file
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !e.IsDir() {
			files = append(files, file{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for len(files) > s.opts.MaxRejected {
		_ = os.Remove(filepath.Join(dir, files[0].name))
		files = files[1:]
	}
}

// Rejected lists the certificates in rejected/certs.
func (s *Store) Rejected() ([]*x509.Certificate, error) {
	return readCertDir(s.rejectedCerts())
}

// Trust moves a certificate from rejected/certs to trusted/certs, or adds
// it there, so that it is accepted from now on.
func (s *Store) Trust(c *x509.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Remove(filepath.Join(s.rejectedCerts(), certFileName(c)))
	if err := s.save(s.trustedCerts(), c); err != nil {
		return err
	}
	return s.reload()
}

// Trusted lists the certificates in trusted/certs.
func (s *Store) Trusted() ([]*x509.Certificate, error) {
	return readCertDir(s.trustedCerts())
}

// Untrust removes a certificate, by its Thumbprint, from trusted/certs.
// A client using it is refused from its next connection on.
func (s *Store) Untrust(thumbprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := removeByThumbprint(s.trustedCerts(), thumbprint); err != nil {
		return err
	}
	return s.reload()
}

// DeleteRejected removes a certificate, by its Thumbprint, from
// rejected/certs. It is listed there again when the client tries again.
func (s *Store) DeleteRejected(thumbprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return removeByThumbprint(s.rejectedCerts(), thumbprint)
}

func removeByThumbprint(dir, thumbprint string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, c := range parseCerts(b) {
			if strings.EqualFold(Thumbprint(c), thumbprint) {
				return os.Remove(p)
			}
		}
	}
	return fmt.Errorf("certs: no certificate %s in %s", thumbprint, dir)
}

func readCertDir(dir string) ([]*x509.Certificate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, parseCerts(b)...)
	}
	return out, nil
}

func parseCerts(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	if bytes.Contains(b, []byte("-----BEGIN")) {
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				out = append(out, c)
			}
		}
		return out
	}
	cs, err := x509.ParseCertificates(b)
	if err != nil {
		return nil
	}
	return cs
}

func readCRLDir(dir string) ([]*x509.RevocationList, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*x509.RevocationList
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if blk, _ := pem.Decode(b); blk != nil {
			b = blk.Bytes
		}
		if crl, err := x509.ParseRevocationList(b); err == nil {
			out = append(out, crl)
		}
	}
	return out, nil
}

// Reload rereads the store's directories.
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reload()
}
