package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ka1hung/opcua/certs"
	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uapolicy"
	"github.com/ka1hung/opcua/uasc"
)

// Option configures a Server.
type Option func(*serverConfig)

type serverConfig struct {
	privateKey     *rsa.PrivateKey
	certificate    []byte
	applicationURI string

	endpoints  []string
	listenAddr string

	applicationName  string
	manufacturerName string
	productName      string
	productURI       string
	softwareVersion  string

	enabledSec  []security
	enabledAuth []ua.UserTokenType

	anonymousReadOnly bool
	lenientWriteTypes bool

	authUser func(ctx context.Context, user, password string) (*Identity, error)
	authCert func(ctx context.Context, cert *x509.Certificate) (*Identity, error)

	trustStore     *certs.Store
	userTrustStore *certs.Store

	helloTimeout time.Duration
	limits       Limits

	logger Logger
}

type security struct {
	secPolicy string
	secMode   ua.MessageSecurityMode
}

func defaultConfig() *serverConfig {
	return &serverConfig{
		applicationName:   "OPC UA Server",
		manufacturerName:  "",
		productName:       "OPC UA Server",
		productURI:        "urn:github.com:ka1hung:opcua:server",
		softwareVersion:   "0.0.0-dev",
		anonymousReadOnly: true,
		lenientWriteTypes: true,
		helloTimeout:      10 * time.Second,
		limits:            DefaultLimits(),
	}
}

// Limits bounds the resources one server, session or request may use.
// Zero values are replaced by the defaults of DefaultLimits.
type Limits struct {
	MaxConnections                   int
	MaxSessions                      int
	MaxSubscriptionsPerSession       int
	MaxMonitoredItemsPerSubscription int
	MaxNodesPerRequest               int
	MaxBrowseContinuationPoints      int
	MaxPublishRequestsPerSession     int
	MaxRetransmissionQueue           int
	MaxQueueSize                     int
	// RequestsPerChannel bounds the requests of one secure channel that are
	// handled at the same time.
	RequestsPerChannel int

	MinPublishingInterval time.Duration
	MinSamplingInterval   time.Duration
	MinSessionTimeout     time.Duration
	MaxSessionTimeout     time.Duration
	// WriteTimeout bounds a write callback; it then answers Bad_Timeout.
	WriteTimeout time.Duration
}

// DefaultLimits returns the limits used for zero fields of Limits.
func DefaultLimits() Limits {
	return Limits{
		MaxConnections:                   100,
		MaxSessions:                      50,
		MaxSubscriptionsPerSession:       10,
		MaxMonitoredItemsPerSubscription: 10000,
		MaxNodesPerRequest:               5000,
		MaxBrowseContinuationPoints:      10,
		MaxPublishRequestsPerSession:     20,
		MaxRetransmissionQueue:           20,
		MaxQueueSize:                     1000,
		RequestsPerChannel:               16,
		MinPublishingInterval:            50 * time.Millisecond,
		MinSamplingInterval:              50 * time.Millisecond,
		MinSessionTimeout:                10 * time.Second,
		MaxSessionTimeout:                time.Hour,
		WriteTimeout:                     5 * time.Second,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	set := func(v *int, def int) {
		if *v <= 0 {
			*v = def
		}
	}
	setD := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	set(&l.MaxConnections, d.MaxConnections)
	set(&l.MaxSessions, d.MaxSessions)
	set(&l.MaxSubscriptionsPerSession, d.MaxSubscriptionsPerSession)
	set(&l.MaxMonitoredItemsPerSubscription, d.MaxMonitoredItemsPerSubscription)
	set(&l.MaxNodesPerRequest, d.MaxNodesPerRequest)
	set(&l.MaxBrowseContinuationPoints, d.MaxBrowseContinuationPoints)
	set(&l.MaxPublishRequestsPerSession, d.MaxPublishRequestsPerSession)
	set(&l.MaxRetransmissionQueue, d.MaxRetransmissionQueue)
	set(&l.MaxQueueSize, d.MaxQueueSize)
	set(&l.RequestsPerChannel, d.RequestsPerChannel)
	setD(&l.MinPublishingInterval, d.MinPublishingInterval)
	setD(&l.MinSamplingInterval, d.MinSamplingInterval)
	setD(&l.MinSessionTimeout, d.MinSessionTimeout)
	setD(&l.MaxSessionTimeout, d.MaxSessionTimeout)
	setD(&l.WriteTimeout, d.WriteTimeout)
	return l
}

// SetLimits sets the server's resource limits; zero fields keep defaults.
func SetLimits(l Limits) Option {
	return func(s *serverConfig) { s.limits = l.withDefaults() }
}

// PrivateKey sets the RSA private key of the server certificate.
func PrivateKey(key *rsa.PrivateKey) Option {
	return func(s *serverConfig) { s.privateKey = key }
}

// Certificate sets the server's application instance certificate (DER).
// The ApplicationURI is taken from its subjectAltName unless set with
// ApplicationURI.
func Certificate(cert []byte) Option {
	return func(s *serverConfig) {
		s.certificate = cert
		if s.applicationURI != "" {
			return
		}
		if c, err := x509.ParseCertificate(cert); err == nil && len(c.URIs) > 0 {
			s.applicationURI = c.URIs[0].String()
		}
	}
}

// ApplicationURI sets the server's ApplicationUri. It must match the URI
// in the server certificate.
func ApplicationURI(uri string) Option {
	return func(s *serverConfig) { s.applicationURI = uri }
}

// EndPoint adds an endpoint URL opc.tcp://host:port. The server listens on
// the port of the first endpoint on all interfaces.
func EndPoint(host string, port int) Option {
	return func(s *serverConfig) {
		u := &url.URL{Scheme: "opc.tcp", Host: fmt.Sprintf("%s:%d", host, port)}
		s.endpoints = append(s.endpoints, u.String())
	}
}

// EnableSecurity offers a security policy (full URI or short name such as
// "Basic256Sha256") with a security mode. A client can open a session only
// with an offered pair.
func EnableSecurity(secPolicy string, secMode ua.MessageSecurityMode) Option {
	return func(s *serverConfig) {
		if !strings.HasPrefix(secPolicy, "http://opcfoundation.org/UA/SecurityPolicy#") {
			secPolicy = "http://opcfoundation.org/UA/SecurityPolicy#" + secPolicy
		}
		supported := false
		for _, sp := range uapolicy.SupportedPolicies() {
			if sp == secPolicy {
				supported = true
			}
		}
		if !supported {
			return
		}
		for _, sec := range s.enabledSec {
			if sec.secPolicy == secPolicy && sec.secMode == secMode {
				return
			}
		}
		s.enabledSec = append(s.enabledSec, security{secPolicy: secPolicy, secMode: secMode})
	}
}

// EnableAuthMode offers a user token type: Anonymous, UserName or
// Certificate. UserName needs UserNameAuthenticator and Certificate needs
// CertificateAuthenticator; without them such tokens are rejected.
func EnableAuthMode(tokenType ua.UserTokenType) Option {
	return func(s *serverConfig) {
		for _, t := range s.enabledAuth {
			if t == tokenType {
				return
			}
		}
		s.enabledAuth = append(s.enabledAuth, tokenType)
	}
}

// AnonymousReadOnly makes anonymous users read-only (the default): they
// can browse, read and subscribe, but not write, call methods or
// acknowledge alarms.
func AnonymousReadOnly(readOnly bool) Option {
	return func(s *serverConfig) { s.anonymousReadOnly = readOnly }
}

// LenientWriteTypes makes the server accept a write whose value is another
// numeric type or Boolean than the variable's DataType and convert it, as
// many SCADA systems write every number as Double (the default). With
// false, a type mismatch answers Bad_TypeMismatch as the standard says.
func LenientWriteTypes(lenient bool) Option {
	return func(s *serverConfig) { s.lenientWriteTypes = lenient }
}

// UserNameAuthenticator checks user names and passwords. It returns the
// user's identity, or an error to reject the user (Bad_UserAccessDenied,
// or the ua.StatusCode it returns).
func UserNameAuthenticator(f func(ctx context.Context, user, password string) (*Identity, error)) Option {
	return func(s *serverConfig) { s.authUser = f }
}

// CertificateAuthenticator maps a user certificate, already validated
// against the user trust store, to an identity.
func CertificateAuthenticator(f func(ctx context.Context, cert *x509.Certificate) (*Identity, error)) Option {
	return func(s *serverConfig) { s.authCert = f }
}

// TrustStore validates client application certificates when a secure
// channel is opened and when a session is created. Without it, every
// client certificate is accepted.
func TrustStore(store *certs.Store) Option {
	return func(s *serverConfig) { s.trustStore = store }
}

// UserTrustStore validates user certificates of X509 identity tokens.
// Defaults to the TrustStore.
func UserTrustStore(store *certs.Store) Option {
	return func(s *serverConfig) { s.userTrustStore = store }
}

// ServerName sets the ApplicationName.
func ServerName(name string) Option {
	return func(s *serverConfig) { s.applicationName = name }
}

// ManufacturerName sets the BuildInfo ManufacturerName.
func ManufacturerName(name string) Option {
	return func(s *serverConfig) { s.manufacturerName = name }
}

// ProductName sets the BuildInfo ProductName.
func ProductName(name string) Option {
	return func(s *serverConfig) { s.productName = name }
}

// ProductURI sets the ProductUri.
func ProductURI(uri string) Option {
	return func(s *serverConfig) { s.productURI = uri }
}

// SoftwareVersion sets the BuildInfo SoftwareVersion.
func SoftwareVersion(v string) Option {
	return func(s *serverConfig) { s.softwareVersion = v }
}

// HelloTimeout bounds how long a new connection may take to send its Hello
// message. Values <= 0 keep the default of 10 seconds.
func HelloTimeout(d time.Duration) Option {
	return func(s *serverConfig) {
		if d > 0 {
			s.helloTimeout = d
		}
	}
}

// Logger is the logging interface of the server; *slog.Logger implements
// it.
type Logger interface {
	Debug(msg string, args ...any)
	Error(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// SetLogger sets the logger. Messages use slog-style key/value arguments.
func SetLogger(l Logger) Option {
	return func(s *serverConfig) { s.logger = l }
}

func defaultChannelConfig() *uasc.Config {
	return &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
	}
}
