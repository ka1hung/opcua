// Package client is a high-level OPC UA client for applications that read,
// write and subscribe to a server's variables: secure endpoint selection
// that never falls back to no security, per-item results, typed writes,
// and connection state events. It wraps the opcua package.
package client

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/certs"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// MinSecurity is the lowest message security Auto accepts.
type MinSecurity int

const (
	// MinSign accepts Sign or SignAndEncrypt.
	MinSign MinSecurity = iota
	// MinSignAndEncrypt accepts SignAndEncrypt only.
	MinSignAndEncrypt
)

// Security chooses the endpoint security.
type Security struct {
	kind   int // 0 auto, 1 explicit, 2 none
	min    MinSecurity
	policy string
	mode   ua.MessageSecurityMode
}

// Auto picks the endpoint with the highest security level that is at least
// min. Without such an endpoint Dial fails; it never falls back to no
// security.
func Auto(min MinSecurity) Security { return Security{kind: 0, min: min} }

// Explicit picks the endpoint with this policy ("Basic256Sha256" or a full
// URI) and mode ("Sign" or "SignAndEncrypt").
func Explicit(policy, mode string) Security {
	if len(policy) > 0 && policy[0] != 'h' {
		policy = "http://opcfoundation.org/UA/SecurityPolicy#" + policy
	}
	m := ua.MessageSecurityModeInvalid
	switch mode {
	case "Sign":
		m = ua.MessageSecurityModeSign
	case "SignAndEncrypt":
		m = ua.MessageSecurityModeSignAndEncrypt
	case "None":
		m = ua.MessageSecurityModeNone
	}
	return Security{kind: 1, policy: policy, mode: m}
}

// NoSecurity connects without security. It must be asked for explicitly.
func NoSecurity() Security { return Security{kind: 2} }

// Auth is the user identity.
type Auth struct {
	tokenType ua.UserTokenType
	user      string
	password  string
	cert      []byte
	key       *rsa.PrivateKey
}

// Anonymous logs in without a user.
func Anonymous() Auth { return Auth{tokenType: ua.UserTokenTypeAnonymous} }

// UserPass logs in with a user name and password.
func UserPass(user, password string) Auth {
	return Auth{tokenType: ua.UserTokenTypeUserName, user: user, password: password}
}

// Cert logs in with a user certificate (DER) and its key.
func Cert(cert []byte, key *rsa.PrivateKey) Auth {
	return Auth{tokenType: ua.UserTokenTypeCertificate, cert: cert, key: key}
}

// Options configures Dial.
type Options struct {
	Security Security
	Auth     Auth
	// Timeout bounds connecting and each request; default 5 s.
	Timeout time.Duration

	// Certificate and Key identify this application for secured
	// endpoints. Without them Dial creates a self-signed certificate for
	// ApplicationURI.
	Certificate []byte
	Key         *rsa.PrivateKey
	// ApplicationURI of this client; default "urn:opcua:client".
	ApplicationURI string
	// ApplicationName the server shows for this client, e.g. in its list of
	// sessions; default "opcua client".
	ApplicationName string
	// TrustStore validates the server certificate. Without it any server
	// certificate is accepted.
	TrustStore *certs.Store
	// VerifyServer, if set, is called with the server certificate (DER)
	// of a secured endpoint before connecting; an error refuses the
	// server. Use it to pin a certificate seen before (trust on first use).
	VerifyServer func(cert []byte) error

	// Reconnect makes the client reconnect after a connection loss and
	// restore its subscriptions (default true; set NoReconnect to disable).
	NoReconnect bool
}

// ConnState is the connection state.
type ConnState = opcua.ConnState

// Connection states.
const (
	Closed       = opcua.Closed
	Connected    = opcua.Connected
	Connecting   = opcua.Connecting
	Disconnected = opcua.Disconnected
	Reconnecting = opcua.Reconnecting
)

// Client is a connection to one server.
type Client struct {
	c       *opcua.Client
	ep      *ua.EndpointDescription
	timeout time.Duration
	state   chan ConnState

	mu         sync.Mutex
	types      map[string]typeInfo
	methods    map[string]methodArgs
	maxRead    int
	maxWrite   int
	maxMonitor int
	ns         []string // namespace table, for nsu= node ids
	nsRead     time.Time
	closeOnce  sync.Once
}

type typeInfo struct {
	builtin ua.TypeID
	rank    int32
}

var errNoEndpoint = errors.New("client: no endpoint matches the requested security")

// Dial connects to the server at endpoint (opc.tcp://host:port).
func Dial(ctx context.Context, endpoint string, o Options) (*Client, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.ApplicationURI == "" {
		o.ApplicationURI = "urn:opcua:client"
	}
	if o.Auth.tokenType == 0 && o.Auth.user == "" && o.Auth.cert == nil {
		o.Auth = Anonymous()
	}

	dctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	eps, err := opcua.GetEndpoints(dctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("client: get endpoints of %s: %w", endpoint, err)
	}
	ep, err := pickEndpoint(eps, o.Security, o.Auth.tokenType)
	if err != nil {
		return nil, err
	}

	opts := []opcua.Option{
		opcua.RequestTimeout(o.Timeout),
		opcua.DialTimeout(o.Timeout),
		opcua.AutoReconnect(!o.NoReconnect),
		opcua.ApplicationURI(o.ApplicationURI),
	}
	if o.ApplicationName != "" {
		opts = append(opts, opcua.ApplicationName(o.ApplicationName))
	}
	if ep.SecurityPolicyURI != ua.SecurityPolicyURINone {
		if o.TrustStore != nil {
			if err := o.TrustStore.Validate(ep.ServerCertificate, ep.Server.ApplicationURI); err != nil {
				return nil, fmt.Errorf("client: server certificate: %w", err)
			}
		}
		if o.VerifyServer != nil {
			if err := o.VerifyServer(ep.ServerCertificate); err != nil {
				return nil, fmt.Errorf("client: server certificate: %w", err)
			}
		}
		cert, key := o.Certificate, o.Key
		if cert == nil || key == nil {
			host, _ := os.Hostname()
			cert, key, err = certs.NewSelfSigned(certs.Spec{ApplicationURI: o.ApplicationURI, Hosts: []string{host}})
			if err != nil {
				return nil, fmt.Errorf("client: create certificate: %w", err)
			}
		}
		opts = append(opts, opcua.Certificate(cert), opcua.PrivateKey(key))
	}
	switch o.Auth.tokenType {
	case ua.UserTokenTypeUserName:
		opts = append(opts, opcua.AuthUsername(o.Auth.user, o.Auth.password))
	case ua.UserTokenTypeCertificate:
		opts = append(opts, opcua.AuthCertificate(o.Auth.cert), opcua.AuthPrivateKey(o.Auth.key))
	default:
		opts = append(opts, opcua.AuthAnonymous())
	}
	opts = append(opts, opcua.SecurityFromEndpoint(ep, o.Auth.tokenType))

	cl := &Client{timeout: o.Timeout, state: make(chan ConnState, 16), types: map[string]typeInfo{}, methods: map[string]methodArgs{}}
	opts = append(opts, opcua.StateChangedFunc(func(s opcua.ConnState) {
		select {
		case cl.state <- s:
		default: // a slow reader misses intermediate states, never blocks the client
		}
	}))
	url := connectURL(endpoint, ep.EndpointURL)
	c, err := opcua.NewClient(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	if err := c.Connect(dctx); err != nil {
		_ = c.Close(context.Background())
		return nil, fmt.Errorf("client: connect to %s: %w", url, err)
	}
	cl.c = c
	cl.ep = ep
	cl.readLimits(ctx)
	_ = cl.loadNamespaces(ctx)
	return cl, nil
}

// connectURL is where to open the session: the endpoint the server
// advertises, but at the host the caller dialled. Servers often advertise
// their own host name, which the client cannot resolve (OPC 10000-4
// §5.4.4 lets clients substitute the host they used for discovery); the
// advertised port and path are kept, since a discovery endpoint may point
// to another port.
func connectURL(dialled, advertised string) string {
	d, err1 := url.Parse(dialled)
	a, err2 := url.Parse(advertised)
	if err1 != nil || err2 != nil || d.Hostname() == "" || a.Hostname() == "" {
		return dialled
	}
	port := a.Port()
	if port == "" {
		port = d.Port()
	}
	a.Host = net.JoinHostPort(d.Hostname(), port)
	if port == "" {
		a.Host = d.Hostname()
	}
	return a.String()
}

// pickEndpoint chooses an endpoint for the security and user token type.
func pickEndpoint(eps []*ua.EndpointDescription, sec Security, tok ua.UserTokenType) (*ua.EndpointDescription, error) {
	offers := func(ep *ua.EndpointDescription) bool {
		for _, p := range ep.UserIdentityTokens {
			if p.TokenType == tok {
				return true
			}
		}
		return false
	}
	var cands []*ua.EndpointDescription
	for _, ep := range eps {
		if !offers(ep) {
			continue
		}
		switch sec.kind {
		case 0: // auto
			if ep.SecurityMode == ua.MessageSecurityModeSignAndEncrypt ||
				ep.SecurityMode == ua.MessageSecurityModeSign && sec.min == MinSign {
				cands = append(cands, ep)
			}
		case 1:
			if ep.SecurityPolicyURI == sec.policy && ep.SecurityMode == sec.mode {
				cands = append(cands, ep)
			}
		case 2:
			if ep.SecurityPolicyURI == ua.SecurityPolicyURINone && ep.SecurityMode == ua.MessageSecurityModeNone {
				cands = append(cands, ep)
			}
		}
	}
	if len(cands) == 0 {
		return nil, errNoEndpoint
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].SecurityLevel > cands[j].SecurityLevel })
	return cands[0], nil
}

// readLimits reads the server's operation limits to split large requests.
func (c *Client) readLimits(ctx context.Context) {
	c.maxRead, c.maxWrite, c.maxMonitor = 1000, 1000, 1000
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: ua.NewNumericNodeID(0, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead), AttributeID: ua.AttributeIDValue},
		{NodeID: ua.NewNumericNodeID(0, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite), AttributeID: ua.AttributeIDValue},
		{NodeID: ua.NewNumericNodeID(0, id.Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall), AttributeID: ua.AttributeIDValue},
	}})
	if err != nil || len(resp.Results) != 3 {
		return
	}
	for i, dst := range []*int{&c.maxRead, &c.maxWrite, &c.maxMonitor} {
		if v := resp.Results[i]; v.Status == ua.StatusOK && v.Value != nil {
			if n, ok := v.Value.Value().(uint32); ok && n > 0 && n < uint32(*dst) {
				*dst = int(n)
			}
		}
	}
}

// Endpoint returns the endpoint the client connected to.
func (c *Client) Endpoint() *ua.EndpointDescription { return c.ep }

// State reports connection state changes: disconnects and reconnects.
func (c *Client) State() <-chan ConnState { return c.state }

// Close closes the connection.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
		err = c.c.Close(ctx)
	})
	return err
}

// Underlying returns the opcua client for what this package does not cover.
func (c *Client) Underlying() *opcua.Client { return c.c }

// parse parses a node id without panicking.
// parse parses a node id, also in the form nsu=<namespace URI>;<id>,
// which stays valid when the server's namespace table changes order.
func (c *Client) parse(s string) (*ua.NodeID, error) {
	if !strings.HasPrefix(s, "nsu=") {
		return parse(s)
	}
	uri, rest, ok := strings.Cut(s[4:], ";")
	if !ok {
		return nil, fmt.Errorf("client: node id %q: %w", s, ua.StatusBadNodeIDInvalid)
	}
	idx, found := c.nsIndex(uri)
	c.mu.Lock()
	stale := time.Since(c.nsRead) > 10*time.Second
	if stale {
		c.nsRead = time.Now() // also when the read fails: do not ask for every node
	}
	c.mu.Unlock()
	if !found && stale {
		// The table may have grown since it was read; at most every 10 s.
		if err := c.loadNamespaces(context.Background()); err == nil {
			idx, found = c.nsIndex(uri)
		}
	}
	if !found {
		return nil, fmt.Errorf("client: node id %q: namespace not on the server: %w", s, ua.StatusBadNodeIDUnknown)
	}
	return parse(fmt.Sprintf("ns=%d;%s", idx, rest))
}

func (c *Client) nsIndex(uri string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, u := range c.ns {
		if u == uri {
			return i, true
		}
	}
	return 0, false
}

func (c *Client) loadNamespaces(ctx context.Context) error {
	ns, err := c.Namespaces(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.ns, c.nsRead = ns, time.Now()
	c.mu.Unlock()
	return nil
}

// NSU returns nodeID in the form nsu=<namespace URI>;<id>, which does not
// depend on the order of the server's namespace table. Node ids of
// namespace 0, already in that form, or of an unknown namespace are
// returned unchanged.
func (c *Client) NSU(nodeID string) string {
	nid, err := ua.ParseNodeID(nodeID)
	if err != nil || nid.Namespace() == 0 {
		return nodeID
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if int(nid.Namespace()) >= len(c.ns) {
		return nodeID
	}
	full := nid.String()
	_, rest, ok := strings.Cut(full, ";")
	if !ok {
		return nodeID
	}
	return "nsu=" + c.ns[nid.Namespace()] + ";" + rest
}

func parse(s string) (*ua.NodeID, error) {
	nid, err := ua.ParseNodeID(s)
	if err != nil {
		return nil, fmt.Errorf("client: node id %q: %w", s, err)
	}
	return nid, nil
}

// Result is the outcome for one node.
type Result struct {
	NodeID     string
	Value      any
	Status     ua.StatusCode
	SourceTime time.Time
	ServerTime time.Time
	// Err is set when the node id is malformed or the request failed;
	// Status then is a Bad code.
	Err error
}

// Good reports whether the value is usable.
func (r Result) Good() bool { return r.Err == nil && uint32(r.Status)&0xC0000000 == 0 }

// ReadMany reads the values of nodes. Each node has its own result; a
// malformed or unknown node id does not affect the others.
func (c *Client) ReadMany(ctx context.Context, ids []string) []Result {
	results := make([]Result, len(ids))
	var reqs []*ua.ReadValueID
	var idx []int
	for i, s := range ids {
		results[i].NodeID = s
		nid, err := c.parse(s)
		if err != nil {
			results[i].Err, results[i].Status = err, ua.StatusBadNodeIDInvalid
			continue
		}
		reqs = append(reqs, &ua.ReadValueID{NodeID: nid, AttributeID: ua.AttributeIDValue})
		idx = append(idx, i)
	}
	for start := 0; start < len(reqs); start += c.maxRead {
		end := min(start+c.maxRead, len(reqs))
		rctx, cancel := context.WithTimeout(ctx, c.timeout)
		resp, err := c.c.Read(rctx, &ua.ReadRequest{NodesToRead: reqs[start:end], TimestampsToReturn: ua.TimestampsToReturnBoth})
		cancel()
		for k := start; k < end; k++ {
			r := &results[idx[k]]
			switch {
			case err != nil:
				r.Err, r.Status = err, statusOf(err)
			case k-start >= len(resp.Results):
				r.Err, r.Status = errors.New("client: short read response"), ua.StatusBadUnexpectedError
			default:
				dv := resp.Results[k-start]
				r.Status, r.SourceTime, r.ServerTime = dv.Status, dv.SourceTimestamp, dv.ServerTimestamp
				if dv.Value != nil {
					r.Value = dv.Value.Value()
				}
			}
		}
	}
	return results
}

func statusOf(err error) ua.StatusCode {
	var sc ua.StatusCode
	if errors.As(err, &sc) {
		return sc
	}
	return ua.StatusBadCommunicationError
}

// WriteAuto writes value to a variable, converted to the variable's
// DataType, which is read once and cached. The returned error wraps the
// server's status code when the write is refused.
func (c *Client) WriteAuto(ctx context.Context, nodeID string, value any) error {
	nid, err := c.parse(nodeID)
	if err != nil {
		return err
	}
	v, err := c.convert(ctx, nid, value)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.c.Write(wctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID: nid, AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v},
	}}})
	if err != nil {
		return fmt.Errorf("client: write %s: %w", nodeID, err)
	}
	if len(resp.Results) != 1 {
		return fmt.Errorf("client: write %s: short response", nodeID)
	}
	if st := resp.Results[0]; st != ua.StatusOK {
		return fmt.Errorf("client: write %s: %w", nodeID, st)
	}
	return nil
}

// convert converts value to the variable's built-in type.
func (c *Client) convert(ctx context.Context, nid *ua.NodeID, value any) (*ua.Variant, error) {
	ti, err := c.typeOf(ctx, nid)
	if err != nil {
		return nil, err
	}
	if ti.builtin == 0 {
		// An abstract DataType: use the type of the current value.
		rs := c.ReadMany(ctx, []string{nid.String()})
		if rs[0].Err != nil || rs[0].Value == nil {
			return nil, fmt.Errorf("client: %s: cannot tell the value type", nid)
		}
		vv, err := ua.NewVariant(rs[0].Value)
		if err != nil {
			return nil, err
		}
		ti.builtin = vv.Type()
	}
	out, err := toBuiltin(value, ti.builtin)
	if err != nil {
		return nil, fmt.Errorf("client: %s: %w", nid, err)
	}
	return ua.NewVariant(out)
}

// typeOf reads and caches a variable's DataType as a built-in type.
func (c *Client) typeOf(ctx context.Context, nid *ua.NodeID) (typeInfo, error) {
	k := nid.String()
	c.mu.Lock()
	ti, ok := c.types[k]
	c.mu.Unlock()
	if ok {
		return ti, nil
	}
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.c.Read(rctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: nid, AttributeID: ua.AttributeIDDataType},
		{NodeID: nid, AttributeID: ua.AttributeIDValueRank},
	}})
	if err != nil {
		return ti, fmt.Errorf("client: read type of %s: %w", nid, err)
	}
	if len(resp.Results) != 2 || resp.Results[0].Status != ua.StatusOK {
		st := ua.StatusBadNodeIDUnknown
		if len(resp.Results) > 0 {
			st = resp.Results[0].Status
		}
		return ti, fmt.Errorf("client: read type of %s: %w", nid, st)
	}
	dt, _ := resp.Results[0].Value.Value().(*ua.NodeID)
	ti.rank = -1
	if r, ok := resp.Results[1].Value.Value().(int32); ok {
		ti.rank = r
	}
	if dt != nil && dt.Namespace() == 0 {
		switch i := dt.IntID(); {
		case i >= 1 && i <= 25 && i != 24:
			ti.builtin = ua.TypeID(i)
		case i == 290: // Duration
			ti.builtin = ua.TypeIDDouble
		case i == 294: // UtcTime
			ti.builtin = ua.TypeIDDateTime
		case i == 289 || i == 288: // Counter, IntegerId
			ti.builtin = ua.TypeIDUint32
		}
	}
	c.mu.Lock()
	c.types[k] = ti
	c.mu.Unlock()
	return ti, nil
}

// Browse lists the nodes a node references hierarchically, following
// continuation points.
func (c *Client) Browse(ctx context.Context, nodeID string) ([]BrowseItem, error) {
	nid, err := c.parse(nodeID)
	if err != nil {
		return nil, err
	}
	bctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.c.Browse(bctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: nid, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
		NodeClassMask: 0, ResultMask: 0x3f,
	}}})
	if err != nil {
		return nil, fmt.Errorf("client: browse %s: %w", nodeID, err)
	}
	if len(resp.Results) != 1 {
		return nil, fmt.Errorf("client: browse %s: short response", nodeID)
	}
	res := resp.Results[0]
	var out []BrowseItem
	for {
		if res.StatusCode != ua.StatusOK {
			return out, fmt.Errorf("client: browse %s: %w", nodeID, res.StatusCode)
		}
		for _, r := range res.References {
			out = append(out, BrowseItem{
				NodeID:      r.NodeID.NodeID.String(),
				BrowseName:  r.BrowseName.Name,
				DisplayName: r.DisplayName.Text,
				NodeClass:   r.NodeClass,
			})
		}
		if len(res.ContinuationPoint) == 0 {
			return out, nil
		}
		next, err := c.c.BrowseNext(bctx, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{res.ContinuationPoint}})
		if err != nil {
			return out, fmt.Errorf("client: browse %s: %w", nodeID, err)
		}
		if len(next.Results) != 1 {
			return out, fmt.Errorf("client: browse %s: short response", nodeID)
		}
		res = next.Results[0]
	}
}

// BrowseItem is one node found by Browse.
type BrowseItem struct {
	NodeID      string
	BrowseName  string
	DisplayName string
	NodeClass   ua.NodeClass
}

var _ = x509.ParseCertificate
