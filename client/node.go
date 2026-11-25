package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/certs"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// NodeInfo describes a node: the attributes an application needs to show
// it or decide what it can do with it. Attributes the node class does not
// have are left zero.
type NodeInfo struct {
	NodeID      string
	NodeClass   ua.NodeClass
	BrowseName  string // "ns:name" for namespaces other than 0
	DisplayName string
	Description string

	// Variables
	DataType                string // e.g. "Double", "Int16", or a node id for other types
	ValueRank               int32  // -1 scalar, 1 one-dimensional array, ...
	AccessLevel             byte   // what the node allows
	UserAccessLevel         byte   // what this session's user may do
	Historizing             bool
	MinimumSamplingInterval float64 // ms

	// Objects and Views
	EventNotifier byte

	// Methods
	Executable     bool
	UserExecutable bool
}

// Access level and event notifier bits (OPC 10000-3 §8.57, §8.59).
const (
	AccessRead          = 0x01
	AccessWrite         = 0x02
	AccessHistoryRead   = 0x04
	NotifierSubscribe   = 0x01
	NotifierHistoryRead = 0x04
)

// CanRead reports whether this session's user may read the value.
func (n NodeInfo) CanRead() bool { return n.UserAccessLevel&AccessRead != 0 }

// CanWrite reports whether this session's user may write the value.
func (n NodeInfo) CanWrite() bool { return n.UserAccessLevel&AccessWrite != 0 }

// HasHistory reports whether the node keeps history: values for a
// variable, events for an object.
func (n NodeInfo) HasHistory() bool {
	return n.UserAccessLevel&AccessHistoryRead != 0 || n.EventNotifier&NotifierHistoryRead != 0
}

// HasEvents reports whether events can be subscribed to on the node.
func (n NodeInfo) HasEvents() bool { return n.EventNotifier&NotifierSubscribe != 0 }

var nodeAttributes = []ua.AttributeID{
	ua.AttributeIDNodeClass, ua.AttributeIDBrowseName, ua.AttributeIDDisplayName, ua.AttributeIDDescription,
	ua.AttributeIDDataType, ua.AttributeIDValueRank, ua.AttributeIDAccessLevel, ua.AttributeIDUserAccessLevel,
	ua.AttributeIDHistorizing, ua.AttributeIDMinimumSamplingInterval, ua.AttributeIDEventNotifier,
	ua.AttributeIDExecutable, ua.AttributeIDUserExecutable,
}

// Attributes reads a node's attributes.
func (c *Client) Attributes(ctx context.Context, nodeID string) (NodeInfo, error) {
	info := NodeInfo{NodeID: nodeID}
	nid, err := c.parse(nodeID)
	if err != nil {
		return info, err
	}
	req := &ua.ReadRequest{}
	for _, a := range nodeAttributes {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: nid, AttributeID: a})
	}
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.c.Read(rctx, req)
	if err != nil {
		return info, fmt.Errorf("client: attributes of %s: %w", nodeID, err)
	}
	if len(resp.Results) != len(nodeAttributes) {
		return info, fmt.Errorf("client: attributes of %s: short response", nodeID)
	}
	if st := resp.Results[0].Status; st != ua.StatusOK {
		return info, fmt.Errorf("client: attributes of %s: %w", nodeID, st)
	}
	for i, a := range nodeAttributes {
		dv := resp.Results[i]
		if dv.Status != ua.StatusOK || dv.Value == nil {
			continue
		}
		v := dv.Value.Value()
		switch a {
		case ua.AttributeIDNodeClass:
			if n, ok := v.(int32); ok {
				info.NodeClass = ua.NodeClass(n)
			}
		case ua.AttributeIDBrowseName:
			if q, ok := v.(*ua.QualifiedName); ok && q != nil {
				info.BrowseName = qualified(q)
			}
		case ua.AttributeIDDisplayName:
			if t, ok := v.(*ua.LocalizedText); ok && t != nil {
				info.DisplayName = t.Text
			}
		case ua.AttributeIDDescription:
			if t, ok := v.(*ua.LocalizedText); ok && t != nil {
				info.Description = t.Text
			}
		case ua.AttributeIDDataType:
			if dt, ok := v.(*ua.NodeID); ok {
				info.DataType = TypeName(dt)
			}
		case ua.AttributeIDValueRank:
			info.ValueRank, _ = v.(int32)
		case ua.AttributeIDAccessLevel:
			info.AccessLevel, _ = v.(byte)
		case ua.AttributeIDUserAccessLevel:
			info.UserAccessLevel, _ = v.(byte)
		case ua.AttributeIDHistorizing:
			info.Historizing, _ = v.(bool)
		case ua.AttributeIDMinimumSamplingInterval:
			info.MinimumSamplingInterval, _ = v.(float64)
		case ua.AttributeIDEventNotifier:
			info.EventNotifier, _ = v.(byte)
		case ua.AttributeIDExecutable:
			info.Executable, _ = v.(bool)
		case ua.AttributeIDUserExecutable:
			info.UserExecutable, _ = v.(bool)
		}
	}
	return info, nil
}

func qualified(q *ua.QualifiedName) string {
	if q.NamespaceIndex == 0 {
		return q.Name
	}
	return fmt.Sprintf("%d:%s", q.NamespaceIndex, q.Name)
}

// TypeName names a DataType node: the built-in type's name for the
// standard types, the node id otherwise.
func TypeName(dt *ua.NodeID) string {
	if dt == nil {
		return ""
	}
	if dt.Namespace() == 0 {
		switch i := dt.IntID(); i {
		case 22:
			return "Structure"
		case 24:
			return "BaseDataType"
		case 26:
			return "Number"
		case 27:
			return "Integer"
		case 28:
			return "UInteger"
		case 29:
			return "Enumeration"
		case 288:
			return "IntegerId"
		case 289:
			return "Counter"
		case 290:
			return "Duration"
		case 294:
			return "UtcTime"
		case 295:
			return "LocaleId"
		default:
			if i >= 1 && i <= 25 {
				return strings.TrimPrefix(ua.TypeID(i).String(), "TypeID")
			}
		}
	}
	return dt.String()
}

// Translate finds the node at a browse path below start, as
// TranslateBrowsePathsToNodeIds does. Each element is a browse name,
// "ns:name" for namespaces other than 0, e.g.
// Translate(ctx, "i=85", "2:Plant", "2:P0000_Temp").
func (c *Client) Translate(ctx context.Context, start string, path ...string) (string, error) {
	nid, err := c.parse(start)
	if err != nil {
		return "", err
	}
	if len(path) == 0 {
		return "", fmt.Errorf("client: translate: empty path")
	}
	rel := &ua.RelativePath{}
	for _, p := range path {
		q, err := parseQualified(p)
		if err != nil {
			return "", err
		}
		rel.Elements = append(rel.Elements, &ua.RelativePathElement{
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true, TargetName: q,
		})
	}
	var resp *ua.TranslateBrowsePathsToNodeIDsResponse
	tctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	err = c.c.Send(tctx, &ua.TranslateBrowsePathsToNodeIDsRequest{
		BrowsePaths: []*ua.BrowsePath{{StartingNode: nid, RelativePath: rel}},
	}, func(r ua.Response) error {
		var ok bool
		if resp, ok = r.(*ua.TranslateBrowsePathsToNodeIDsResponse); !ok {
			return fmt.Errorf("unexpected response %T", r)
		}
		return nil
	})
	what := start + "/" + strings.Join(path, "/")
	if err != nil {
		return "", fmt.Errorf("client: translate %s: %w", what, err)
	}
	if len(resp.Results) != 1 {
		return "", fmt.Errorf("client: translate %s: short response", what)
	}
	res := resp.Results[0]
	if res.StatusCode != ua.StatusOK {
		return "", fmt.Errorf("client: translate %s: %w", what, res.StatusCode)
	}
	if len(res.Targets) == 0 || res.Targets[0].TargetID == nil {
		return "", fmt.Errorf("client: translate %s: %w", what, ua.StatusBadNoMatch)
	}
	return res.Targets[0].TargetID.NodeID.String(), nil
}

func parseQualified(s string) (*ua.QualifiedName, error) {
	if i := strings.IndexByte(s, ':'); i > 0 {
		if ns, err := strconv.ParseUint(s[:i], 10, 16); err == nil {
			return &ua.QualifiedName{NamespaceIndex: uint16(ns), Name: s[i+1:]}, nil
		}
	}
	if s == "" {
		return nil, fmt.Errorf("client: empty browse name")
	}
	return &ua.QualifiedName{Name: s}, nil
}

// ServerStatus is the server's state and build information.
type ServerStatus struct {
	State               string // Running, Failed, NoConfiguration, Suspended, Shutdown, Test, CommunicationFault, Unknown
	StartTime           time.Time
	CurrentTime         time.Time
	ProductName         string
	ProductURI          string
	ManufacturerName    string
	SoftwareVersion     string
	BuildNumber         string
	SecondsTillShutdown uint32
	ShutdownReason      string
}

// ServerStatus reads the server's Server_ServerStatus variable.
func (c *Client) ServerStatus(ctx context.Context) (ServerStatus, error) {
	var st ServerStatus
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.c.Read(rctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: ua.NewNumericNodeID(0, id.Server_ServerStatus), AttributeID: ua.AttributeIDValue},
	}})
	if err != nil {
		return st, fmt.Errorf("client: server status: %w", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].Status != ua.StatusOK || resp.Results[0].Value == nil {
		return st, fmt.Errorf("client: server status: not available")
	}
	eo, ok := resp.Results[0].Value.Value().(*ua.ExtensionObject)
	if !ok || eo == nil {
		return st, fmt.Errorf("client: server status: unexpected value")
	}
	s, ok := eo.Value.(*ua.ServerStatusDataType)
	if !ok || s == nil {
		return st, fmt.Errorf("client: server status: unexpected value")
	}
	st = ServerStatus{State: strings.TrimPrefix(s.State.String(), "ServerState"), StartTime: s.StartTime,
		CurrentTime: s.CurrentTime, SecondsTillShutdown: s.SecondsTillShutdown}
	if b := s.BuildInfo; b != nil {
		st.ProductName, st.ProductURI, st.ManufacturerName = b.ProductName, b.ProductURI, b.ManufacturerName
		st.SoftwareVersion, st.BuildNumber = b.SoftwareVersion, b.BuildNumber
	}
	if s.ShutdownReason != nil {
		st.ShutdownReason = s.ShutdownReason.Text
	}
	return st, nil
}

// Namespaces reads the server's namespace table; a node id's ns=N is the
// N-th entry.
func (c *Client) Namespaces(ctx context.Context) ([]string, error) {
	nctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ns, err := c.c.NamespaceArray(nctx)
	if err != nil {
		return nil, fmt.Errorf("client: namespaces: %w", err)
	}
	return ns, nil
}

// EndpointInfo is one endpoint a server offers.
type EndpointInfo struct {
	URL           string
	Policy        string // e.g. "None", "Basic256Sha256"
	Mode          string // "None", "Sign" or "SignAndEncrypt"
	SecurityLevel byte
	UserTokens    []string // "Anonymous", "UserName", "Certificate", "IssuedToken"
	ServerURI     string
	ServerName    string
	// Thumbprint is the upper-case hex SHA-1 of the server certificate,
	// empty when the endpoint has none.
	Thumbprint string
}

// Endpoints lists a server's endpoints without opening a session, to see
// which security and logins it offers before Dial.
func Endpoints(ctx context.Context, endpoint string, timeout time.Duration) ([]EndpointInfo, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	eps, err := opcua.GetEndpoints(ectx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("client: get endpoints of %s: %w", endpoint, err)
	}
	out := make([]EndpointInfo, 0, len(eps))
	for _, ep := range eps {
		e := EndpointInfo{
			URL:           ep.EndpointURL,
			Policy:        strings.TrimPrefix(ep.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#"),
			Mode:          strings.TrimPrefix(ep.SecurityMode.String(), "MessageSecurityMode"),
			SecurityLevel: ep.SecurityLevel,
		}
		if ep.Server != nil {
			e.ServerURI = ep.Server.ApplicationURI
			if ep.Server.ApplicationName != nil {
				e.ServerName = ep.Server.ApplicationName.Text
			}
		}
		e.Thumbprint = CertThumbprint(ep.ServerCertificate)
		for _, t := range ep.UserIdentityTokens {
			e.UserTokens = append(e.UserTokens, strings.TrimPrefix(t.TokenType.String(), "UserTokenType"))
		}
		out = append(out, e)
	}
	return out, nil
}

// CertThumbprint returns the upper-case hex SHA-1 thumbprint of a DER
// certificate (the first one of a chain), as certs.Thumbprint does; empty
// for no certificate.
func CertThumbprint(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	if c, err := x509.ParseCertificate(der); err == nil {
		return certs.Thumbprint(c)
	}
	if cs, err := x509.ParseCertificates(der); err == nil && len(cs) > 0 {
		return certs.Thumbprint(cs[0])
	}
	return ""
}
