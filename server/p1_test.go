package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

type fixture struct {
	srv  *server.Server
	ep   string
	cert []byte
	ns   uint16
}

// newFixture starts a server with None and Basic256Sha256/SignAndEncrypt,
// anonymous and user name login (admin/secret may write; viewer/view may
// not), and namespace 2 "urn:test:points" with a few variables.
func newFixture(t *testing.T, opts ...server.Option) *fixture {
	t.Helper()
	cert, key := testCert(t, "urn:test:server")
	port := freePort(t)
	base := []server.Option{
		server.Certificate(cert),
		server.PrivateKey(key),
		server.EndPoint("127.0.0.1", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.UserNameAuthenticator(func(ctx context.Context, user, pass string) (*server.Identity, error) {
			switch {
			case user == "admin" && pass == "secret":
				return &server.Identity{Roles: []string{"admin"}}, nil
			case user == "viewer" && pass == "view":
				return &server.Identity{Roles: []string{"viewer"}}, nil
			}
			return nil, errors.New("bad password")
		}),
	}
	srv := server.New(append(base, opts...)...)
	ns := srv.AddNamespace("urn:test:points")

	isAdmin := func(who *server.Identity) bool {
		return len(who.Roles) > 0 && who.Roles[0] == "admin"
	}
	folder, err := srv.AddFolder(server.ObjectsFolder, ua.NewStringNodeID(ns, "Points"), "Points")
	require.NoError(t, err)
	_, err = srv.AddVariable(folder.ID(), server.VariableSpec{
		NodeID: ua.NewStringNodeID(ns, "Temp"), BrowseName: "Temp",
		DataType: ua.TypeIDDouble, Writable: true, Unit: "°C", EURange: &server.Range{Low: 0, High: 100},
		CanWrite: isAdmin, Value: 21.5,
	})
	require.NoError(t, err)
	_, err = srv.AddVariable(folder.ID(), server.VariableSpec{
		NodeID: ua.NewStringNodeID(ns, "Count"), BrowseName: "Count",
		DataType: ua.TypeIDInt16, Writable: true, CanWrite: isAdmin, Value: int16(1),
	})
	require.NoError(t, err)
	_, err = srv.AddVariable(folder.ID(), server.VariableSpec{
		NodeID: ua.NewStringNodeID(ns, "ReadOnly"), BrowseName: "ReadOnly",
		DataType: ua.TypeIDBoolean, Value: true,
	})
	require.NoError(t, err)
	_, err = srv.AddVariable(folder.ID(), server.VariableSpec{
		NodeID: ua.NewStringNodeID(ns, "NoUnit"), BrowseName: "NoUnit",
		DataType: ua.TypeIDDouble, Value: 1.0,
	})
	require.NoError(t, err)

	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return &fixture{srv: srv, ep: endpointURL(port), cert: cert, ns: ns}
}

// client connects with the endpoint of the given policy and a user.
func (f *fixture) client(t *testing.T, policy string, user, pass string) (*opcua.Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, f.ep)
	require.NoError(t, err)
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityPolicyURI == policy {
			ep = e
		}
	}
	require.NotNil(t, ep, "endpoint %s", policy)

	authType := ua.UserTokenTypeAnonymous
	opts := []opcua.Option{opcua.AutoReconnect(false)}
	if user != "" {
		authType = ua.UserTokenTypeUserName
		opts = append(opts, opcua.AuthUsername(user, pass))
	}
	opts = append(opts, opcua.SecurityFromEndpoint(ep, authType))
	if policy != ua.SecurityPolicyURINone {
		cert, key := testCert(t, "urn:test:client")
		opts = append(opts, opcua.Certificate(cert), opcua.PrivateKey(key), opcua.ApplicationURI("urn:test:client"))
	}
	c, err := opcua.NewClient(ep.EndpointURL, opts...)
	require.NoError(t, err)
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, nil
}

func (f *fixture) anon(t *testing.T) *opcua.Client {
	c, err := f.client(t, ua.SecurityPolicyURINone, "", "")
	require.NoError(t, err)
	return c
}

func (f *fixture) id(name string) *ua.NodeID { return ua.NewStringNodeID(f.ns, name) }

func write(t *testing.T, c *opcua.Client, nid *ua.NodeID, v any) ua.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID: nid, AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
	}}})
	require.NoError(t, err)
	return resp.Results[0]
}

func read(t *testing.T, c *opcua.Client, nid *ua.NodeID) *ua.DataValue {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: nid, AttributeID: ua.AttributeIDValue}}})
	require.NoError(t, err)
	return resp.Results[0]
}

// The first namespace an application adds is 2, so existing NodeIds
// ns=2;s=<point> keep working (§5.1).
func TestNamespaceIndexIsFixed(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, uint16(2), f.ns)
	c := f.anon(t)
	nsa, err := c.NamespaceArray(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"http://opcfoundation.org/UA/", "urn:test:server", "urn:test:points"}, nsa)
}

func TestReadValuesAndBadIDs(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)
	ctx := context.Background()
	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead: []*ua.ReadValueID{
			{NodeID: f.id("Temp"), AttributeID: ua.AttributeIDValue},
			{NodeID: f.id("Missing"), AttributeID: ua.AttributeIDValue},
			{NodeID: f.id("Temp"), AttributeID: ua.AttributeIDDisplayName},
			{NodeID: f.id("Temp"), AttributeID: ua.AttributeIDEventNotifier},
			{NodeID: ua.NewNumericNodeID(0, id.Server_ServerStatus_State), AttributeID: ua.AttributeIDValue},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 21.5, resp.Results[0].Value.Value())
	require.False(t, resp.Results[0].SourceTimestamp.IsZero())
	require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[1].Status)
	require.Equal(t, "Temp", resp.Results[2].Value.LocalizedText().Text)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, resp.Results[3].Status)
	require.Equal(t, int32(ua.ServerStateRunning), resp.Results[4].Value.Value())
}

func TestBrowseAndTranslate(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)
	ctx := context.Background()

	refs, err := c.Node(server.ObjectsFolder).ReferencedNodes(ctx, id.Organizes, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	found := false
	for _, r := range refs {
		if r.ID.String() == f.id("Points").String() {
			found = true
		}
	}
	require.True(t, found, "Points is organized by Objects")

	// A small page size makes the server use continuation points.
	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		RequestedMaxReferencesPerNode: 2,
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: f.id("Points"), BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
			ResultMask: 0x3f,
		}},
	})
	require.NoError(t, err)
	got := len(resp.Results[0].References)
	cp := resp.Results[0].ContinuationPoint
	require.Equal(t, 2, got)
	require.NotEmpty(t, cp)
	for cp != nil {
		next, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{cp}})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, next.Results[0].StatusCode)
		got += len(next.Results[0].References)
		cp = next.Results[0].ContinuationPoint
	}
	require.Equal(t, 4, got)

	var trResp *ua.TranslateBrowsePathsToNodeIDsResponse
	require.NoError(t, c.Send(ctx, &ua.TranslateBrowsePathsToNodeIDsRequest{BrowsePaths: []*ua.BrowsePath{{
		StartingNode: server.ObjectsFolder,
		RelativePath: &ua.RelativePath{Elements: []*ua.RelativePathElement{
			{TargetName: &ua.QualifiedName{NamespaceIndex: f.ns, Name: "Points"}},
			{TargetName: &ua.QualifiedName{NamespaceIndex: f.ns, Name: "Temp"}},
			{TargetName: &ua.QualifiedName{Name: "EURange"}},
		}},
	}}}, func(r ua.Response) error {
		trResp = r.(*ua.TranslateBrowsePathsToNodeIDsResponse)
		return nil
	}))
	require.Equal(t, ua.StatusOK, trResp.Results[0].StatusCode)
	require.Equal(t, "ns=2;s=Temp.EURange", trResp.Results[0].Targets[0].TargetID.NodeID.String())
}

func TestWritePermissionsAndTypes(t *testing.T) {
	f := newFixture(t)
	var seen []string
	f.srv.OnWrite(func(ctx context.Context, who *server.Identity, nid *ua.NodeID, v *ua.Variant) ua.StatusCode {
		seen = append(seen, who.UserName+":"+nid.String())
		if v.Type() == ua.TypeIDDouble && v.Float() == 99 {
			return ua.StatusBadOutOfRange // the device refused it
		}
		return ua.StatusOK
	})

	anon := f.anon(t)
	require.Equal(t, ua.StatusBadUserAccessDenied, write(t, anon, f.id("Temp"), 30.0), "anonymous is read-only")

	viewer, err := f.client(t, ua.SecurityPolicyURINone, "viewer", "view")
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadUserAccessDenied, write(t, viewer, f.id("Temp"), 30.0), "CanWrite denies viewer")

	admin, err := f.client(t, ua.SecurityPolicyURIBasic256Sha256, "admin", "secret")
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, write(t, admin, f.id("Temp"), 30.0))
	require.Equal(t, 30.0, read(t, anon, f.id("Temp")).Value.Value())
	require.Equal(t, []string{"admin:ns=2;s=Temp"}, seen)

	require.Equal(t, ua.StatusBadOutOfRange, write(t, admin, f.id("Temp"), 99.0), "callback result is returned")
	require.Equal(t, 30.0, read(t, anon, f.id("Temp")).Value.Value(), "a refused write is not stored")

	// SCADA systems often write Double to an Int16 variable.
	require.Equal(t, ua.StatusOK, write(t, admin, f.id("Count"), 7.0))
	require.Equal(t, int16(7), read(t, anon, f.id("Count")).Value.Value())
	require.Equal(t, ua.StatusBadOutOfRange, write(t, admin, f.id("Count"), 70000.0))
	require.Equal(t, ua.StatusBadTypeMismatch, write(t, admin, f.id("Count"), 1.5))
	require.Equal(t, ua.StatusBadTypeMismatch, write(t, admin, f.id("Count"), "x"))
	require.Equal(t, ua.StatusBadNotWritable, write(t, admin, f.id("ReadOnly"), false))
	require.Equal(t, ua.StatusBadNodeIDUnknown, write(t, admin, f.id("Missing"), 1.0))
}

func TestWriteTimeout(t *testing.T) {
	f := newFixture(t, server.SetLimits(server.Limits{WriteTimeout: 200 * time.Millisecond}))
	f.srv.OnWrite(func(ctx context.Context, who *server.Identity, nid *ua.NodeID, v *ua.Variant) ua.StatusCode {
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		return ua.StatusOK
	})
	admin, err := f.client(t, ua.SecurityPolicyURINone, "admin", "secret")
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadTimeout, write(t, admin, f.id("Temp"), 1.0))
}

func TestUserNameLogin(t *testing.T) {
	f := newFixture(t)
	for _, policy := range []string{ua.SecurityPolicyURINone, ua.SecurityPolicyURIBasic256Sha256} {
		_, err := f.client(t, policy, "admin", "secret")
		require.NoError(t, err, policy)
		_, err = f.client(t, policy, "admin", "wrong")
		require.ErrorIs(t, err, ua.StatusBadUserAccessDenied, policy)
	}
}

func TestAnonymousNotOffered(t *testing.T) {
	cert, key := testCert(t, "urn:test:server")
	port := freePort(t)
	srv := server.New(
		server.Certificate(cert), server.PrivateKey(key),
		server.EndPoint("127.0.0.1", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.UserNameAuthenticator(func(ctx context.Context, u, p string) (*server.Identity, error) { return nil, nil }),
	)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := opcua.NewClient(endpointURL(port), opcua.AutoReconnect(false), opcua.AuthAnonymous(), opcua.AuthPolicyID("anonymous"))
	require.NoError(t, err)
	require.ErrorIs(t, c.Connect(ctx), ua.StatusBadIdentityTokenInvalid)
}

func subscribe(t *testing.T, c *opcua.Client, nid *ua.NodeID, filter *ua.DataChangeFilter) (chan *opcua.PublishNotificationData, ua.StatusCode) {
	t.Helper()
	ctx := context.Background()
	ch := make(chan *opcua.PublishNotificationData, 32)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nid, ua.AttributeIDValue, 1)
	if filter != nil {
		req.RequestedParameters.Filter = ua.NewExtensionObject(filter)
	}
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, req)
	require.NoError(t, err)
	return ch, res.Results[0].StatusCode
}

// next returns the next data change value, skipping keep-alives.
func next(t *testing.T, ch chan *opcua.PublishNotificationData, within time.Duration) *ua.DataValue {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case n := <-ch:
			require.NoError(t, n.Error)
			if dc, ok := n.Value.(*ua.DataChangeNotification); ok && len(dc.MonitoredItems) > 0 {
				return dc.MonitoredItems[len(dc.MonitoredItems)-1].Value
			}
		case <-deadline:
			return nil
		}
	}
}

func TestSubscriptionReportsChanges(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)
	ch, st := subscribe(t, c, f.id("Temp"), nil)
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, 21.5, next(t, ch, 2*time.Second).Value.Value(), "initial value")

	require.NoError(t, f.srv.SetValue(f.id("Temp"), 22.0, ua.StatusOK, time.Time{}))
	require.Equal(t, 22.0, next(t, ch, 2*time.Second).Value.Value())

	require.NoError(t, f.srv.SetValue(f.id("Temp"), 22.0, ua.StatusBadCommunicationError, time.Time{}))
	dv := next(t, ch, 2*time.Second)
	require.Equal(t, ua.StatusBadCommunicationError, dv.Status, "a status change alone is reported")
}

func TestDeadband(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)

	ch, st := subscribe(t, c, f.id("Temp"), &ua.DataChangeFilter{
		Trigger: ua.DataChangeTriggerStatusValue, DeadbandType: uint32(ua.DeadbandTypeAbsolute), DeadbandValue: 1.0,
	})
	require.Equal(t, ua.StatusOK, st)
	require.NotNil(t, next(t, ch, 2*time.Second))
	require.NoError(t, f.srv.SetValue(f.id("Temp"), 22.0, ua.StatusOK, time.Time{})) // +0.5
	require.Nil(t, next(t, ch, 300*time.Millisecond), "within the deadband")
	require.NoError(t, f.srv.SetValue(f.id("Temp"), 23.0, ua.StatusOK, time.Time{})) // +1.5 from 21.5
	require.Equal(t, 23.0, next(t, ch, 2*time.Second).Value.Value())

	// 5 % of the EURange 0..100 is 5.
	pch, st := subscribe(t, c, f.id("Temp"), &ua.DataChangeFilter{
		Trigger: ua.DataChangeTriggerStatusValue, DeadbandType: uint32(ua.DeadbandTypePercent), DeadbandValue: 5,
	})
	require.Equal(t, ua.StatusOK, st)
	require.NotNil(t, next(t, pch, 2*time.Second))
	require.NoError(t, f.srv.SetValue(f.id("Temp"), 27.0, ua.StatusOK, time.Time{}))
	require.Nil(t, next(t, pch, 300*time.Millisecond))
	require.NoError(t, f.srv.SetValue(f.id("Temp"), 29.0, ua.StatusOK, time.Time{}))
	require.Equal(t, 29.0, next(t, pch, 2*time.Second).Value.Value())

	// Percent deadband needs an EURange (OPC 10000-8 §6.2).
	_, st = subscribe(t, c, f.id("NoUnit"), &ua.DataChangeFilter{
		DeadbandType: uint32(ua.DeadbandTypePercent), DeadbandValue: 5,
	})
	require.Equal(t, ua.StatusBadMonitoredItemFilterUnsupported, st)
	// Deadband on a non-numeric variable is not allowed.
	_, st = subscribe(t, c, f.id("ReadOnly"), &ua.DataChangeFilter{
		DeadbandType: uint32(ua.DeadbandTypeAbsolute), DeadbandValue: 1,
	})
	require.Equal(t, ua.StatusBadFilterNotAllowed, st)
}

func TestSubscribePolledServerTime(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)
	ch, st := subscribe(t, c, ua.NewNumericNodeID(0, id.Server_ServerStatus_CurrentTime), nil)
	require.Equal(t, ua.StatusOK, st)
	first := next(t, ch, 2*time.Second)
	second := next(t, ch, 2*time.Second)
	require.NotNil(t, first)
	require.NotNil(t, second)
	require.True(t, second.Value.Time().After(first.Value.Time()))
}

func TestRemoveNodeNotifiesSubscribers(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)
	ch, _ := subscribe(t, c, f.id("Count"), nil)
	require.NotNil(t, next(t, ch, 2*time.Second))

	require.NoError(t, f.srv.RemoveNode(f.id("Count")))
	require.Equal(t, ua.StatusBadNodeIDUnknown, next(t, ch, 2*time.Second).Status)
	require.Equal(t, ua.StatusBadNodeIDUnknown, read(t, c, f.id("Count")).Status)

	// Removing a folder removes the variables it organizes.
	require.NoError(t, f.srv.RemoveNode(f.id("Points")))
	require.Equal(t, ua.StatusBadNodeIDUnknown, read(t, c, f.id("Temp")).Status)
	require.Equal(t, ua.StatusBadNodeIDUnknown, read(t, c, ua.NewStringNodeID(f.ns, "Temp.EURange")).Status)
}

func TestSessionLimit(t *testing.T) {
	f := newFixture(t, server.SetLimits(server.Limits{MaxSessions: 2}))
	f.anon(t)
	f.anon(t)
	_, err := f.client(t, ua.SecurityPolicyURINone, "", "")
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)
	require.Len(t, f.srv.Stats().Sessions, 2)
}

func TestSessionTimesOut(t *testing.T) {
	f := newFixture(t, server.SetLimits(server.Limits{MinSessionTimeout: time.Second}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := opcua.NewClient(f.ep, opcua.AutoReconnect(false), opcua.SessionTimeout(time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	require.Len(t, f.srv.Stats().Sessions, 1)

	// The gopcua client sends no requests by itself, so the session
	// times out on the server.
	require.Eventually(t, func() bool { return len(f.srv.Stats().Sessions) == 0 }, 5*time.Second, 100*time.Millisecond)
}
