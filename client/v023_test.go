package client_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/certs"
	"github.com/ka1hung/opcua/client"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

// Many nodes go into several calls and, when a subscription is full, into
// more subscriptions; every node still reports its changes.
func TestSubscribeSplitsCallsAndSubscriptions(t *testing.T) {
	lim := server.DefaultLimits()
	lim.MaxNodesPerRequest = 40
	lim.MaxMonitoredItemsPerSubscription = 100
	s := newServer(t, false, server.SetLimits(lim))
	ns := uint16(2)
	const n = 250
	ids := make([]string, n)
	for i := range n {
		name := fmt.Sprintf("P%d", i)
		_, err := s.srv.AddVariable(server.ObjectsFolder, server.VariableSpec{NodeID: ua.NewStringNodeID(ns, name), BrowseName: name, DataType: ua.TypeIDDouble, Value: 0.0})
		require.NoError(t, err)
		ids[i] = "ns=2;s=" + name
	}
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	var mu sync.Mutex
	last := map[string]any{}
	sub, results, err := c.Subscribe(context.Background(), ids, 50*time.Millisecond, func(id string, r client.Result) {
		mu.Lock()
		last[id] = r.Value
		mu.Unlock()
	})
	require.NoError(t, err)
	defer sub.Close()
	for i, r := range results {
		require.Equal(t, ua.StatusOK, r.Status, ids[i])
	}
	require.Equal(t, 3, sub.Count())
	for i := range n {
		require.NoError(t, s.srv.SetValue(ua.NewStringNodeID(ns, fmt.Sprintf("P%d", i)), float64(i+1), ua.StatusOK, time.Time{}))
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for i, id := range ids {
			if last[id] != float64(i+1) {
				return false
			}
		}
		return true
	}, 5*time.Second, 50*time.Millisecond)
}

// nsu= node ids resolve through the namespace table, and NSU converts back.
func TestNamespaceURINodeIDs(t *testing.T) {
	s := newServer(t, false, server.AnonymousReadOnly(false))
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	rs := c.ReadMany(context.Background(), []string{"nsu=urn:test:points;s=D", "nsu=urn:nope;s=D"})
	require.True(t, rs[0].Good(), rs[0].Err)
	require.Equal(t, 1.5, rs[0].Value)
	require.Error(t, rs[1].Err)
	require.Equal(t, "nsu=urn:test:points;s=D", c.NSU("ns=2;s=D"))
	require.Equal(t, "i=85", c.NSU("i=85"))
	require.NoError(t, c.WriteAuto(context.Background(), "nsu=urn:test:points;s=D", 2.5))
}

// VerifyServer sees the server certificate and can refuse the server;
// Endpoints reports the same thumbprint.
func TestVerifyServerPinsCertificate(t *testing.T) {
	s := newServer(t, true)
	eps, err := client.Endpoints(context.Background(), s.ep, 0)
	require.NoError(t, err)
	want := client.CertThumbprint(s.cert)
	require.NotEmpty(t, want)
	for _, e := range eps {
		require.Equal(t, want, e.Thumbprint)
	}
	var seen string
	o := client.Options{Security: client.Auto(client.MinSign), VerifyServer: func(der []byte) error {
		seen = client.CertThumbprint(der)
		return nil
	}}
	_ = dial(t, s.ep, o)
	require.Equal(t, want, seen)
	o.VerifyServer = func([]byte) error { return fmt.Errorf("changed") }
	_, err = client.Dial(context.Background(), s.ep, o)
	require.ErrorContains(t, err, "changed")
}

// SessionOf tells callbacks which client called; Stats has the details
// and CloseSession ends a session.
func TestSessionInfoAndClose(t *testing.T) {
	s := newServer(t, false, server.AnonymousReadOnly(false))
	var who server.SessionInfo
	s.srv.OnWrite(func(ctx context.Context, _ *server.Identity, _ *ua.NodeID, _ *ua.Variant) ua.StatusCode {
		who, _ = s.srv.SessionOf(ctx)
		return ua.StatusOK
	})
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity(), ApplicationURI: "urn:test:upper", ApplicationName: "Upper"})
	sub, _, err := c.Subscribe(context.Background(), []string{"ns=2;s=D", "ns=2;s=B"}, 100*time.Millisecond, func(string, client.Result) {})
	require.NoError(t, err)
	defer sub.Close()
	require.NoError(t, c.WriteAuto(context.Background(), "ns=2;s=D", 3.0))
	require.Equal(t, "urn:test:upper", who.ClientURI)
	require.Equal(t, "Upper", who.ClientName)
	require.NotEmpty(t, who.ClientAddr)

	st := s.srv.Stats()
	require.Len(t, st.Sessions, 1)
	require.Equal(t, 2, st.Sessions[0].MonitoredItems)
	require.False(t, st.Sessions[0].Created.IsZero())
	require.NoError(t, s.srv.CloseSession(st.Sessions[0].ID))
	require.Empty(t, s.srv.Stats().Sessions)
	require.Error(t, s.srv.CloseSession("ns=1;g=00000000-0000-0000-0000-000000000000"))
}

// Trusted, Untrust and DeleteRejected manage the trust list by thumbprint.
func TestStoreTrustList(t *testing.T) {
	dir := t.TempDir()
	st, err := certs.Open(dir, certs.Options{})
	require.NoError(t, err)
	der, _ := testCert(t, "urn:test:client")
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	tp := certs.Thumbprint(c)

	rej := filepath.Join(dir, "rejected", "certs")
	require.NoError(t, os.MkdirAll(rej, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rej, "x.der"), der, 0o644))
	require.NoError(t, st.DeleteRejected(tp))
	got, err := st.Rejected()
	require.NoError(t, err)
	require.Empty(t, got)

	require.NoError(t, st.Trust(c))
	got, err = st.Trusted()
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.NoError(t, st.Untrust(tp))
	got, err = st.Trusted()
	require.NoError(t, err)
	require.Empty(t, got)
	require.Error(t, st.Untrust(tp))
}
