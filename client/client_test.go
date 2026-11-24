package client_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/client"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

func testCert(t *testing.T, appURI string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type testServer struct {
	srv  *server.Server
	ep   string
	port int
	cert []byte
	key  *rsa.PrivateKey
}

// startServer starts a server on port; with secured, it also offers
// Basic256Sha256 SignAndEncrypt.
func startServer(t *testing.T, port int, cert []byte, key *rsa.PrivateKey, secured bool, opts ...server.Option) *testServer {
	t.Helper()
	base := []server.Option{
		server.Certificate(cert), server.PrivateKey(key),
		server.EndPoint("127.0.0.1", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.UserNameAuthenticator(func(ctx context.Context, u, p string) (*server.Identity, error) {
			if u == "op" && p == "pw" {
				return &server.Identity{}, nil
			}
			return nil, errors.New("no")
		}),
	}
	if secured {
		base = append(base, server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))
	}
	srv := server.New(append(base, opts...)...)
	ns := srv.AddNamespace("urn:test:points")
	for _, v := range []server.VariableSpec{
		{NodeID: ua.NewStringNodeID(ns, "D"), BrowseName: "D", DataType: ua.TypeIDDouble, Writable: true, Value: 1.5},
		{NodeID: ua.NewStringNodeID(ns, "I16"), BrowseName: "I16", DataType: ua.TypeIDInt16, Writable: true, Value: int16(3)},
		{NodeID: ua.NewStringNodeID(ns, "B"), BrowseName: "B", DataType: ua.TypeIDBoolean, Writable: true, Value: false},
		{NodeID: ua.NewStringNodeID(ns, "Any"), BrowseName: "Any", Writable: true, Value: int32(5)},
	} {
		_, err := srv.AddVariable(server.ObjectsFolder, v)
		require.NoError(t, err)
	}
	require.NoError(t, srv.Start(context.Background()))
	return &testServer{srv: srv, ep: fmt.Sprintf("opc.tcp://127.0.0.1:%d", port), port: port, cert: cert, key: key}
}

func newServer(t *testing.T, secured bool, opts ...server.Option) *testServer {
	cert, key := testCert(t, "urn:test:server")
	s := startServer(t, freePort(t), cert, key, secured, opts...)
	t.Cleanup(func() { _ = s.srv.Close() })
	return s
}

func dial(t *testing.T, ep string, o client.Options) *client.Client {
	t.Helper()
	c, err := client.Dial(context.Background(), ep, o)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSecuritySelectionNeverDowngrades(t *testing.T) {
	secured := newServer(t, true)
	c := dial(t, secured.ep, client.Options{Security: client.Auto(client.MinSignAndEncrypt), Auth: client.UserPass("op", "pw")})
	require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, c.Endpoint().SecurityPolicyURI)

	noneOnly := newServer(t, false)
	_, err := client.Dial(context.Background(), noneOnly.ep, client.Options{Security: client.Auto(client.MinSign)})
	require.Error(t, err, "Auto must not fall back to None")
	_, err = client.Dial(context.Background(), secured.ep, client.Options{Security: client.Explicit("Basic256Sha256", "Sign")})
	require.Error(t, err, "Sign is not offered")
	dial(t, noneOnly.ep, client.Options{Security: client.NoSecurity()})
}

func TestReadMany(t *testing.T) {
	s := newServer(t, false)
	require.NoError(t, s.srv.SetValue(ua.NewStringNodeID(2, "D"), 2.5, ua.StatusUncertainInitialValue, time.Time{}))
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})

	rs := c.ReadMany(context.Background(), []string{"ns=2;s=D", "ns=x;i=abc", "ns=2;s=Missing", "ns=2;s=I16"})
	require.Len(t, rs, 4)
	require.Equal(t, 2.5, rs[0].Value)
	require.Equal(t, ua.StatusUncertainInitialValue, rs[0].Status)
	require.False(t, rs[0].Good())
	require.Error(t, rs[1].Err, "a malformed id fails only itself")
	require.Equal(t, ua.StatusBadNodeIDUnknown, rs[2].Status)
	require.Equal(t, int16(3), rs[3].Value)
	require.True(t, rs[3].Good())
}

func TestWriteAuto(t *testing.T) {
	s := newServer(t, false, server.AnonymousReadOnly(false))
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	ctx := context.Background()

	require.NoError(t, c.WriteAuto(ctx, "ns=2;s=I16", 12.0))
	require.NoError(t, c.WriteAuto(ctx, "ns=2;s=B", "true"))
	require.NoError(t, c.WriteAuto(ctx, "ns=2;s=D", 7))
	require.NoError(t, c.WriteAuto(ctx, "ns=2;s=Any", 9), "abstract DataType: the current value's type is used")
	rs := c.ReadMany(ctx, []string{"ns=2;s=I16", "ns=2;s=B", "ns=2;s=D", "ns=2;s=Any"})
	require.Equal(t, int16(12), rs[0].Value)
	require.Equal(t, true, rs[1].Value)
	require.Equal(t, 7.0, rs[2].Value)
	require.Equal(t, int32(9), rs[3].Value)

	require.Error(t, c.WriteAuto(ctx, "ns=2;s=I16", 70000), "out of range")
	require.Error(t, c.WriteAuto(ctx, "ns=2;s=I16", 1.5), "not an integer")
	require.Error(t, c.WriteAuto(ctx, "i=abc", 1))
	err := c.WriteAuto(ctx, "ns=2;s=Missing", 1)
	require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
}

func TestWriteRefusedByServer(t *testing.T) {
	s := newServer(t, false) // anonymous is read-only
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	require.ErrorIs(t, c.WriteAuto(context.Background(), "ns=2;s=D", 1.0), ua.StatusBadUserAccessDenied)
}

func TestTimeout(t *testing.T) {
	s := newServer(t, false, server.AnonymousReadOnly(false))
	s.srv.OnWrite(func(ctx context.Context, who *server.Identity, nid *ua.NodeID, v *ua.Variant) ua.StatusCode {
		time.Sleep(2 * time.Second)
		return ua.StatusOK
	})
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity(), Timeout: 500 * time.Millisecond})
	start := time.Now()
	require.Error(t, c.WriteAuto(context.Background(), "ns=2;s=D", 1.0))
	require.Less(t, time.Since(start), 1500*time.Millisecond)
}

func TestSubscribe(t *testing.T) {
	s := newServer(t, false)
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	var mu sync.Mutex
	got := map[string][]any{}
	sub, results, err := c.Subscribe(context.Background(), []string{"ns=2;s=D", "i=abc", "ns=2;s=Missing"}, 50*time.Millisecond,
		func(id string, r client.Result) {
			mu.Lock()
			got[id] = append(got[id], r.Value)
			mu.Unlock()
		})
	require.NoError(t, err)
	defer sub.Close()
	require.Equal(t, ua.StatusOK, results[0].Status)
	require.Error(t, results[1].Err)
	require.Equal(t, ua.StatusBadNodeIDUnknown, results[2].Status)

	require.NoError(t, s.srv.SetValue(ua.NewStringNodeID(2, "D"), 8.0, ua.StatusOK, time.Time{}))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		v := got["ns=2;s=D"]
		return len(v) >= 2 && v[len(v)-1] == 8.0
	}, 3*time.Second, 20*time.Millisecond)
}

// After the server restarts the client reconnects, reports the state
// changes, and reads again (P5).
func TestReconnect(t *testing.T) {
	cert, key := testCert(t, "urn:test:server")
	port := freePort(t)
	s := startServer(t, port, cert, key, false)

	c, err := client.Dial(context.Background(), s.ep, client.Options{Security: client.NoSecurity(), Timeout: 2 * time.Second})
	require.NoError(t, err)
	defer c.Close()
	require.True(t, c.ReadMany(context.Background(), []string{"ns=2;s=D"})[0].Good())

	require.NoError(t, s.srv.Close())
	s = startServer(t, port, cert, key, false)
	defer s.srv.Close()

	sawDisconnect := false
	deadline := time.After(20 * time.Second)
	for {
		select {
		case st := <-c.State():
			if st == client.Disconnected || st == client.Reconnecting {
				sawDisconnect = true
			}
			if st == client.Connected && sawDisconnect {
				require.True(t, c.ReadMany(context.Background(), []string{"ns=2;s=D"})[0].Good())
				return
			}
		case <-deadline:
			t.Fatal("did not reconnect")
		}
	}
}

// Closing a client leaves no goroutines behind (P5: no leaks).
func TestCloseReleasesGoroutines(t *testing.T) {
	s := newServer(t, false)
	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		c, err := client.Dial(context.Background(), s.ep, client.Options{Security: client.NoSecurity()})
		require.NoError(t, err)
		sub, _, err := c.Subscribe(context.Background(), []string{"ns=2;s=D"}, 50*time.Millisecond, func(string, client.Result) {})
		require.NoError(t, err)
		require.NoError(t, sub.Close())
		require.NoError(t, c.Close())
	}
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= before+5 }, 5*time.Second, 100*time.Millisecond,
		"goroutines: before %d, now %d", before, runtime.NumGoroutine())
}
