package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/ua"
)

// A client keeps working across several security token renewals, under
// None and under SignAndEncrypt (§10.1 T7, §10.4 matrix C).
func TestRequestsAcrossTokenRenewals(t *testing.T) {
	f := newFixture(t)
	for _, policy := range []string{ua.SecurityPolicyURINone, ua.SecurityPolicyURIBasic256Sha256} {
		t.Run(policy, func(t *testing.T) {
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
			opts := []opcua.Option{
				opcua.AutoReconnect(false),
				opcua.Lifetime(2 * time.Second),
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			}
			if policy != ua.SecurityPolicyURINone {
				cert, key := testCert(t, "urn:test:client")
				opts = append(opts, opcua.Certificate(cert), opcua.PrivateKey(key), opcua.ApplicationURI("urn:test:client"))
			}
			c, err := opcua.NewClient(ep.EndpointURL, opts...)
			require.NoError(t, err)
			require.NoError(t, c.Connect(ctx))
			defer c.Close(context.Background())

			// The client renews at 75 % of 2 s; 7 s covers four renewals.
			deadline := time.Now().Add(7 * time.Second)
			n := 0
			for time.Now().Before(deadline) {
				dv := read(t, c, f.id("Temp"))
				require.Equal(t, ua.StatusOK, dv.Status, "read %d", n)
				n++
				time.Sleep(100 * time.Millisecond)
			}
			require.Greater(t, n, 40)
		})
	}
}
