package server_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

// A pushed monitored item applies CanRead to every value, so revoking a
// user's read access stops the values the subscription delivers
// (GHSA-57r3-wjr8-q87m).
func TestRevokedReadStopsPushedValues(t *testing.T) {
	f := newFixture(t)
	var allowed atomic.Bool
	allowed.Store(true)
	_, err := f.srv.AddVariable(f.id("Points"), server.VariableSpec{
		NodeID: f.id("Revocable"), BrowseName: "Revocable", DataType: ua.TypeIDDouble, Value: 1.0,
		CanRead: func(*server.Identity) bool { return allowed.Load() },
	})
	require.NoError(t, err)

	c := f.anon(t)
	ch, st := subscribe(t, c, f.id("Revocable"), nil)
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, 1.0, next(t, ch, 2*time.Second).Value.Value(), "initial value")

	allowed.Store(false)
	require.NoError(t, f.srv.SetValue(f.id("Revocable"), 2.0, ua.StatusOK, time.Time{}))
	dv := next(t, ch, 2*time.Second)
	require.NotNil(t, dv)
	require.Equal(t, ua.StatusBadUserAccessDenied, dv.Status)
	require.Nil(t, dv.Value.Value(), "the value must not reach a revoked user")

	require.NoError(t, f.srv.SetValue(f.id("Revocable"), 3.0, ua.StatusOK, time.Time{}))
	require.Nil(t, next(t, ch, 300*time.Millisecond), "no more notifications while denied")

	allowed.Store(true)
	require.NoError(t, f.srv.SetValue(f.id("Revocable"), 4.0, ua.StatusOK, time.Time{}))
	require.Equal(t, 4.0, next(t, ch, 2*time.Second).Value.Value(), "values resume when read is allowed again")
}
