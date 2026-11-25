package server

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/ua"
)

// An index range ending at the largest int must not overflow the slice
// bound (GHSA-8mxw-fxpr-c4c7).
func TestIndexRangeUpperBoundDoesNotOverflow(t *testing.T) {
	maxInt := strconv.Itoa(int(^uint(0) >> 1))
	for _, val := range []any{"hello", []byte("hello"), []int32{1, 2, 3, 4, 5}} {
		v, err := ua.NewVariant(val)
		require.NoError(t, err)
		out, st := applyIndexRange(v, "1:"+maxInt)
		require.Equal(t, ua.StatusOK, st)
		require.NotNil(t, out)
	}
	v, _ := ua.NewVariant("hello")
	out, st := applyIndexRange(v, "1:"+maxInt)
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, "ello", out.Value())
	out, st = applyIndexRange(v, "1:2")
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, "el", out.Value())
	out, st = applyIndexRange(v, "4")
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, "o", out.Value())
}
