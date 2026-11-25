package ua

import (
	"bytes"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

// Nested values are bounded so that a small message cannot overflow the
// stack (GHSA-fcmr-6rv7-672q).
func TestDecodeDepthIsBounded(t *testing.T) {
	// A stack overflow is fatal; keep the ceiling low so that a regression
	// fails fast instead of taking a gigabyte.
	defer debug.SetMaxStack(debug.SetMaxStack(8 << 20))

	nestedVariant := func(depth int) []byte {
		return append(bytes.Repeat([]byte{byte(TypeIDVariant)}, depth), 0x00)
	}
	nestedDataValue := func(depth int) []byte {
		// DataValue{Value: Variant{DataValue{...}}}
		b := bytes.Repeat([]byte{DataValueValue, byte(TypeIDDataValue)}, depth)
		return append(b, 0x00)
	}
	nestedDiag := func(depth int) []byte {
		return append(bytes.Repeat([]byte{DiagnosticInfoInnerDiagnosticInfo}, depth), 0x00)
	}

	t.Run("shallow decodes", func(t *testing.T) {
		_, err := new(Variant).Decode(nestedVariant(50))
		require.NoError(t, err)
		_, err = new(DataValue).Decode(nestedDataValue(40))
		require.NoError(t, err)
		_, err = new(DiagnosticInfo).Decode(nestedDiag(50))
		require.NoError(t, err)
	})
	t.Run("deep is rejected", func(t *testing.T) {
		_, err := new(Variant).Decode(nestedVariant(200000))
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
		_, err = new(DataValue).Decode(nestedDataValue(200000))
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
		_, err = new(DiagnosticInfo).Decode(nestedDiag(200000))
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
	})
	t.Run("deep inside a service", func(t *testing.T) {
		// A WriteRequest whose value is a deeply nested Variant.
		req := &WriteRequest{RequestHeader: &RequestHeader{AuthenticationToken: NewTwoByteNodeID(0), AdditionalHeader: NewExtensionObject(nil)}}
		b, err := Encode(req)
		require.NoError(t, err)
		// replace the empty NodesToWrite (-1) with one WriteValue
		b = b[:len(b)-4]
		wv := []byte{1, 0, 0, 0}                // one element
		wv = append(wv, 0x00, 0x01)             // NodeID ns=0;i=1
		wv = append(wv, 13, 0, 0, 0)            // AttributeID
		wv = append(wv, 0xff, 0xff, 0xff, 0xff) // IndexRange null
		wv = append(wv, DataValueValue)
		wv = append(wv, nestedVariant(200000)...)
		_, err = Decode(append(b, wv...), new(WriteRequest))
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
	})
}
