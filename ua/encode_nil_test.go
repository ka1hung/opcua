package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A request with nil structure fields still encodes to bytes the decoder
// reads back (upstream wrote nothing for them).
func TestNilStructFieldsEncodeAsZeroValues(t *testing.T) {
	for _, v := range []interface{}{
		&QueryFirstRequest{},
		&ReadProcessedDetails{},
		&BrowseRequest{NodesToBrowse: []*BrowseDescription{{NodeID: NewNumericNodeID(0, 85)}}},
	} {
		b, err := Encode(v)
		require.NoError(t, err, "%T", v)
		_, err = Decode(b, v)
		require.NoError(t, err, "%T", v)
	}
}
