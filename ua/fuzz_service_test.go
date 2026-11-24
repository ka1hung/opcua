package ua

import "testing"

// FuzzDecodeService feeds arbitrary bytes to the service decoder, which
// decodes the body of every request a server receives.
func FuzzDecodeService(f *testing.F) {
	for _, req := range []interface{}{
		&ReadRequest{RequestHeader: &RequestHeader{}, NodesToRead: []*ReadValueID{{NodeID: NewNumericNodeID(0, 2258), AttributeID: AttributeIDValue}}},
		&BrowseRequest{RequestHeader: &RequestHeader{}, NodesToBrowse: []*BrowseDescription{{NodeID: NewNumericNodeID(0, 85)}}},
		&CreateSessionRequest{RequestHeader: &RequestHeader{}, ClientDescription: &ApplicationDescription{}},
		&ActivateSessionRequest{RequestHeader: &RequestHeader{}, ClientSignature: &SignatureData{}, UserIdentityToken: NewExtensionObject(&AnonymousIdentityToken{PolicyID: "anonymous"}), UserTokenSignature: &SignatureData{}},
		&WriteRequest{RequestHeader: &RequestHeader{}, NodesToWrite: []*WriteValue{{NodeID: NewStringNodeID(2, "x"), AttributeID: AttributeIDValue, Value: &DataValue{Value: MustVariant(1.5)}}}},
	} {
		id := ServiceTypeID(req)
		b, err := Encode(NewFourByteExpandedNodeID(0, id))
		if err != nil {
			f.Fatal(err)
		}
		body, err := Encode(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(append(b, body...))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = DecodeService(b)
	})
}
