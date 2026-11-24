package uacp

import (
	"testing"

	"github.com/ka1hung/opcua/ua"
)

// FuzzDecode feeds arbitrary bytes to every uacp message decoder: the
// bytes a server reads before any security is in place.
func FuzzDecode(f *testing.F) {
	for _, m := range []interface{}{
		&Hello{ReceiveBufSize: 65535, SendBufSize: 65535, MaxMessageSize: 1 << 20, MaxChunkCount: 64, EndpointURL: "opc.tcp://localhost:4840"},
		&Acknowledge{ReceiveBufSize: 65535, SendBufSize: 65535},
		&ReverseHello{ServerURI: "urn:x", EndpointURL: "opc.tcp://x"},
		&Error{ErrorCode: 1, Reason: "r"},
	} {
		b, err := ua.Encode(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("HELF\x20\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = new(Header).Decode(b)
		_, _ = new(Hello).Decode(b)
		_, _ = new(Acknowledge).Decode(b)
		_, _ = new(ReverseHello).Decode(b)
		_, _ = new(Error).Decode(b)
	})
}
