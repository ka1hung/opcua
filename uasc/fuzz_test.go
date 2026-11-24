package uasc

import (
	"encoding/binary"
	"testing"

	"github.com/ka1hung/opcua/ua"
)

// FuzzMessageChunkDecode feeds arbitrary bytes to the secure channel chunk
// decoder, which runs on every chunk a server receives.
func FuzzMessageChunkDecode(f *testing.F) {
	opn := []byte{0x4f, 0x50, 0x4e, 0x46, 0x30, 0, 0, 0, 0, 0, 0, 0,
		0x2f, 0, 0, 0}
	opn = append(opn, []byte("http://opcfoundation.org/UA/SecurityPolicy#None")...)
	opn = append(opn, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 1, 0, 0, 0)
	f.Add(opn)
	f.Add([]byte{0x4d, 0x53, 0x47, 0x46, 0x18, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = new(MessageChunk).Decode(b)
	})
}

// FuzzVerifyAndDecrypt feeds arbitrary chunk bodies to verifyAndDecrypt
// under Sign and SignAndEncrypt. The peer controls every length in them.
func FuzzVerifyAndDecrypt(f *testing.F) {
	f.Add([]byte{}, false)
	f.Add(make([]byte, 64), true)
	f.Add(make([]byte, 80), false)
	f.Fuzz(func(t *testing.T, body []byte, encrypt bool) {
		mode := ua.MessageSecurityModeSign
		if encrypt {
			mode = ua.MessageSecurityModeSignAndEncrypt
		}
		c := symInstance(t, mode)
		r := make([]byte, 16, 16+len(body))
		copy(r, "MSGF")
		binary.LittleEndian.PutUint32(r[4:], uint32(16+len(body)))
		r = append(r, body...)
		_, _ = c.verifyAndDecrypt(symChunk(), r)

		// A validly signed (and encrypted) chunk around the same body
		// exercises the padding code past the signature check.
		plain := append(append([]byte(nil), r...), make([]byte, 0)...)
		sig, err := c.algo.Signature(plain)
		if err != nil {
			return
		}
		payload := append(append([]byte(nil), body...), sig...)
		if encrypt {
			bs := c.algo.PlaintextBlockSize()
			if len(payload)%bs != 0 {
				return
			}
			if payload, err = c.algo.Encrypt(payload); err != nil {
				return
			}
		}
		signed := append(append([]byte(nil), r[:16]...), payload...)
		_, _ = c.verifyAndDecrypt(symChunk(), signed)
	})
}
