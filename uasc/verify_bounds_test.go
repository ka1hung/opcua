package uasc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uapolicy"
)

// symInstance returns a channelInstance whose signing and verifying keys
// are identical, so a test can build a validly signed chunk itself - as a
// peer that holds the channel's keys can.
func symInstance(t *testing.T, mode ua.MessageSecurityMode) *channelInstance {
	t.Helper()
	const uri = ua.SecurityPolicyURIBasic256Sha256
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	algo, err := uapolicy.Symmetric(uri, nonce, nonce)
	require.NoError(t, err)
	return &channelInstance{
		sc:   &SecureChannel{cfg: &Config{SecurityMode: mode, SecurityPolicyURI: uri}},
		algo: algo,
	}
}

func symChunk() *MessageChunk {
	return &MessageChunk{MessageHeader: &MessageHeader{
		Header:                  &Header{MessageType: MessageTypeMessage, ChunkType: ChunkTypeFinal},
		SymmetricSecurityHeader: &SymmetricSecurityHeader{TokenID: 1},
		SequenceHeader:          &SequenceHeader{SequenceNumber: 1, RequestID: 1},
	}}
}

// A Sign-mode chunk shorter than header + signature must be rejected, not
// sliced out of range (§10.1 T4).
func TestVerifyAndDecryptRejectsShortSignedChunk(t *testing.T) {
	c := symInstance(t, ua.MessageSecurityModeSign)
	for _, n := range []int{0, 4, 12, 16, 20, 16 + 31} {
		r := make([]byte, n)
		require.NotPanics(t, func() {
			_, err := c.verifyAndDecrypt(symChunk(), r)
			require.Error(t, err, "len %d", n)
		}, "len %d", n)
	}
}

// A validly signed SignAndEncrypt chunk whose PaddingSize exceeds the body
// must be rejected, not sliced out of range (§10.1 T4).
func TestVerifyAndDecryptRejectsOversizedPadding(t *testing.T) {
	c := symInstance(t, ua.MessageSecurityModeSignAndEncrypt)
	const headerLength = 16 // 12-byte message header + 4-byte TokenID

	for _, pad := range []byte{17, 200, 255} {
		// 15 body bytes + 1 PaddingSize byte + 32 signature bytes = 48,
		// a whole number of AES blocks.
		plain := make([]byte, headerLength, headerLength+15+1+32)
		copy(plain, []byte{'M', 'S', 'G', 'F'})
		binary.LittleEndian.PutUint32(plain[4:], uint32(headerLength+48))
		plain = append(plain, make([]byte, 15)...)
		plain = append(plain, pad)

		sig, err := c.algo.Signature(plain)
		require.NoError(t, err)
		enc, err := c.algo.Encrypt(append(append([]byte(nil), plain[headerLength:]...), sig...))
		require.NoError(t, err)
		r := append(append([]byte(nil), plain[:headerLength]...), enc...)

		require.NotPanics(t, func() {
			_, err := c.verifyAndDecrypt(symChunk(), r)
			require.Error(t, err, "padding %d", pad)
		}, "padding %d", pad)
	}
}

// Padding bytes must all hold the PaddingSize value (OPC 10000-6 §6.7.2.5).
func TestVerifyAndDecryptRejectsInconsistentPadding(t *testing.T) {
	c := symInstance(t, ua.MessageSecurityModeSignAndEncrypt)
	const headerLength = 16

	// 12 body bytes + 3 Padding bytes + 1 PaddingSize byte + 32 signature = 48.
	plain := make([]byte, headerLength, headerLength+48)
	copy(plain, []byte{'M', 'S', 'G', 'F'})
	binary.LittleEndian.PutUint32(plain[4:], uint32(headerLength+48))
	plain = append(plain, make([]byte, 12)...)
	plain = append(plain, 3, 9, 3) // the middle Padding byte is wrong
	plain = append(plain, 3)       // PaddingSize

	sig, err := c.algo.Signature(plain)
	require.NoError(t, err)
	enc, err := c.algo.Encrypt(append(append([]byte(nil), plain[headerLength:]...), sig...))
	require.NoError(t, err)
	r := append(append([]byte(nil), plain[:headerLength]...), enc...)

	_, err = c.verifyAndDecrypt(symChunk(), r)
	require.Error(t, err)
}

// ecdsaCert returns a DER certificate with an ECDSA key, which no RSA
// security policy can use.
func ecdsaCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// A non-RSA certificate from the peer must produce an error, not a failed
// type assertion (§10.1 T4).
func TestNonRSACertificateIsAnError(t *testing.T) {
	cert := ecdsaCert(t)

	_, err := uapolicy.PublicKey(cert)
	require.Error(t, err)

	sc := &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSign,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
	}}
	require.NotPanics(t, func() {
		_, _, err := sc.NewSessionSignature(cert, []byte("nonce"))
		require.Error(t, err)
	})
	require.NotPanics(t, func() {
		require.Error(t, sc.VerifySessionSignature(cert, []byte("nonce"), []byte("sig")))
	})
	require.NotPanics(t, func() {
		_, _, err := sc.EncryptUserPassword(ua.SecurityPolicyURIBasic256Sha256, "pw", cert, []byte("nonce"))
		require.Error(t, err)
	})
	require.NotPanics(t, func() {
		_, _, err := sc.NewUserTokenSignature(ua.SecurityPolicyURIBasic256Sha256, cert, []byte("nonce"))
		require.Error(t, err)
	})
}
