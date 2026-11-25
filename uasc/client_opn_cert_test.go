package uasc

import (
	"crypto/rsa"
	"crypto/x509"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uacp"
	"github.com/ka1hung/opcua/uapolicy"
)

// A client takes the OpenSecureChannel response only from the server
// certificate it opened the channel with (GHSA-9fhc-mm6p-cx94).
func TestClientOPNResponseMustComeFromPinnedServer(t *testing.T) {
	cliCertDER, cliKey := genThumbprintTestCert(t, "client")
	srvCertDER, srvKey := genThumbprintTestCert(t, "server")
	evilCertDER, evilKey := genThumbprintTestCert(t, "impostor")
	cliCert, err := x509.ParseCertificate(cliCertDER)
	require.NoError(t, err)
	cliPub := cliCert.PublicKey.(*rsa.PublicKey)

	cases := []struct {
		name   string
		cert   []byte
		key    *rsa.PrivateKey
		policy string
		want   error
	}{
		{"pinned server", srvCertDER, srvKey, ua.SecurityPolicyURIBasic256Sha256, nil},
		{"other certificate", evilCertDER, evilKey, ua.SecurityPolicyURIBasic256Sha256, ua.StatusBadSecurityChecksFailed},
		{"other policy", srvCertDER, srvKey, ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.StatusBadSecurityPolicyRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cliTCP, srvTCP := newTestTCPConnPair(t)
			defer cliTCP.Close()
			defer srvTCP.Close()
			conn, err := uacp.NewConn(cliTCP, &uacp.Acknowledge{
				ReceiveBufSize: 65535, SendBufSize: 65535, MaxMessageSize: 2 << 20, MaxChunkCount: 512,
			})
			require.NoError(t, err)
			cfg := &Config{
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
				SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
				LocalKey:          cliKey,
				Certificate:       cliCertDER,
				RemoteCertificate: srvCertDER,
				Thumbprint:        uapolicy.Thumbprint(srvCertDER),
			}
			s, err := NewSecureChannel("opc.tcp://localhost", conn, cfg, make(chan error, 1))
			require.NoError(t, err)
			s.openingInstance = newChannelInstance(s) // as open does

			m := &Message{
				MessageHeader: &MessageHeader{
					Header:                   NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 1),
					AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(tc.policy, tc.cert, uapolicy.Thumbprint(cliCertDER)),
					SequenceHeader:           NewSequenceHeader(1, 1),
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.OpenSecureChannelResponse_Encoding_DefaultBinary),
				Service: &ua.OpenSecureChannelResponse{
					ResponseHeader: &ua.ResponseHeader{Timestamp: time.Now(), AdditionalHeader: ua.NewExtensionObject(nil)},
					SecurityToken:  &ua.ChannelSecurityToken{ChannelID: 1, TokenID: 1, CreatedAt: time.Now(), RevisedLifetime: 3600000},
					ServerNonce:    make([]byte, 32),
				},
			}
			chunks, err := m.EncodeChunks(math.MaxUint32)
			require.NoError(t, err)
			algo, err := uapolicy.Asymmetric(tc.policy, tc.key, cliPub)
			require.NoError(t, err)
			enc := &channelInstance{
				sc:   &SecureChannel{cfg: &Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt, SecurityPolicyURI: tc.policy}},
				algo: algo,
			}
			cipher, err := enc.signAndEncrypt(m, chunks[0])
			require.NoError(t, err)
			go func() { _, _ = srvTCP.Write(cipher) }()

			_, err = s.readChunk()
			if tc.want == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.want)
			}
			require.Equal(t, srvCertDER, s.cfg.RemoteCertificate, "the pinned certificate must not change")
			require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, s.cfg.SecurityPolicyURI)
		})
	}
}
