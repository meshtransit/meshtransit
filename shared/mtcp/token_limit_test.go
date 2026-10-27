package mtcp

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/kubejoin"
)

// A Kubernetes gateway sends its pod token, of up to kubejoin.MaxTokenSize,
// with its join and both key rotations, and its cluster's JWKS, of up to
// kubejoin.MaxJWKSSize, with its join (K1.1): the messages that carry them
// must take the largest of each.
func TestMessagesTakeTheLargestPodTokenAndJWKS(t *testing.T) {
	token := strings.Repeat("t", kubejoin.MaxTokenSize)
	key32 := make([]byte, 32)
	proof := make([]byte, 64)
	cases := []struct {
		name    string
		message MessageType
		value   proto.Message
	}{
		{"RotateMachineKey", MessageRotateMachineKey, &mtcpv1.RotateMachineKey{
			NewMachineKey: key32, Proof: proof, ServiceAccountToken: token,
		}},
		{"RotateNodeKey", MessageRotateNodeKey, &mtcpv1.RotateNodeKey{
			NewNodeKey: key32, NewDiscoKey: key32, NodeKeyProof: proof, DiscoKeyProof: proof,
			ServiceAccountToken: token,
		}},
		{"RegisterRequest with ClusterJoin", MessageRegisterRequest, &mtcpv1.RegisterRequest{
			NodeKey: key32, DiscoKey: key32, NodeKeyProof: proof, DiscoKeyProof: proof,
			Auth: &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_ClusterJoin{
				ClusterJoin: &mtcpv1.RegisterRequest_ClusterJoin{
					JoinKey:              "mtk1." + strings.Repeat("k", 80),
					Reported:             make([]byte, 2048),
					ServiceAccountToken:  token,
					ServiceAccountIssuer: "https://" + strings.Repeat("i", kubejoin.MaxIssuerSize-len("https://")),
					ServiceAccountJwks:   []byte(strings.Repeat("j", kubejoin.MaxJWKSSize)),
				},
			}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fragments, err := EncodeMessage(tc.message, tc.value, NodeToCore, EncodeOptions{})
			if err != nil {
				t.Fatalf("EncodeMessage() error = %v", err)
			}
			assembler := NewAssembler(NodeToCore)
			var payload []byte
			for index, fragment := range fragments {
				_, decoded, complete, err := assembler.Add(fragment)
				if err != nil || complete != (index == len(fragments)-1) {
					t.Fatalf("fragment %d: complete = %t, error = %v", index, complete, err)
				}
				payload = decoded
			}
			decoded, err := DecodeMessage(tc.message, payload)
			if err != nil || !proto.Equal(decoded, tc.value) {
				t.Fatalf("DecodeMessage() did not return the message: %v", err)
			}
		})
	}
	// One byte over each limit is still refused.
	for _, tc := range cases {
		t.Run(tc.name+" over the limit", func(t *testing.T) {
			value := proto.Clone(tc.value)
			size := proto.Size(value)
			pad := strings.Repeat("p", tc.message.Limit()-size+1)
			switch m := value.(type) {
			case *mtcpv1.RotateMachineKey:
				m.ServiceAccountToken += pad
			case *mtcpv1.RotateNodeKey:
				m.ServiceAccountToken += pad
			case *mtcpv1.RegisterRequest:
				m.GetAuth().GetClusterJoin().ServiceAccountToken += pad
			}
			// The field's length prefix may grow too: trim back to one over.
			for proto.Size(value) > tc.message.Limit()+1 {
				switch m := value.(type) {
				case *mtcpv1.RotateMachineKey:
					m.ServiceAccountToken = m.ServiceAccountToken[1:]
				case *mtcpv1.RotateNodeKey:
					m.ServiceAccountToken = m.ServiceAccountToken[1:]
				case *mtcpv1.RegisterRequest:
					join := m.GetAuth().GetClusterJoin()
					join.ServiceAccountToken = join.ServiceAccountToken[1:]
				}
			}
			if got := proto.Size(value); got != tc.message.Limit()+1 {
				t.Fatalf("message of %d bytes, want %d", got, tc.message.Limit()+1)
			}
			if _, err := EncodeMessage(tc.message, value, NodeToCore, EncodeOptions{}); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("EncodeMessage() error = %v, want ErrTooLarge", err)
			}
		})
	}
}
