package kubecluster_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubejoin"
)

func signingKeys(t *testing.T, kids ...string) kubejoin.JWKS {
	t.Helper()
	members := ""
	for index, kid := range kids {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		point, err := private.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if index > 0 {
			members += ","
		}
		members += fmt.Sprintf(`{"kty":"EC","crv":"P-256","kid":%q,"x":%q,"y":%q}`, kid,
			base64.RawURLEncoding.EncodeToString(point[1:33]), base64.RawURLEncoding.EncodeToString(point[33:65]))
	}
	jwks, err := kubejoin.ParseJWKS([]byte(`{"keys":[` + members + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return jwks
}

func podTrust(t *testing.T, jwks kubejoin.JWKS, pod string) kubejoin.Trust {
	t.Helper()
	return kubejoin.Trust{Issuer: "https://kubernetes.default.svc.cluster.local", JWKS: jwks,
		Namespace: "mt-kube-k1", ServiceAccount: "meshgw", PodName: pod}
}

func TestNewJoinTrust(t *testing.T) {
	t.Parallel()
	jwks := signingKeys(t, "a", "b")
	signer, _ := jwks.Key("b")
	trust, err := kubecluster.NewJoinTrust(podTrust(t, jwks, "meshgw-3"), signer.Thumbprint)
	if err != nil {
		t.Fatalf("NewJoinTrust() error = %v", err)
	}
	digest, _ := kubejoin.TrustDigest(podTrust(t, jwks, "meshgw-3"))
	if !trust.IsValid() || trust.Digest() != digest || trust.StatefulSet() != "meshgw" ||
		trust.PodName() != "meshgw-3" || trust.JoinKeyThumbprint() != signer.Thumbprint ||
		len(trust.KeyThumbprints()) != 2 || string(trust.JWKS()) != string(jwks.Canonical()) ||
		trust.Issuer() != "https://kubernetes.default.svc.cluster.local" || trust.Namespace() != "mt-kube-k1" ||
		trust.ServiceAccount() != "meshgw" {
		t.Fatalf("NewJoinTrust() = %+v", trust)
	}
	// Returned slices are copies.
	thumbprints := trust.KeyThumbprints()
	thumbprints[0][0] ^= 1
	if trust.KeyThumbprints()[0] == thumbprints[0] {
		t.Fatal("KeyThumbprints() shares its backing array")
	}
	if (kubecluster.JoinTrust{}).IsValid() {
		t.Fatal("the zero JoinTrust is valid")
	}
}

func TestNewJoinTrustRefuses(t *testing.T) {
	t.Parallel()
	jwks := signingKeys(t, "a")
	signer, _ := jwks.Key("a")
	other := signingKeys(t, "x")
	foreign, _ := other.Key("x")
	for name, test := range map[string]struct {
		trust kubejoin.Trust
		key   [32]byte
	}{
		"signer not among the keys": {podTrust(t, jwks, "meshgw-0"), foreign.Thumbprint},
		"pod without ordinal":       {podTrust(t, jwks, "meshgw"), signer.Thumbprint},
		"no keys":                   {podTrust(t, kubejoin.JWKS{}, "meshgw-0"), signer.Thumbprint},
		"http issuer": {kubejoin.Trust{Issuer: "http://x", JWKS: jwks, Namespace: "n", ServiceAccount: "s",
			PodName: "p-0"}, signer.Thumbprint},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := kubecluster.NewJoinTrust(test.trust, test.key); !errors.Is(err, kubecluster.ErrInvalid) {
				t.Fatalf("NewJoinTrust() error = %v, want ErrInvalid", err)
			}
		})
	}
}

// A replica's join must carry its trust from K1.1 on.
func TestJoinAttemptNeedsTrust(t *testing.T) {
	t.Parallel()
	attempt := validJoinAttempt(t)
	if !attempt.IsValid() {
		t.Fatal("a complete attempt is invalid")
	}
	attempt.Trust = kubecluster.JoinTrust{}
	if attempt.IsValid() {
		t.Fatal("an attempt without trust is valid")
	}
}

func validJoinAttempt(t *testing.T) kubecluster.JoinAttempt {
	t.Helper()
	token, err := enrollment.GenerateCredentialToken()
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := enrollment.NewJoinKeyPresentation(enrollment.CredentialID(mustID(t, "000000000001")), token)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := node.NewMachineKey([32]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := node.ParseHostname("meshgw-0")
	if err != nil {
		t.Fatal(err)
	}
	jwks := signingKeys(t, "a")
	signer, _ := jwks.Key("a")
	trust, err := kubecluster.NewJoinTrust(podTrust(t, jwks, "meshgw-0"), signer.Thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	return kubecluster.JoinAttempt{
		Presentation: presentation, MachineKey: machine, NodeKey: node.Key([32]byte{4, 5, 6}), Hostname: hostname,
		Reported: []byte(`{}`), RequestID: kubecluster.RequestID(mustID(t, "000000000002")), Nonce: [32]byte{7},
		Trust: trust,
	}
}
