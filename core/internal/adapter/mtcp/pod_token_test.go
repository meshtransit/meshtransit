package mtcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/adapter/kubetoken"
)

// The cluster the tests' pods run in: its issuer and signing key.
const testIssuer = "https://kubernetes.default.svc.cluster.local"

var (
	podSignerOnce sync.Once
	podSigner     *ecdsa.PrivateKey
)

func testPodSigner() *ecdsa.PrivateKey {
	podSignerOnce.Do(func() {
		var err error
		if podSigner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
	})
	return podSigner
}

// testJWKS is the cluster's JWKS as the API server serves it.
func testJWKS() []byte {
	point, err := testPodSigner().PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return fmt.Appendf(nil, `{"keys":[{"use":"sig","kty":"EC","crv":"P-256","kid":"k1","alg":"ES256","x":%q,"y":%q}]}`,
		base64.RawURLEncoding.EncodeToString(point[1:33]), base64.RawURLEncoding.EncodeToString(point[33:65]))
}

// testPodClaims are what kubelet puts in the token of pod at now.
func testPodClaims(now time.Time, pod string) map[string]any {
	return map[string]any{
		"iss": testIssuer, "aud": []string{kubetoken.Audience}, "sub": "system:serviceaccount:mt-kube-k1:meshgw",
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(),
		"jti": "jti-" + pod,
		"kubernetes.io": map[string]any{"namespace": "mt-kube-k1",
			"pod":            map[string]any{"name": pod, "uid": "uid-" + pod},
			"serviceaccount": map[string]any{"name": "meshgw", "uid": "sa-uid"}},
	}
}

// signPodToken signs claims with key as the cluster does (ES256, kid k1).
func signPodToken(t testing.TB, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// testPodToken is a valid token of pod meshgw-0 at the fixtures' clock.
func testPodToken(t testing.TB) string {
	t.Helper()
	return signPodToken(t, testPodSigner(), testPodClaims(fixtureClock, "meshgw-0"))
}

// fixtureClock is newConversationFixture's clock.
var fixtureClock = time.Unix(1_800_000_000, 0)

// signPodTokenOrPanic is signPodToken for fixtures built outside a test.
func signPodTokenOrPanic(key *ecdsa.PrivateKey, claims map[string]any) string {
	return signPodToken(panicTB{}, key, claims)
}

// panicTB fails by panicking: fixtures signed at package level have no T.
type panicTB struct{ testing.TB }

func (panicTB) Helper()           {}
func (panicTB) Fatal(args ...any) { panic(fmt.Sprint(args...)) }
