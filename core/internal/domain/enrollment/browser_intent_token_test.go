package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

func TestBrowserIntentTokenRetryAndRotation(t *testing.T) {
	t.Parallel()
	deploymentPublicID, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := deployment.NewID(deploymentPublicID.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	intentPublicID, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := ParseBrowserIntentID(intentPublicID.String())
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewBrowserIntentNonce()
	if err != nil {
		t.Fatal(err)
	}
	active := testBrowserIntentKey(t, "browser-v1", 0x11)
	keys, err := NewBrowserIntentKeyring(active)
	if err != nil {
		t.Fatal(err)
	}
	token, digest, keyID, err := keys.Issue(deploymentID, 3, intentID, nonce)
	if err != nil || len(token.Encoded()) != 43 || keyID != active.id {
		t.Fatalf("issue browser intent: key %s, error %v", keyID, err)
	}
	presented, err := DigestPresentedBrowserIntentToken(token.Encoded())
	if err != nil || presented != digest {
		t.Fatalf("presented token lookup digest mismatch: %v", err)
	}

	// A replacement Core process can reconstruct the same URL while the prior
	// key is retained for the bounded intent lifetime.
	rotated := testBrowserIntentKey(t, "browser-v2", 0x22)
	restarted, err := NewBrowserIntentKeyring(rotated, active)
	if err != nil {
		t.Fatal(err)
	}
	reissued, err := restarted.Reissue(deploymentID, 3, intentID, nonce, keyID, digest)
	if err != nil || reissued.Encoded() != token.Encoded() {
		t.Fatalf("retry changed the authorization URL token: %v", err)
	}
	if _, err := restarted.Reissue(deploymentID, 4, intentID, nonce, keyID, digest); !errors.Is(err, ErrInvalidBrowserIntentToken) {
		t.Fatalf("stale recovery epoch reissued token: %v", err)
	}
	wrongNonce := nonce
	wrongNonce[0] ^= 0xff
	if _, err := restarted.Reissue(deploymentID, 3, intentID, wrongNonce, keyID, digest); !errors.Is(err, ErrInvalidBrowserIntentToken) {
		t.Fatalf("changed nonce reissued token: %v", err)
	}
	if _, err := keys.Reissue(deploymentID, 3, intentID, nonce, rotated.id, digest); !errors.Is(err, ErrInvalidBrowserIntentToken) {
		t.Fatalf("unknown key reissued token: %v", err)
	}
	if _, err := NewBrowserIntentKeyring(active, active); !errors.Is(err, ErrInvalidBrowserIntentToken) {
		t.Fatalf("duplicate key version accepted: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", token, nonce), token.Encoded()) {
		t.Fatal("diagnostics exposed URL token")
	}
	for _, secret := range []any{token, nonce, digest, active, restarted} {
		if _, err := json.Marshal(secret); !errors.Is(err, ErrInvalidBrowserIntentToken) {
			t.Fatalf("JSON exported browser registration secret: %v", err)
		}
	}
}

func TestBrowserIntentTokenRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	for _, encoded := range []string{"", strings.Repeat("A", 43), strings.Repeat("a", 42),
		strings.Repeat("!", 43), strings.Repeat("a", 43) + "="} {
		if _, err := DigestPresentedBrowserIntentToken(encoded); !errors.Is(err, ErrInvalidBrowserIntentToken) {
			t.Fatalf("invalid token accepted: length %d, error %v", len(encoded), err)
		}
	}
	if _, err := ParseBrowserIntentNonce([32]byte{}); !errors.Is(err, ErrInvalidBrowserIntentToken) {
		t.Fatalf("zero nonce accepted: %v", err)
	}
	if _, err := ParseBrowserIntentDigest([32]byte{}); !errors.Is(err, ErrInvalidBrowserIntentToken) {
		t.Fatalf("zero stored digest accepted: %v", err)
	}
	keyID, err := NewBrowserIntentKeyID("browser-v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewBrowserIntentKey(keyID, bytes.Repeat([]byte{0}, 32)); !errors.Is(err, ErrInvalidBrowserIntentToken) {
		t.Fatalf("zero HMAC key accepted: %v", err)
	}
}

func testBrowserIntentKey(t *testing.T, id string, fill byte) BrowserIntentKey {
	t.Helper()
	keyID, err := NewBrowserIntentKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewBrowserIntentKey(keyID, bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
