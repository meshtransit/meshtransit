package postgres

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/platform/idempotency"
)

func TestOfferTokenNeedsTheProcessKey(t *testing.T) {
	t.Parallel()
	keyID, err := idempotency.NewDigestKeyID("offer-token-test")
	if err != nil {
		t.Fatal(err)
	}
	digester, err := idempotency.NewDigester(keyID, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := digester.Proof("an-idempotency-key-of-enough-length")
	if err != nil {
		t.Fatal(err)
	}
	token, nonce, err := resourceSharingOfferToken(digester, proof)
	if err != nil {
		t.Fatal(err)
	}
	replayed, _, err := resourceSharingOfferToken(digester, proof)
	if err != nil || replayed != token {
		t.Fatalf("a replay gets another token: %v", err)
	}
	raw := token.Bytes()
	if nonce != sha256.Sum256(raw[:]) {
		t.Fatal("the stored nonce digest is not SHA-256 of the token")
	}
	// The stored digest alone (the old derivation) no longer gives the token.
	digest := proof.Digest()
	if sha256.Sum256(append([]byte("meshtransit/resource-sharing/offer-token/v1\x00"), digest[:]...)) == raw {
		t.Fatal("the token is still derived from the stored digest alone")
	}
	if _, _, err := resourceSharingOfferToken(nil, proof); !errors.Is(err, sharing.ErrUnavailable) {
		t.Fatalf("no binder = %v", err)
	}
}
