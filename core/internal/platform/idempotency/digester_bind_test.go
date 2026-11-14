package idempotency

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestBindNeedsTheKey(t *testing.T) {
	t.Parallel()
	keyID, err := NewDigestKeyID("bind-test")
	if err != nil {
		t.Fatal(err)
	}
	digester, err := NewDigester(keyID, bytes.Repeat([]byte{1}, digestKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewDigester(keyID, bytes.Repeat([]byte{2}, digestKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("request"))
	bound := digester.Bind("purpose", digest)
	if bound == ([sha256.Size]byte{}) || bound != digester.Bind("purpose", digest) {
		t.Fatal("Bind is not a stable, non-zero value")
	}
	for name, value := range map[string][sha256.Size]byte{
		"another key":     other.Bind("purpose", digest),
		"another purpose": digester.Bind("purpose2", digest),
		"another digest":  digester.Bind("purpose", sha256.Sum256([]byte("other"))),
		"the digest only": sha256.Sum256(append([]byte("purpose"), digest[:]...)),
	} {
		if value == bound {
			t.Errorf("%s gives the same value", name)
		}
	}
	var none *Digester
	if none.Bind("purpose", digest) != ([sha256.Size]byte{}) {
		t.Fatal("a nil Digester bound a value")
	}
}
