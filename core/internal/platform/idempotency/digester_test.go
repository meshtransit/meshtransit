package idempotency_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/platform/idempotency"
)

func TestDigesterProducesStableDomainSeparatedProof(t *testing.T) {
	t.Parallel()

	keyID, err := idempotency.NewDigestKeyID("management-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	digester, err := idempotency.NewDigester(keyID, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewDigester() error = %v", err)
	}
	first, err := digester.Proof("request-key-0001")
	if err != nil {
		t.Fatalf("Proof() error = %v", err)
	}
	second, err := digester.Proof("request-key-0001")
	if err != nil {
		t.Fatalf("Proof() replay error = %v", err)
	}
	other, err := digester.Proof("request-key-0002")
	if err != nil {
		t.Fatalf("Proof() alternate error = %v", err)
	}
	if first != second || first == other || first.DigestKeyID() != "management-v1" {
		t.Fatal("Digester did not produce stable key-versioned evidence")
	}
	logValue := digester.LogValue()
	if fmt.Sprint(digester) != "[REDACTED]" ||
		fmt.Sprintf("%#v", digester) != "idempotency.Digester([REDACTED])" ||
		logValue.Kind() != slog.KindString || logValue.String() != "[REDACTED]" {
		t.Fatal("Digester formatting disclosed key material")
	}
}

func TestDigesterRejectsUnsafeKeysAndRawValues(t *testing.T) {
	t.Parallel()

	validID, err := idempotency.NewDigestKeyID("management-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	for _, test := range []struct {
		name     string
		keyID    string
		material []byte
	}{
		{name: "invalid key id", keyID: " invalid", material: bytes.Repeat([]byte{1}, 32)},
		{name: "short key", keyID: "valid", material: bytes.Repeat([]byte{1}, 31)},
		{name: "zero key", keyID: "valid", material: make([]byte, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			keyID, keyErr := idempotency.NewDigestKeyID(test.keyID)
			if keyErr == nil {
				_, keyErr = idempotency.NewDigester(keyID, test.material)
			}
			if !errors.Is(keyErr, idempotency.ErrInvalidDigestKey) {
				t.Fatalf("invalid key error = %v, want ErrInvalidDigestKey", keyErr)
			}
		})
	}
	digester, err := idempotency.NewDigester(validID, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("NewDigester() error = %v", err)
	}
	for _, value := range []string{"", "short", "contains space here", string(bytes.Repeat([]byte{'a'}, 129))} {
		if _, err := digester.Proof(value); !errors.Is(err, idempotency.ErrInvalidRawKey) {
			t.Fatalf("Proof(%q) error = %v, want ErrInvalidRawKey", value, err)
		}
	}
}
