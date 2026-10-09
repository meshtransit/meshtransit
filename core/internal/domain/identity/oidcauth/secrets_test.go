package oidcauth

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"testing"
)

func TestGenerateSecretsCreatesPurposeDistinctCanonicalValues(t *testing.T) {
	t.Parallel()

	entropy := append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)...)
	entropy = append(entropy, bytes.Repeat([]byte{0x33}, 32)...)
	entropy = append(entropy, bytes.Repeat([]byte{0x44}, 32)...)
	secrets, err := generateSecrets(bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("generateSecrets() error = %v", err)
	}
	if !secrets.IsValid() {
		t.Fatal("generateSecrets() returned invalid secrets")
	}
	if len(secrets.State().Encoded()) != 43 || len(secrets.Nonce().Encoded()) != 43 ||
		len(secrets.Verifier().Encoded()) != 43 || len(secrets.Verifier().Challenge()) != 43 {
		t.Fatal("generated values are not canonical 256-bit base64url")
	}
	if parsed, parseErr := ParseState(secrets.State().Encoded()); parseErr != nil ||
		parsed.Encoded() != secrets.State().Encoded() {
		t.Fatalf("ParseState() = (%v, %v), want round trip", parsed, parseErr)
	}
	if parsed, parseErr := ParseNonce(secrets.Nonce().Encoded()); parseErr != nil ||
		parsed.Encoded() != secrets.Nonce().Encoded() {
		t.Fatalf("ParseNonce() = (%v, %v), want round trip", parsed, parseErr)
	}
	if parsed, parseErr := ParseVerifier(secrets.Verifier().Encoded()); parseErr != nil ||
		parsed.Encoded() != secrets.Verifier().Encoded() {
		t.Fatalf("ParseVerifier() = (%v, %v), want round trip", parsed, parseErr)
	}
}

func TestGenerateSecretsRejectsUnsafeEntropy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entropy []byte
	}{
		{name: "short read", entropy: bytes.Repeat([]byte{0x44}, 127)},
		{name: "legacy three values", entropy: bytes.Repeat([]byte{0x44}, 96)},
		{name: "zero material", entropy: make([]byte, 128)},
		{name: "reused material", entropy: bytes.Repeat([]byte{0x55}, 128)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := generateSecrets(bytes.NewReader(test.entropy))
			if !errors.Is(err, ErrGenerateSecrets) {
				t.Fatalf("generateSecrets() error = %v, want ErrGenerateSecrets", err)
			}
		})
	}
}

func TestTransactionSecretsAlwaysFormatRedacted(t *testing.T) {
	t.Parallel()

	secrets := secretFixture(t)
	values := []any{secrets, secrets.State(), secrets.Nonce(), secrets.Verifier(), secrets.PreAuthCookie()}
	for _, value := range values {
		if got := fmt.Sprint(value); got != "[REDACTED]" {
			t.Errorf("fmt.Sprint(%T) = %q, want redacted", value, got)
		}
		logValue, ok := value.(slog.LogValuer)
		if !ok || logValue.LogValue().String() != "[REDACTED]" {
			t.Errorf("LogValue(%T) did not redact", value)
		}
	}
}

func TestGenerateSecretsRejectsEveryPurposeAlias(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		first, second int
	}{
		{name: "state nonce", first: 0, second: 1},
		{name: "state verifier", first: 0, second: 2},
		{name: "nonce verifier", first: 1, second: 2},
		{name: "cookie state", first: 3, second: 0},
		{name: "cookie nonce", first: 3, second: 1},
		{name: "cookie verifier", first: 3, second: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entropy := make([]byte, 0, 128)
			for index := range 4 {
				entropy = append(entropy, bytes.Repeat([]byte{byte(index + 1)}, 32)...)
			}
			copy(entropy[test.second*32:(test.second+1)*32], entropy[test.first*32:(test.first+1)*32])
			if secrets, err := generateSecrets(bytes.NewReader(entropy)); !errors.Is(err, ErrGenerateSecrets) || secrets.IsValid() {
				t.Fatal("purpose alias accepted")
			}
		})
	}
}

func secretFixture(t *testing.T) Secrets {
	t.Helper()
	entropy := append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)...)
	entropy = append(entropy, bytes.Repeat([]byte{0x33}, 32)...)
	entropy = append(entropy, bytes.Repeat([]byte{0x44}, 32)...)
	secrets, err := generateSecrets(bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("generateSecrets() error = %v", err)
	}
	return secrets
}
