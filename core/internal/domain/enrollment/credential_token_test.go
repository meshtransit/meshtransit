package enrollment

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestCredentialTokenCanonicalEncoding(t *testing.T) {
	t.Parallel()

	secret := [credentialTokenBytes]byte{}
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	token, err := NewCredentialToken(secret)
	if err != nil {
		t.Fatalf("NewCredentialToken() error = %v", err)
	}
	encoded := token.Reveal()
	parsed, err := ParseCredentialToken(encoded)
	if err != nil {
		t.Fatalf("ParseCredentialToken() error = %v", err)
	}
	if parsed.bytes() != secret {
		t.Fatal("ParseCredentialToken() changed token bytes")
	}
	if encoded != "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA" {
		t.Fatalf("CredentialToken.Reveal() = %q, want canonical base64url", encoded)
	}
	if fmt.Sprint(token) != "[REDACTED]" ||
		fmt.Sprintf("%#v", token) != "enrollment.CredentialToken([REDACTED])" ||
		token.LogValue().String() != "[REDACTED]" {
		t.Fatal("CredentialToken formatting disclosed secret state")
	}
}

func TestCredentialTokenRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"AQID",
		"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHy+",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for _, value := range tests {
		if _, err := ParseCredentialToken(value); !errors.Is(err, ErrInvalidCredentialToken) {
			t.Fatalf("ParseCredentialToken(%q) error = %v, want ErrInvalidCredentialToken", value, err)
		}
	}
	if _, err := NewCredentialToken([credentialTokenBytes]byte{}); !errors.Is(err, ErrInvalidCredentialToken) {
		t.Fatalf("NewCredentialToken(zero) error = %v, want ErrInvalidCredentialToken", err)
	}
	if (CredentialToken{}).IsValid() {
		t.Fatal("zero CredentialToken is valid")
	}
}

func TestGenerateCredentialToken(t *testing.T) {
	t.Parallel()

	token, err := GenerateCredentialToken()
	if err != nil {
		t.Fatalf("GenerateCredentialToken() error = %v", err)
	}
	if !token.IsValid() {
		t.Fatal("GenerateCredentialToken() returned invalid token")
	}
	if _, err := generateCredentialToken(nil); !errors.Is(err, ErrInvalidCredentialToken) {
		t.Fatalf("generateCredentialToken(nil) error = %v, want ErrInvalidCredentialToken", err)
	}
	wantErr := errors.New("entropy unavailable")
	if _, err := generateCredentialToken(errorReader{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("generateCredentialToken(error) error = %v, want wrapped entropy error", err)
	}
	if _, err := generateCredentialToken(bytes.NewReader(make([]byte, credentialTokenBytes-1))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("generateCredentialToken(short) error = %v, want io.ErrUnexpectedEOF", err)
	}
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }
