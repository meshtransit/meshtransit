package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileReferencesAlwaysFormatAsRedacted(t *testing.T) {
	t.Parallel()

	secret := SecretFile{path: "/private/secret-value"}
	trust := TrustFile{path: "/private/trust-value"}
	for name, value := range map[string]any{"secret": secret, "trust": trust} {
		formatted := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(formatted, "private") || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("%s formatting = %q, want redacted", name, formatted)
		}
	}
	formattedConfig := fmt.Sprintf("%#v", StorageConfig{
		PostgreSQL: PostgreSQLConfig{
			CAFile: trust,
			Runtime: &PostgreSQLRoleConfig{
				PasswordFile: secret,
			},
			Worker: &PostgreSQLRoleConfig{
				PasswordFile: secret,
			},
		},
		Redis: RedisConfig{PasswordFile: secret, CAFile: trust},
	})
	if strings.Contains(formattedConfig, "private") {
		t.Fatalf("nested config formatting exposed file path: %q", formattedConfig)
	}
}

func TestSecretFileReadIsBoundedAndPreservesCredentialBytes(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credential")
	if err := os.WriteFile(credentialPath, []byte("  difficult credential  \r\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	credential, err := (SecretFile{path: credentialPath}).Read()
	if err != nil {
		t.Fatalf("SecretFile.Read() error = %v", err)
	}
	if credential != "  difficult credential  " {
		t.Fatalf("credential = %q, want spaces preserved and terminal CRLF removed", credential)
	}

	tests := []struct {
		name    string
		content []byte
	}{
		{name: "empty", content: nil},
		{name: "only line ending", content: []byte("\n")},
		{name: "multiline", content: []byte("first\nsecond")},
		{name: "nul byte", content: []byte("first\x00second")},
		{name: "oversized", content: bytes.Repeat([]byte("x"), maxCredentialBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name)
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			if _, err := (SecretFile{path: path}).Read(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("SecretFile.Read() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestTrustFileReadRejectsNonRegularAndOversizedFiles(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	trustPath := filepath.Join(directory, "ca.pem")
	want := []byte("certificate bundle")
	if err := os.WriteFile(trustPath, want, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	got, err := (TrustFile{path: trustPath}).Read()
	if err != nil {
		t.Fatalf("TrustFile.Read() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("TrustFile.Read() = %q, want %q", got, want)
	}

	if _, err := (TrustFile{path: directory}).Read(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("TrustFile.Read(directory) error = %v, want ErrInvalid", err)
	}
	oversizedPath := filepath.Join(directory, "oversized.pem")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte("x"), maxTrustBytes+1), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if _, err := (TrustFile{path: oversizedPath}).Read(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("TrustFile.Read(oversized) error = %v, want ErrInvalid", err)
	}
}
