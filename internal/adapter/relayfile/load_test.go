package relayfile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeReturnsValidatedDirectory(t *testing.T) {
	t.Parallel()

	document := validDirectoryDocument()
	digest := sha256.Sum256([]byte(document))
	directory, err := Decode(strings.NewReader(document), digest)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	region, found := directory.Region(1)
	if directory.Revision() != 7 || !found || region.Code() != "sin" ||
		region.Nodes()[0].HostName() != "relay.example.com" {
		t.Fatalf("directory = revision %d region %+v found %t", directory.Revision(), region, found)
	}
}

func TestDecodeRejectsUntrustedInput(t *testing.T) {
	t.Parallel()

	valid := validDirectoryDocument()
	tests := []struct {
		name     string
		document string
		digest   func(string) [sha256.Size]byte
	}{
		{name: "digest mismatch", document: valid, digest: func(string) [sha256.Size]byte { return [sha256.Size]byte{1} }},
		{name: "empty", digest: digestDocument},
		{name: "oversized", document: strings.Repeat(" ", MaximumDocumentBytes+1), digest: digestDocument},
		{name: "unknown field", document: strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"extra":true`, 1), digest: digestDocument},
		{name: "duplicate field", document: strings.Replace(valid, `"revision":7`, `"revision":7,"revision":8`, 1), digest: digestDocument},
		{name: "case alias", document: strings.Replace(valid, `"revision":7`, `"revision":7,"Revision":8`, 1), digest: digestDocument},
		{name: "trailing value", document: valid + `{}`, digest: digestDocument},
		{name: "unsupported schema", document: strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1), digest: digestDocument},
		{name: "missing node field", document: strings.Replace(valid, `,"stun_only":false`, ``, 1), digest: digestDocument},
		{name: "null regions", document: strings.Replace(valid, `"regions":[`, `"regions":null,"unused":[`, 1), digest: digestDocument},
		{name: "invalid domain value", document: strings.Replace(valid, `"host_name":"relay.example.com"`, `"host_name":"127.0.0.1"`, 1), digest: digestDocument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Decode(strings.NewReader(test.document), test.digest(test.document)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Decode() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseDigest(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("directory"))
	encoded := "sha256:" + hex.EncodeToString(digest[:])
	parsed, err := ParseDigest(encoded)
	if err != nil || parsed != digest {
		t.Fatalf("ParseDigest() = %x, %v", parsed, err)
	}
	for _, value := range []string{
		"",
		hex.EncodeToString(digest[:]),
		"sha256:" + strings.ToUpper(hex.EncodeToString(digest[:])),
		"sha256:" + strings.Repeat("0", sha256.Size*2),
		"sha256:01",
	} {
		if _, err := ParseDigest(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ParseDigest(%q) error = %v, want ErrInvalid", value, err)
		}
	}
}

func TestLoadReadsBoundedProtectedFile(t *testing.T) {
	t.Parallel()

	document := validDirectoryDocument()
	digest := sha256.Sum256([]byte(document))
	directoryPath := filepath.Join(t.TempDir(), "relay-directory.json")
	if err := os.WriteFile(directoryPath, []byte(document), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	directory, err := Load(t.Context(), directoryPath, digest)
	if err != nil || !directory.IsValid() {
		t.Fatalf("Load() = valid %t, error %v", directory.IsValid(), err)
	}
}

func TestLoadRejectsUnsafeFile(t *testing.T) {
	t.Parallel()

	document := validDirectoryDocument()
	digest := sha256.Sum256([]byte(document))
	directoryPath := filepath.Join(t.TempDir(), "relay-directory.json")
	if err := os.WriteFile(directoryPath, []byte(document), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	// #nosec G302 -- this negative fixture deliberately creates an unsafe mode.
	if err := os.Chmod(directoryPath, 0o666); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := Load(t.Context(), directoryPath, digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load(group writable) error = %v, want ErrInvalid", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Load(canceled, directoryPath, digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load(canceled) error = %v, want ErrInvalid", err)
	}
	if _, err := Load(t.Context(), "relative.json", digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load(relative) error = %v, want ErrInvalid", err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(validDirectoryDocument()))
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, document []byte) {
		digest := sha256.Sum256(document)
		directory, err := Decode(strings.NewReader(string(document)), digest)
		if err == nil && !directory.IsValid() {
			t.Fatal("Decode() accepted an invalid directory")
		}
	})
}

func validDirectoryDocument() string {
	return `{"schema_version":1,"revision":7,"regions":[{"id":1,"code":"sin","name":"Singapore","nodes":[{"name":"1a","host_name":"relay.example.com","cert_name":"","ipv4":"192.0.2.10","ipv6":"2001:db8::10","stun_port":3478,"relay_port":443,"stun_only":false}]}]}`
}

func digestDocument(document string) [sha256.Size]byte {
	return sha256.Sum256([]byte(document))
}
