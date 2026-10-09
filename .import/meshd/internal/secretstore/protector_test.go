package secretstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectorRoundTrip(t *testing.T) {
	t.Parallel()

	protector := testProtector(t, bytes.NewReader([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
	}))
	plaintext := []byte("private identity material")
	additionalData := []byte("profile binding")

	first, err := protector.Seal(t.Context(), plaintext, additionalData)
	if err != nil {
		t.Fatalf("Seal(first) error = %v", err)
	}
	second, err := protector.Seal(t.Context(), plaintext, additionalData)
	if err != nil {
		t.Fatalf("Seal(second) error = %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two protected records use the same nonce")
	}
	if bytes.Contains(first, plaintext) || bytes.Contains(second, plaintext) {
		t.Fatal("protected record contains plaintext")
	}

	opened, err := protector.Open(t.Context(), first, additionalData)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open() = %q, want original plaintext", opened)
	}
	clear(opened)
}

func TestProtectorKeySetRotation(t *testing.T) {
	t.Parallel()

	active := bytes.Repeat([]byte{0x21}, KeySize)
	fallback := bytes.Repeat([]byte{0x22}, KeySize)
	encoded, err := EncodeKeySet(active, fallback)
	if err != nil {
		t.Fatalf("EncodeKeySet() error = %v", err)
	}
	defer clear(encoded)
	protector, err := NewFromCredential(encoded)
	if err != nil {
		t.Fatalf("NewFromCredential() error = %v", err)
	}
	t.Cleanup(func() { _ = protector.Close() })

	oldProtector, err := New(fallback)
	if err != nil {
		t.Fatalf("New(fallback) error = %v", err)
	}
	t.Cleanup(func() { _ = oldProtector.Close() })
	additionalData := []byte("profile binding")
	oldCiphertext, err := oldProtector.Seal(t.Context(), []byte("identity"), additionalData)
	if err != nil {
		t.Fatalf("Seal(fallback) error = %v", err)
	}
	opened, needsRotation, err := protector.OpenWithRotation(
		t.Context(),
		oldCiphertext,
		additionalData,
	)
	if err != nil {
		t.Fatalf("OpenWithRotation(fallback) error = %v", err)
	}
	if !needsRotation || string(opened) != "identity" {
		t.Fatalf("OpenWithRotation(fallback) = %q, %t", opened, needsRotation)
	}
	clear(opened)

	newCiphertext, err := protector.Seal(t.Context(), []byte("identity"), additionalData)
	if err != nil {
		t.Fatalf("Seal(active) error = %v", err)
	}
	opened, needsRotation, err = protector.OpenWithRotation(
		t.Context(),
		newCiphertext,
		additionalData,
	)
	if err != nil {
		t.Fatalf("OpenWithRotation(active) error = %v", err)
	}
	if needsRotation || string(opened) != "identity" {
		t.Fatalf("OpenWithRotation(active) = %q, %t", opened, needsRotation)
	}
	clear(opened)

	if _, err := oldProtector.Open(t.Context(), newCiphertext, additionalData); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("fallback-only Open(active ciphertext) error = %v, want ErrAuthentication", err)
	}
}

func TestKeySetCredentialRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	active := bytes.Repeat([]byte{0x31}, KeySize)
	fallback := bytes.Repeat([]byte{0x32}, KeySize)
	valid, err := EncodeKeySet(active, fallback)
	if err != nil {
		t.Fatalf("EncodeKeySet() error = %v", err)
	}
	defer clear(valid)

	tests := []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "truncated", encoded: append([]byte(nil), valid[:len(valid)-1]...)},
		{name: "unknown magic", encoded: append([]byte{0xff}, valid[1:]...)},
		{name: "unknown version", encoded: mutateCredentialByte(valid, len(credentialMagic), 0xff)},
		{name: "wrong key count", encoded: mutateCredentialByte(valid, len(credentialMagic)+1, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewFromCredential(test.encoded); !errors.Is(err, ErrKeyInvalid) {
				t.Fatalf("NewFromCredential() error = %v, want ErrKeyInvalid", err)
			}
		})
	}
	if _, err := EncodeKeySet(active, active); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("EncodeKeySet(duplicate) error = %v, want ErrKeyInvalid", err)
	}
}

func TestProtectorRejectsUnauthenticatedRecords(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x11}, KeySize)
	protector, err := New(key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = protector.Close() })

	protected, err := protector.Seal(t.Context(), []byte("secret"), []byte("profile-a"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	tampered := append([]byte(nil), protected...)
	tampered[len(tampered)-1] ^= 0x80

	other, err := New(bytes.Repeat([]byte{0x22}, KeySize))
	if err != nil {
		t.Fatalf("New(other) error = %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })

	tests := []struct {
		name           string
		candidate      []byte
		additionalData []byte
		candidateBox   *Protector
	}{
		{name: "tampered ciphertext", candidate: tampered, additionalData: []byte("profile-a"), candidateBox: protector},
		{name: "wrong profile binding", candidate: protected, additionalData: []byte("profile-b"), candidateBox: protector},
		{name: "wrong key", candidate: protected, additionalData: []byte("profile-a"), candidateBox: other},
		{name: "truncated payload", candidate: protected[:12], additionalData: []byte("profile-a"), candidateBox: protector},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := test.candidateBox.Open(
				t.Context(),
				test.candidate,
				test.additionalData,
			); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("Open() error = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestProtectorCloseAndCancellation(t *testing.T) {
	t.Parallel()

	protector := testProtector(t, bytes.NewReader(bytes.Repeat([]byte{0x33}, 32)))
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := protector.Seal(cancelled, []byte("secret"), []byte("binding")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Seal(cancelled) error = %v, want context.Canceled", err)
	}
	if err := protector.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := protector.Seal(t.Context(), []byte("secret"), []byte("binding")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Seal(closed) error = %v, want ErrClosed", err)
	}
	if _, err := protector.Open(t.Context(), make([]byte, 32), []byte("binding")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Open(closed) error = %v, want ErrClosed", err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		prepare   func(*testing.T, string)
		expected  error
		isSuccess bool
	}{
		{
			name: "owner-only key",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, bytes.Repeat([]byte{0x44}, KeySize), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			isSuccess: true,
		},
		{
			name: "owner-only rotating key set",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				encoded, err := EncodeKeySet(
					bytes.Repeat([]byte{0x45}, KeySize),
					bytes.Repeat([]byte{0x46}, KeySize),
				)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(encoded)
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			isSuccess: true,
		},
		{
			name:     "missing key",
			prepare:  func(*testing.T, string) {},
			expected: ErrKeyMissing,
		},
		{
			name: "broad permissions",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				//nolint:gosec // The test intentionally creates an unsafe permission mode.
				if err := os.WriteFile(path, bytes.Repeat([]byte{0x44}, KeySize), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			expected: ErrKeyInvalid,
		},
		{
			name: "wrong size",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, bytes.Repeat([]byte{0x44}, KeySize-1), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expected: ErrKeyInvalid,
		},
		{
			name: "symbolic link",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, bytes.Repeat([]byte{0x44}, KeySize), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
			expected: ErrKeyInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "identity.key")
			test.prepare(t, path)
			protector, err := Load(path)
			if test.isSuccess {
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				t.Cleanup(func() { _ = protector.Close() })

				return
			}
			if !errors.Is(err, test.expected) {
				t.Fatalf("Load() error = %v, want %v", err, test.expected)
			}
		})
	}
}

func TestSystemdCredentialPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		expected bool
	}{
		{path: "/run/credentials/meshd.service/meshd.identity-key", expected: true},
		{path: "/run/credentials/custom.service/meshd.identity-key", expected: true},
		{path: "/run/credentials/meshd.service", expected: false},
		{path: "/run/credentials/meshd.identity-key", expected: false},
		{path: "/run/credentials/../meshd.service/meshd.identity-key", expected: false},
		{path: "/tmp/meshd.service/meshd.identity-key", expected: false},
		{path: "run/credentials/meshd.service/meshd.identity-key", expected: false},
	}
	for _, test := range tests {
		if actual := isSystemdCredentialPath(test.path); actual != test.expected {
			t.Errorf("isSystemdCredentialPath(%q) = %v, want %v", test.path, actual, test.expected)
		}
	}
}

func FuzzProtectorOpen(f *testing.F) {
	protector, err := New(bytes.Repeat([]byte{0x61}, KeySize))
	if err != nil {
		f.Fatalf("New() error = %v", err)
	}
	f.Cleanup(func() { _ = protector.Close() })
	valid, err := protector.Seal(
		context.Background(),
		[]byte("identity material"),
		[]byte("profile binding"),
	)
	if err != nil {
		f.Fatalf("Seal() error = %v", err)
	}
	f.Add(valid, "profile binding")
	f.Add([]byte{}, "profile binding")
	f.Add([]byte("not ciphertext"), "different binding")

	f.Fuzz(func(t *testing.T, protected []byte, additionalData string) {
		if len(protected) > 1<<16 || len(additionalData) > 256 || additionalData == "" {
			t.Skip()
		}
		plaintext, err := protector.Open(t.Context(), protected, []byte(additionalData))
		if err == nil {
			clear(plaintext)
		}
	})
}

func testProtector(t *testing.T, random *bytes.Reader) *Protector {
	t.Helper()

	protector, err := newWithRandom(bytes.Repeat([]byte{0x10}, KeySize), nil, random)
	if err != nil {
		t.Fatalf("newWithRandom() error = %v", err)
	}
	t.Cleanup(func() { _ = protector.Close() })

	return protector
}

func mutateCredentialByte(encoded []byte, index int, value byte) []byte {
	mutated := append([]byte(nil), encoded...)
	mutated[index] = value

	return mutated
}
